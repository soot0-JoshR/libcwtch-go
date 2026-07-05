package filesharing

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	path "path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/protocol/files"
	"git.openprivacy.ca/openprivacy/log"
)

// Functionality groups some common UI triggered functions for contacts...
type Functionality struct {
}

// FunctionalityGate returns filesharing if enabled in the given experiment map
// Note: Experiment maps are currently in libcwtch-go
func FunctionalityGate(experimentMap map[string]bool) (*Functionality, error) {
	if experimentMap[constants.FileSharingExperiment] {
		return new(Functionality), nil
	}
	return nil, errors.New("filesharing is not enabled")
}

// PreviewFunctionalityGate returns filesharing if image previews are enabled
func PreviewFunctionalityGate(experimentMap map[string]bool) (*Functionality, error) {
	if experimentMap[constants.FileSharingExperiment] && experimentMap[constants.ImagePreviewsExperiment] {
		return new(Functionality), nil
	}
	return nil, errors.New("image previews are not enabled")
}

// OverlayMessage presents the canonical format of the File Sharing functionality Overlay Message
// This is the format that the UI will parse to display the message
type OverlayMessage struct {
	Name  string `json:"f"`
	Hash  string `json:"h"`
	Nonce string `json:"n"`
	Size  uint64 `json:"s"`
}

// FileKey is the unique reference to a file offer
func (om *OverlayMessage) FileKey() string {
	return fmt.Sprintf("%s.%s", om.Hash, om.Nonce)
}

// ShouldAutoDL checks file size and file name. *DOES NOT* check user settings or contact state
func (om *OverlayMessage) ShouldAutoDL() bool {
	if om.Size > constants.ImagePreviewMaxSizeInBytes {
		return false
	}
	lname := strings.ToLower(om.Name)
	for _, s := range constants.AutoDLFileExts {
		if strings.HasSuffix(lname, s) {
			return true
		}
	}
	return false
}

// DownloadFile given a profile, a conversation handle and a file sharing key, start off a download process
// to downloadFilePath
func (f *Functionality) DownloadFile(profile peer.CwtchPeer, conversationID int, downloadFilePath string, manifestFilePath string, key string, limit uint64) error {

	// Don't download files if the download or manifest path is not set
	if downloadFilePath == "" || manifestFilePath == "" {
		return errors.New("download path or manifest path is empty")
	}

	// We write to a temp file for Android...
	if runtime.GOOS != "android" {
		// Don't download files if the download file directory does not exist
		if _, err := os.Stat(path.Dir(downloadFilePath)); os.IsNotExist(err) {
			return errors.New("download directory does not exist")
		}

		// Don't download files if the manifest file directory does not exist
		if _, err := os.Stat(path.Dir(manifestFilePath)); os.IsNotExist(err) {
			return errors.New("manifest directory does not exist")
		}
	}
	// Store local.filesharing.filekey.manifest as the location of the manifest
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", key), manifestFilePath)

	// Store local.filesharing.filekey.path as the location of the download
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", key), downloadFilePath)

	// Store local.filesharing.filekey.limit as the max file size of the download
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.limit", key), strconv.FormatUint(limit, 10))

	// Get the value of conversation.filesharing.filekey.manifest.size from `handle`
	profile.SendScopedZonedGetValToContact(conversationID, attr.ConversationScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest.size", key))

	return nil
}

// RestartFileShare takes in an existing filekey and, assuming the manifest exists, restarts sharing of the manifest
func (f *Functionality) RestartFileShare(profile peer.CwtchPeer, filekey string) error {
	// check that a manifest exists
	manifest, manifestExists := profile.GetScopedZonedAttribute(attr.ConversationScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", filekey))
	if manifestExists {
		// everything is in order, so reshare this file with the engine
		profile.ShareFile(filekey, manifest)
		return nil
	}
	return fmt.Errorf("manifest does not exist for filekey: %v", filekey)
}

// ReShareFiles given a profile we iterate through all existing fileshares and re-share them
// if the time limit has not expired
func (f *Functionality) ReShareFiles(profile peer.CwtchPeer) error {
	keys, err := profile.GetScopedZonedAttributeKeys(attr.LocalScope, attr.FilesharingZone)
	if err != nil {
		return err
	}

	for _, key := range keys {
		// only look at timestamp keys
		// this is an arbitrary choice
		if strings.HasSuffix(key, ".ts") {
			_, zonedpath := attr.ParseScope(key)
			_, keypath := attr.ParseZone(zonedpath)
			keyparts := strings.Split(keypath, ".")

			// assert that the key is well-formed
			if len(keyparts) == 3 && keyparts[2] == "ts" {
				// fetch the timestamp key
				filekey := strings.Join(keyparts[:2], ".")
				sharedFile, err := f.GetFileShareInfo(profile, filekey)

				// If we haven't explicitly stopped sharing the file AND
				// If fewer than 30 days have passed since we originally shared this file,
				// Then attempt to share this file again...
				// TODO: In the future this would be the point to change the timestamp and reshare the file...
				if err == nil && sharedFile.Active {
					f.RestartFileShare(profile, filekey)
				}
			}
		}
	}
	return nil
}

// GetFileShareInfo returns information related to a known fileshare.
// An error is returned if the data is incomplete
func (f *Functionality) GetFileShareInfo(profile peer.CwtchPeer, filekey string) (*SharedFile, error) {
	timestampString, tsExists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.ts", filekey))
	pathString, pathExists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", filekey))
	activeString, activeExists := profile.GetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.active", filekey))
	if tsExists && pathExists && activeExists {
		timestamp, err := strconv.Atoi(timestampString)
		if err == nil {

			dateShared := time.Unix(int64(timestamp), 0)
			expired := time.Since(dateShared) >= time.Hour*24*30

			return &SharedFile{
				FileKey:    filekey,
				Path:       pathString,
				DateShared: dateShared,
				Active:     !expired && activeString == constants.True,
				Expired:    expired,
			}, nil
		}
	}
	return nil, fmt.Errorf("nonexistant or malformed fileshare %v", filekey)
}

// ShareFile given a profile and a conversation handle, sets up a file sharing process to share the file
// at filepath
func (f *Functionality) ShareFile(filepath string, profile peer.CwtchPeer) (string, string, error) {
	manifest, err := files.CreateManifest(filepath)
	if err != nil {
		return "", "", err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Errorf("Cannot read from random: %v\n", err)
		return "", "", err
	}

	message := OverlayMessage{
		Name:  path.Base(manifest.FileName),
		Hash:  hex.EncodeToString(manifest.RootHash),
		Nonce: hex.EncodeToString(nonce[:]),
		Size:  manifest.FileSizeInBytes,
	}

	data, _ := json.Marshal(message)

	wrapper := model.MessageWrapper{
		Overlay: model.OverlayFileSharing,
		Data:    string(data),
	}

	wrapperJSON, _ := json.Marshal(wrapper)
	key := fmt.Sprintf("%x.%x", manifest.RootHash, nonce)
	serializedManifest, _ := json.Marshal(manifest)

	// Store the size of the manifest (in chunks) as part of the public scope so contacts who we share the file with
	// can fetch the manifest as if it were a file.
	// manifest.FileName gets redacted in filesharing_subsystem (to remove the system-specific file hierarchy),
	// but we need to *store* the full path because the sender also uses it to locate the file
	lenDiff := len(filepath) - len(path.Base(filepath))

	// the sender needs to know the location of the file so they can display it in a preview...
	// This eventually becomes a message attribute, but we don't have access to the message identifier until
	// the message gets sent.
	// In the worst case, this can be obtained using CheckDownloadStatus (though in practice this lookup will be
	// rare because the UI will almost always initiate the construction of a preview a file directly after sending it).
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.path", key), filepath)

	// Store the timestamp, manifest and manifest size for later.
	profile.SetScopedZonedAttribute(attr.LocalScope, attr.FilesharingZone, fmt.Sprintf("%s.ts", key), strconv.FormatInt(time.Now().Unix(), 10))
	profile.SetScopedZonedAttribute(attr.ConversationScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest", key), string(serializedManifest))
	profile.SetScopedZonedAttribute(attr.ConversationScope, attr.FilesharingZone, fmt.Sprintf("%s.manifest.size", key), strconv.Itoa(int(math.Ceil(float64(len(serializedManifest)-lenDiff)/float64(files.DefaultChunkSize)))))

	profile.ShareFile(key, string(serializedManifest))

	return key, string(wrapperJSON), err
}

// SharedFile encapsulates information about a shared file
// including the file key, file path, the original share date and the
// current sharing status
type SharedFile struct {

	// The roothash.nonce identifier derived for this file share
	FileKey string

	// Path is the OS specific location of the file
	Path string

	// DateShared is the original datetime the file was shared
	DateShared time.Time

	// Active is true if the file is currently being shared, false otherwise
	Active bool

	// Expired is true if the file is not eligible to be shared (because e.g. it has been too long since the file was originally shared,
	// or the file no longer exists).
	Expired bool
}

// GetSharedFiles returns all file shares associated with a given conversation
func (f *Functionality) GetSharedFiles(profile peer.CwtchPeer, conversationID int) []SharedFile {
	sharedFiles := []SharedFile{}
	ci, err := profile.GetConversationInfo(conversationID)
	if err == nil {
		for k := range ci.Attributes {
			// when we share a file with a conversation we set a single attribute conversation.filesharing.<filekey>
			if strings.HasPrefix(k, "conversation.filesharing") {
				parts := strings.SplitN(k, ".", 3)
				if len(parts) == 3 {
					key := parts[2]
					sharedFile, err := f.GetFileShareInfo(profile, key)
					if err == nil {
						sharedFiles = append(sharedFiles, *sharedFile)
					}
				}
			}
		}
	}
	return sharedFiles
}

// GenerateDownloadPath creates a file path that doesn't currently exist on the filesystem
func GenerateDownloadPath(basePath, fileName string, overwrite bool) (filePath, manifestPath string) {
	// avoid all kina funky shit
	re := regexp.MustCompile(`[^A-Za-z0-9._-]`)
	filePath = re.ReplaceAllString(filePath, "")
	// avoid hidden files on linux
	for strings.HasPrefix(filePath, ".") {
		filePath = strings.TrimPrefix(filePath, ".")
	}
	// avoid empties
	if strings.TrimSpace(filePath) == "" {
		filePath = "untitled"
	}
	// if you like it, put a / on it
	if !strings.HasSuffix(basePath, string(os.PathSeparator)) {
		basePath = fmt.Sprintf("%s%s", basePath, string(os.PathSeparator))
	}
	filePath = fmt.Sprintf("%s%s", basePath, fileName)
	manifestPath = fmt.Sprintf("%s.manifest", filePath)

	// if file is named "file", iterate "file", "file (2)", "file (3)", ... until DNE
	// if file is named "file.ext", iterate "file.ext", "file (2).ext", "file (3).ext", ... until DNE
	parts := strings.Split(fileName, ".")
	fileNameBase := parts[0]
	fileNameExt := ""
	if len(parts) > 1 {
		fileNameBase = strings.Join(parts[0:len(parts)-1], ".")
		fileNameExt = fmt.Sprintf(".%s", parts[len(parts)-1])
	}

	if !overwrite {
		for i := 2; ; i++ {
			if _, err := os.Open(filePath); os.IsNotExist(err) {
				if _, err := os.Open(manifestPath); os.IsNotExist(err) {
					return
				}
			}
			filePath = fmt.Sprintf("%s%s (%d)%s", basePath, fileNameBase, i, fileNameExt)
			manifestPath = fmt.Sprintf("%s.manifest", filePath)
		}
	}
	return
}
