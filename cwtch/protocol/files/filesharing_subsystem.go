package files

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	path "path/filepath"
	"strconv"
	"strings"
	"sync"

	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/protocol/model"
	"git.openprivacy.ca/openprivacy/log"
)

// FileSharingSubSystem encapsulates the functionality necessary to share and download files via Cwtch
type FileSharingSubSystem struct {

	// for sharing files
	activeShares sync.Map // file key to manifest

	// for downloading files
	prospectiveManifests sync.Map // file key to serialized manifests
	activeDownloads      sync.Map // file key to manifests
}

// ShareFile given a file key and a serialized manifest, allow the serialized manifest to be downloaded
// by Cwtch profiles in possession of the fileKey
func (fsss *FileSharingSubSystem) ShareFile(fileKey string, serializedManifest string) {
	var manifest Manifest
	err := json.Unmarshal([]byte(serializedManifest), &manifest)
	if err != nil {
		log.Errorf("could not share file %v", err)
		return
	}
	fsss.activeShares.Store(fileKey, &manifest)
}

// StopFileShare given a file key removes the serialized manifest from consideration by the file sharing
// subsystem. Future requests on this manifest will fail, as will any in-progress chunk requests.
func (fsss *FileSharingSubSystem) StopFileShare(fileKey string) {
	fsss.activeShares.Delete(fileKey)
}

// StopAllFileShares removes all active file shares from consideration
func (fsss *FileSharingSubSystem) StopAllFileShares() {
	fsss.activeShares.Range(func(key, value interface{}) bool {
		fsss.activeShares.Delete(key)
		return true
	})
}

// FetchManifest given a file key and knowledge of the manifest size in chunks (obtained via an attribute lookup)
// construct a request to download the manifest.
func (fsss *FileSharingSubSystem) FetchManifest(fileKey string, manifestSize uint64) model.PeerMessage {
	fsss.prospectiveManifests.Store(fileKey, strings.Repeat("\"", int(manifestSize*DefaultChunkSize)))
	return model.PeerMessage{
		Context: event.ContextRequestManifest,
		ID:      fileKey,
		Data:    []byte{},
	}
}

// CompileChunkRequests takes in a complete serializedManifest and returns a set of chunk request messages
// TODO in the future we will want this to return the handles of contacts to request chunks from
func (fsss *FileSharingSubSystem) CompileChunkRequests(fileKey, serializedManifest, tempFile, title string) []model.PeerMessage {
	var manifest Manifest
	err := json.Unmarshal([]byte(serializedManifest), &manifest)
	var messages []model.PeerMessage
	if err == nil {
		manifest.TempFileName = tempFile
		manifest.Title = title
		err := manifest.PrepareDownload()
		if err == nil {
			fsss.activeDownloads.Store(fileKey, &manifest)
			log.Debugf("downloading file chunks: %v", manifest.GetChunkRequest().Serialize())
			messages = append(messages, model.PeerMessage{
				ID:      fileKey,
				Context: event.ContextRequestFile,
				Data:    []byte(manifest.GetChunkRequest().Serialize()),
			})
		} else {
			log.Errorf("couldn't prepare download: %v", err)
		}
	}
	return messages
}

// RequestManifestParts given a fileKey construct a set of messages representing requests to download various
// parts of the Manifest
func (fsss *FileSharingSubSystem) RequestManifestParts(fileKey string) []model.PeerMessage {
	manifestI, exists := fsss.activeShares.Load(fileKey)
	var messages []model.PeerMessage
	if exists {
		oldManifest := manifestI.(*Manifest)
		serializedOldManifest := oldManifest.Serialize()
		log.Debugf("found serialized manifest")

		// copy so we dont get threading issues by modifying the original
		// and then redact the file path before sending
		// nb: manifest.size has already been corrected elsewhere
		var manifest Manifest
		json.Unmarshal([]byte(serializedOldManifest), &manifest)
		manifest.FileName = path.Base(manifest.FileName)
		serializedManifest := manifest.Serialize()

		chunkID := 0
		for i := 0; i < len(serializedManifest); i += DefaultChunkSize {
			offset := i
			end := i + DefaultChunkSize
			// truncate end
			if end > len(serializedManifest) {
				end = len(serializedManifest)
			}
			chunk := serializedManifest[offset:end]
			// request this manifest part
			messages = append(messages, model.PeerMessage{
				Context: event.ContextSendManifest,
				ID:      fmt.Sprintf("%s.%d", fileKey, chunkID),
				Data:    chunk,
			})
			chunkID++
		}
	}
	return messages
}

// ReceiveManifestPart given a manifestKey reconstruct part the manifest from the provided part
func (fsss *FileSharingSubSystem) ReceiveManifestPart(manifestKey string, part []byte) (fileKey string, serializedManifest string) {
	fileKeyParts := strings.Split(manifestKey, ".")
	if len(fileKeyParts) == 3 { // rootHash.nonce.manifestPart
		fileKey = fmt.Sprintf("%s.%s", fileKeyParts[0], fileKeyParts[1])
		log.Debugf("manifest filekey: %s", fileKey)
		manifestPart, err := strconv.Atoi(fileKeyParts[2])
		if err == nil {
			serializedManifest, exists := fsss.prospectiveManifests.Load(fileKey)
			if exists {
				serializedManifest := serializedManifest.(string)
				log.Debugf("loaded manifest")
				offset := manifestPart * DefaultChunkSize
				end := (manifestPart + 1) * DefaultChunkSize

				log.Debugf("storing manifest part %v %v", offset, end)
				serializedManifestBytes := []byte(serializedManifest)
				if len(serializedManifestBytes) > offset && len(serializedManifestBytes) >= end {
					copy(serializedManifestBytes[offset:end], part[:])

					if len(part) < DefaultChunkSize {
						serializedManifestBytes = serializedManifestBytes[0 : len(serializedManifestBytes)-(DefaultChunkSize-len(part))]
					}

					serializedManifest = string(serializedManifestBytes)
					fsss.prospectiveManifests.Store(fileKey, serializedManifest)
					log.Debugf("current manifest: [%s]", serializedManifest)
					var manifest Manifest
					err := json.Unmarshal([]byte(serializedManifest), &manifest)
					if err == nil && hex.EncodeToString(manifest.RootHash) == fileKeyParts[0] {
						log.Debugf("valid manifest received! %x", manifest.RootHash)
						return fileKey, serializedManifest
					}
				}
			}
		}
	}
	return "", ""
}

// ProcessChunkRequest given a fileKey, and a chunk request, compile a set of responses for each requested Chunk
func (fsss *FileSharingSubSystem) ProcessChunkRequest(fileKey string, serializedChunkRequest []byte) []model.PeerMessage {
	log.Debugf("chunk request: %v", fileKey)
	// fileKey is rootHash.nonce
	manifestI, exists := fsss.activeShares.Load(fileKey)
	var messages []model.PeerMessage
	if exists {
		manifest := manifestI.(*Manifest)
		log.Debugf("manifest found: %x", manifest.RootHash)
		chunkSpec, err := Deserialize(string(serializedChunkRequest))
		log.Debugf("deserialized chunk spec found: %v [%s]", chunkSpec, serializedChunkRequest)
		if err == nil {
			for _, chunk := range *chunkSpec {
				contents, err := manifest.GetChunkBytes(chunk)
				if err == nil {
					log.Debugf("sending chunk: %v %x", chunk, contents)
					messages = append(messages, model.PeerMessage{
						ID:      fmt.Sprintf("%v.%d", fileKey, chunk),
						Context: event.ContextSendFile,
						Data:    contents,
					})
				}
			}
		}
	}
	return messages
}

// ProcessChunk given a chunk key and a chunk attempt to store and verify the chunk  as part of an active download
// If this results in the file download being completed return downloaded = true
// Always return the progress of a matched download if it exists along with the total number of chunks and the
// given chunk ID
// If not such active download exists then return an empty file key and ignore all further processing.
func (fsss *FileSharingSubSystem) ProcessChunk(chunkKey string, chunk []byte) (fileKey string, progress uint64, totalChunks uint64, chunkID uint64, title string) {
	fileKeyParts := strings.Split(chunkKey, ".")
	log.Debugf("got chunk for %s", fileKeyParts)
	if len(fileKeyParts) == 3 { // fileKey is rootHash.nonce.chunk
		// recalculate file key
		fileKey = fmt.Sprintf("%s.%s", fileKeyParts[0], fileKeyParts[1])
		derivedChunkID, err := strconv.Atoi(fileKeyParts[2])
		if err == nil {
			chunkID = uint64(derivedChunkID)
			log.Debugf("got chunk id %d", chunkID)
			manifestI, exists := fsss.activeDownloads.Load(fileKey)
			if exists {
				manifest := manifestI.(*Manifest)
				totalChunks = uint64(len(manifest.Chunks))
				title = manifest.Title
				log.Debugf("found active manifest %v", manifest)
				progress, err = manifest.StoreChunk(chunkID, chunk)
				log.Debugf("attempts to store chunk %v %v", progress, err)
				if err != nil {
					log.Debugf("error storing chunk: %v", err)
					// malicious contacts who share conversations can share random chunks
					// these will not match the chunk hash and as such will fail.
					// at this point we can't differentiate between a malicious chunk and failure to store a
					// legitimate chunk, so if there is an error we silently drop it and expect the higher level callers (e.g. the ui)
					//to detect and respond to missing chunks if it detects them..
				}
			}
		}
	}
	return
}

// VerifyFile returns true if the file has been downloaded, false otherwise
// as well as the temporary filename, if one was used
func (fsss *FileSharingSubSystem) VerifyFile(fileKey string) (tempFile string, filePath string, downloaded bool) {
	manifestI, exists := fsss.activeDownloads.Load(fileKey)
	if exists {
		manifest := manifestI.(*Manifest)
		if manifest.VerifyFile() == nil {
			manifest.Close()
			fsss.activeDownloads.Delete(fileKey)
			log.Debugf("file verified and downloaded!")
			return manifest.TempFileName, manifest.FileName, true
		}
	}
	return "", "", false
}
