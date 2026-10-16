package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
)

// ProfileMergeSummary describes durable data added from a duplicate store.
type ProfileMergeSummary struct {
	ConversationsAdded int `json:"conversationsAdded"`
	MessagesAdded      int `json:"messagesAdded"`
}

// MergeEncryptedProfileDirectories merges secondary into a validated clone of
// primary, then atomically installs that clone at primaryDirectory. Both input
// stores must be offline. The originals are not removed until the clone has
// reopened with the expected identity.
func MergeEncryptedProfileDirectories(primaryDirectory, primaryPassword, secondaryDirectory, secondaryPassword string) (CwtchPeer, *ProfileMergeSummary, error) {
	if primaryDirectory == secondaryDirectory {
		return nil, nil, errors.New("cannot merge a profile store with itself")
	}
	primary, err := FromEncryptedDatabase(primaryDirectory, primaryPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unlock current profile copy: %w", err)
	}
	secondary, err := FromEncryptedDatabase(secondaryDirectory, secondaryPassword)
	if err != nil {
		primary.ShutdownWithoutPurgingMessages()
		return nil, nil, fmt.Errorf("could not unlock duplicate profile copy: %w", err)
	}
	primaryPeer, primaryOK := primary.(*cwtchPeer)
	secondaryPeer, secondaryOK := secondary.(*cwtchPeer)
	if !primaryOK || !secondaryOK || primary.GetOnion() != secondary.GetOnion() {
		primary.ShutdownWithoutPurgingMessages()
		secondary.ShutdownWithoutPurgingMessages()
		return nil, nil, errors.New("profile copies do not contain the same identity")
	}
	expectedOnion := primary.GetOnion()
	primaryPrivate, primaryKeyErr := primaryPeer.storage.LoadProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey")
	secondaryPrivate, secondaryKeyErr := secondaryPeer.storage.LoadProfileKeyValue(TypePrivateKey, "Ed25519PrivateKey")
	if primaryKeyErr != nil || secondaryKeyErr != nil || !bytes.Equal(primaryPrivate, secondaryPrivate) {
		primary.ShutdownWithoutPurgingMessages()
		secondary.ShutdownWithoutPurgingMessages()
		return nil, nil, errors.New("profile copies do not contain the same private identity key")
	}

	parent := filepath.Dir(primaryDirectory)
	tempRoot, err := os.MkdirTemp(parent, ".cwtch-merge-")
	if err != nil {
		primary.ShutdownWithoutPurgingMessages()
		secondary.ShutdownWithoutPurgingMessages()
		return nil, nil, err
	}
	defer os.RemoveAll(tempRoot)
	mergedDirectory := filepath.Join(tempRoot, filepath.Base(primaryDirectory))
	key, _, err := initV2Directory(mergedDirectory, primaryPassword)
	if err == nil {
		err = primaryPeer.storage.cloneEncryptedDatabase(filepath.Join(mergedDirectory, dbFile), key)
	}
	if err != nil {
		primary.ShutdownWithoutPurgingMessages()
		secondary.ShutdownWithoutPurgingMessages()
		return nil, nil, fmt.Errorf("could not create merge workspace: %w", err)
	}
	merged, err := FromEncryptedDatabase(mergedDirectory, primaryPassword)
	if err != nil {
		primary.ShutdownWithoutPurgingMessages()
		secondary.ShutdownWithoutPurgingMessages()
		return nil, nil, fmt.Errorf("could not open merge workspace: %w", err)
	}
	mergedPeer := merged.(*cwtchPeer)
	summary, err := mergeProfileData(mergedPeer.storage, secondaryPeer.storage)
	if err == nil && merged.GetOnion() != expectedOnion {
		err = errors.New("merged profile identity changed")
	}
	merged.ShutdownWithoutPurgingMessages()
	primary.ShutdownWithoutPurgingMessages()
	secondary.ShutdownWithoutPurgingMessages()
	if err != nil {
		return nil, nil, err
	}

	// The .bak suffix also makes an interruption-safe recovery copy invisible
	// to application profile discovery until this operation finishes.
	recoveryDirectory := primaryDirectory + ".merge-original-" + model.GenerateRandomID() + ".bak"
	if err := os.Rename(primaryDirectory, recoveryDirectory); err != nil {
		return nil, nil, fmt.Errorf("could not stage current profile for replacement: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = os.RemoveAll(primaryDirectory)
			_ = os.Rename(recoveryDirectory, primaryDirectory)
		}
	}()
	if err := os.Rename(mergedDirectory, primaryDirectory); err != nil {
		return nil, nil, fmt.Errorf("could not install merged profile: %w", err)
	}
	installed, err := FromEncryptedDatabase(primaryDirectory, primaryPassword)
	if err != nil || installed.GetOnion() != expectedOnion {
		if installed != nil {
			installed.ShutdownWithoutPurgingMessages()
		}
		return nil, nil, errors.New("merged profile failed final identity validation")
	}
	rollback = false
	if err := os.RemoveAll(recoveryDirectory); err != nil {
		installed.ShutdownWithoutPurgingMessages()
		return nil, nil, fmt.Errorf("merged profile installed but old current copy could not be removed: %w", err)
	}
	if err := os.RemoveAll(secondaryDirectory); err != nil {
		installed.ShutdownWithoutPurgingMessages()
		return nil, nil, fmt.Errorf("merged profile installed but duplicate copy could not be removed: %w", err)
	}
	return installed, summary, nil
}

func (cps *CwtchProfileStorage) cloneEncryptedDatabase(destination string, key [32]byte) error {
	if strings.ContainsAny(destination, "'\x00") {
		return errors.New("unsupported merge path")
	}
	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	ctx := context.Background()
	conn, err := cps.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`ATTACH DATABASE '%s' AS merged KEY "x'%x'";`, destination, key)); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, `DETACH DATABASE merged;`)
	if _, err := conn.ExecContext(ctx, `PRAGMA merged.cipher_page_size = 8192;`); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `SELECT sqlcipher_export('merged');`)
	return err
}

func mergeProfileData(destination, source *CwtchProfileStorage) (*ProfileMergeSummary, error) {
	if err := mergeProfileAttributes(destination, source); err != nil {
		return nil, err
	}
	summary := &ProfileMergeSummary{}
	destinationConversations, err := destination.FetchConversations()
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]*model.Conversation)
	for _, conversation := range destinationConversations {
		byKey[conversationMergeKey(conversation)] = conversation
	}
	sourceConversations, err := source.FetchConversations()
	if err != nil {
		return nil, err
	}
	for _, sourceConversation := range sourceConversations {
		key := conversationMergeKey(sourceConversation)
		destinationConversation := byKey[key]
		if destinationConversation == nil {
			attributes := filteredMergeAttributes(sourceConversation.Attributes)
			id, err := destination.NewConversation(sourceConversation.Handle, attributes, sourceConversation.ACL, sourceConversation.Accepted)
			if err != nil {
				return nil, err
			}
			destinationConversation, err = destination.GetConversation(id)
			if err != nil {
				return nil, err
			}
			byKey[key] = destinationConversation
			summary.ConversationsAdded++
		} else if err := mergeConversationMetadata(destination, destinationConversation, sourceConversation); err != nil {
			return nil, err
		}
		added, err := mergeConversationMessages(destination, destinationConversation.ID, source, sourceConversation.ID)
		if err != nil {
			return nil, err
		}
		summary.MessagesAdded += added
	}
	return summary, nil
}

func conversationMergeKey(conversation *model.Conversation) string {
	if groupID, ok := conversation.GetAttribute(attr.LocalScope, attr.LegacyGroupZone, constants.GroupID); ok && groupID != "" {
		return "group:" + groupID
	}
	if conversation.IsServer() {
		return "server:" + strings.ToLower(conversation.Handle)
	}
	return "peer:" + strings.ToLower(conversation.Handle)
}

func filteredMergeAttributes(attributes model.Attributes) model.Attributes {
	merged := make(model.Attributes)
	filesharingPrefix := attr.LocalScope.ConstructScopedZonedPath(attr.FilesharingZone.ConstructZonedPath("")).ToString()
	for key, value := range attributes {
		if strings.HasPrefix(key, filesharingPrefix) || strings.Contains(strings.ToLower(key), "lastconnection") || strings.Contains(strings.ToLower(key), "syncmostrecent") || strings.Contains(strings.ToLower(key), "syncprelast") {
			continue
		}
		merged[key] = value
	}
	return merged
}

func mergeConversationMetadata(destination *CwtchProfileStorage, current, other *model.Conversation) error {
	changed := false
	for key, value := range filteredMergeAttributes(other.Attributes) {
		if _, exists := current.Attributes[key]; !exists {
			current.Attributes[key] = value
			changed = true
		}
	}
	if changed {
		if _, err := destination.setConversationAttributesStmt.Exec(current.Attributes.Serialize(), current.ID); err != nil {
			return err
		}
	}
	acl := current.ACL
	if acl == nil {
		acl = make(model.AccessControlList)
	}
	aclChanged := false
	for handle, access := range other.ACL {
		if existing, ok := acl[handle]; !ok {
			acl[handle] = access
			aclChanged = true
		} else if access.Blocked && !existing.Blocked {
			existing.Blocked, existing.Read, existing.Append = true, false, false
			acl[handle] = existing
			aclChanged = true
		}
	}
	if aclChanged {
		if err := destination.SetConversationACL(current.ID, acl); err != nil {
			return err
		}
	}
	if other.Accepted && !current.Accepted {
		return destination.AcceptConversation(current.ID)
	}
	return nil
}

func mergeConversationMessages(destination *CwtchProfileStorage, destinationID int, source *CwtchProfileStorage, sourceID int) (int, error) {
	count, err := source.GetChannelMessageCount(sourceID, 0)
	if err != nil {
		return 0, err
	}
	added := 0
	for remaining := count; remaining > 0; {
		batchSize := 500
		if remaining < batchSize {
			batchSize = remaining
		}
		offset := remaining - batchSize
		messages, err := source.GetMostRecentMessages(sourceID, 0, offset, batchSize)
		if err != nil {
			return added, err
		}
		for index := len(messages) - 1; index >= 0; index-- {
			message := messages[index]
			if message.Signature != "" {
				if _, err := destination.GetChannelMessageBySignature(destinationID, 0, message.Signature); err == nil {
					continue
				}
			} else if message.ContentHash != "" {
				if _, err := destination.GetChannelMessageByContentHash(destinationID, 0, message.ContentHash); err == nil {
					continue
				}
			}
			if _, err := destination.InsertMessage(destinationID, 0, message.Body, message.Attr, message.Signature, message.ContentHash); err != nil {
				return added, err
			}
			added++
		}
		remaining = offset
	}
	return added, nil
}

func mergeProfileAttributes(destination, source *CwtchProfileStorage) error {
	rows, err := source.db.Query(`select KeyName, KeyValue from profile_kv where KeyType=(?)`, string(TypeAttribute))
	if err != nil {
		return err
	}
	defer rows.Close()
	filesharingPrefix := attr.LocalScope.ConstructScopedZonedPath(attr.FilesharingZone.ConstructZonedPath("")).ToString()
	backupPasswordMarker := attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(BackupPasswordAttribute)).ToString()
	// The current store can itself be a restored backup after restart. Remove
	// backup-only metadata from the cloned destination as well as skipping it
	// when copying attributes from the other store.
	if _, err := destination.db.Exec(`delete from profile_kv where KeyType=(?) and KeyName=(?)`, string(TypeAttribute), backupPasswordMarker); err != nil {
		return err
	}
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		if strings.HasPrefix(key, filesharingPrefix) || key == backupPasswordMarker {
			continue
		}
		if _, err := destination.LoadProfileKeyValue(TypeAttribute, key); err == nil {
			continue
		}
		if err := destination.StoreProfileKeyValue(TypeAttribute, key, value); err != nil {
			return err
		}
	}
	return rows.Err()
}
