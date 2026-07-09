package peer

import (
	"archive/tar"
	"compress/gzip"
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"database/sql"
	"errors"
	"fmt"
	"git.openprivacy.ca/openprivacy/log"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// StorageKeyType is an interface wrapper around storage key types
type StorageKeyType string

const (
	// TypeAttribute for Profile Scoped and Zoned Attributes
	TypeAttribute = StorageKeyType("Attribute")

	// TypePrivateKey for Profile Private Keys
	TypePrivateKey = StorageKeyType("PrivateKey")

	// TypePublicKey for Profile Public Keys
	TypePublicKey = StorageKeyType("PublicKey")
)

// CwtchProfileStorage encapsulates common datastore requests so as to not pollute the main cwtch profile
// struct with database knowledge
type CwtchProfileStorage struct {

	// Note: Statements are thread safe..
	mutex sync.Mutex

	// Profile related statements
	insertProfileKeyValueStmt *sql.Stmt
	selectProfileKeyValueStmt *sql.Stmt
	findProfileKeySQLStmt     *sql.Stmt

	// Conversation related statements
	insertConversationStmt         *sql.Stmt
	fetchAllConversationsStmt      *sql.Stmt
	selectConversationStmt         *sql.Stmt
	selectConversationByHandleStmt *sql.Stmt
	acceptConversationStmt         *sql.Stmt
	deleteConversationStmt         *sql.Stmt
	setConversationAttributesStmt  *sql.Stmt
	setConversationACLStmt         *sql.Stmt

	channelInsertStmts                  map[ChannelID]*sql.Stmt
	channelUpdateMessageStmts           map[ChannelID]*sql.Stmt
	channelGetMessageStmts              map[ChannelID]*sql.Stmt
	channelGetMessageBySignatureStmts   map[ChannelID]*sql.Stmt
	channelGetCountStmts                map[ChannelID]*sql.Stmt
	channelGetMostRecentMessagesStmts   map[ChannelID]*sql.Stmt
	channelGetMessageByContentHashStmts map[ChannelID]*sql.Stmt
	channelRowNumberStmts               map[ChannelID]*sql.Stmt
	ProfileDirectory                    string
	db                                  *sql.DB
	memoryStore                         bool
}

// ChannelID encapsulates the data necessary to reference a channel structure.
type ChannelID struct {
	Conversation int
	Channel      int
}

const insertProfileKeySQLStmt = `insert or replace into profile_kv(KeyType, KeyName, KeyValue) values(?,?,?);`
const selectProfileKeySQLStmt = `select KeyValue from  profile_kv where KeyType=(?) and KeyName=(?);`
const findProfileKeySQLStmt = `select KeyName from  profile_kv where KeyType=(?) and KeyName LIKE (?);`

const insertConversationSQLStmt = `insert into conversations(Handle, Attributes, ACL, Accepted) values(?,?,?,?);`
const fetchAllConversationsSQLStmt = `select ID, Handle, Attributes, ACL, Accepted from conversations;`
const selectConversationSQLStmt = `select ID, Handle, Attributes, ACL, Accepted from  conversations where ID=(?);`
const selectConversationByHandleSQLStmt = `select ID, Handle, Attributes, ACL, Accepted from  conversations where Handle=(?);`
const acceptConversationSQLStmt = `update conversations set Accepted=true where ID=(?);`
const setConversationAttributesSQLStmt = `update conversations set Attributes=(?) where ID=(?) ;`
const setConversationACLSQLStmt = `update conversations set ACL=(?) where ID=(?) ;`
const deleteConversationSQLStmt = `delete from conversations where ID=(?);`

// createTableConversationMessagesSQLStmt is a template for creating conversation based tables...
const createTableConversationMessagesSQLStmt = `create table if not exists channel_%d_0_chat (ID integer unique primary key autoincrement, Body text, Attributes []byte, Expiry datetime, Signature text unique, ContentHash blob text);`

// insertMessageIntoConversationSQLStmt is a template for creating conversation based tables...
const insertMessageIntoConversationSQLStmt = `insert into channel_%d_%d_chat (Body, Attributes, Signature, ContentHash) values(?,?,?,?);`

// updateMessageIntoConversationSQLStmt is a template for updating attributes of a message in a conversation
const updateMessageIntoConversationSQLStmt = `update channel_%d_%d_chat set Attributes=(?) where ID=(?);`

// purgeMessagesFromConversationSQLStmt is a template for updating attributes of a message in a conversation
const purgeMessagesFromConversationSQLStmt = `delete from channel_%d_%d_chat;`

// getMessageFromConversationSQLStmt is a template for fetching a message by ID from a conversation
const getMessageFromConversationSQLStmt = `select Body, Attributes from channel_%d_%d_chat where ID=(?);`

// getMessageBySignatureFromConversationSQLStmt is a template for selecting conversation messages by signature
const getMessageBySignatureFromConversationSQLStmt = `select ID from channel_%d_%d_chat where Signature=(?);`

// getMessageByContentHashFromConversationSQLStmt is a template for selecting conversation messages by content hash
const getMessageByContentHashFromConversationSQLStmt = `select ID from channel_%d_%d_chat where ContentHash=(?) order by ID desc limit 1;`

// getLocalIndexOfMessageIDSQLStmt is a template for fetching the offset of a message from the bottom of the database.
const getLocalIndexOfMessageIDSQLStmt = `select count (*) from channel_%d_%d_chat where ID >= (?) order by ID desc;`

// getMessageCountFromConversationSQLStmt is a template for fetching the count of a messages  in a conversation channel
const getMessageCountFromConversationSQLStmt = `select count(*) from channel_%d_%d_chat;`

// getMostRecentMessagesSQLStmt is a template for fetching the most recent N messages in a conversation channel
const getMostRecentMessagesSQLStmt = `select ID, Body, Attributes, Signature, ContentHash from channel_%d_%d_chat order by ID desc limit (?) offset (?);`

// NewCwtchProfileStorage constructs a new CwtchProfileStorage from a database. It is also responsible for
// Preparing commonly used SQL Statements
func NewCwtchProfileStorage(db *sql.DB, profileDirectory string) (*CwtchProfileStorage, error) {

	if db == nil {
		return nil, errors.New("cannot construct cwtch profile storage with a nil database")
	}

	insertProfileKeyValueStmt, err := db.Prepare(insertProfileKeySQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", insertProfileKeySQLStmt, err)
		return nil, err
	}

	selectProfileKeyStmt, err := db.Prepare(selectProfileKeySQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", selectProfileKeySQLStmt, err)
		return nil, err
	}

	findProfileKeyStmt, err := db.Prepare(findProfileKeySQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", findProfileKeySQLStmt, err)
		return nil, err
	}

	insertConversationStmt, err := db.Prepare(insertConversationSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", insertConversationSQLStmt, err)
		return nil, err
	}

	fetchAllConversationsStmt, err := db.Prepare(fetchAllConversationsSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", fetchAllConversationsSQLStmt, err)
		return nil, err
	}

	selectConversationStmt, err := db.Prepare(selectConversationSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", selectConversationSQLStmt, err)
		return nil, err
	}

	selectConversationByHandleStmt, err := db.Prepare(selectConversationByHandleSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", selectConversationByHandleSQLStmt, err)
		return nil, err
	}

	acceptConversationStmt, err := db.Prepare(acceptConversationSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", acceptConversationSQLStmt, err)
		return nil, err
	}

	deleteConversationStmt, err := db.Prepare(deleteConversationSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", deleteConversationSQLStmt, err)
		return nil, err
	}

	setConversationAttributesStmt, err := db.Prepare(setConversationAttributesSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", setConversationAttributesSQLStmt, err)
		return nil, err
	}

	setConversationACLStmt, err := db.Prepare(setConversationACLSQLStmt)
	if err != nil {
		db.Close()
		log.Errorf("error preparing query: %v %v", setConversationACLSQLStmt, err)
		return nil, err
	}

	return &CwtchProfileStorage{db: db,
			ProfileDirectory:                    profileDirectory,
			insertProfileKeyValueStmt:           insertProfileKeyValueStmt,
			selectProfileKeyValueStmt:           selectProfileKeyStmt,
			findProfileKeySQLStmt:               findProfileKeyStmt,
			fetchAllConversationsStmt:           fetchAllConversationsStmt,
			insertConversationStmt:              insertConversationStmt,
			selectConversationStmt:              selectConversationStmt,
			selectConversationByHandleStmt:      selectConversationByHandleStmt,
			acceptConversationStmt:              acceptConversationStmt,
			deleteConversationStmt:              deleteConversationStmt,
			setConversationAttributesStmt:       setConversationAttributesStmt,
			setConversationACLStmt:              setConversationACLStmt,
			channelInsertStmts:                  map[ChannelID]*sql.Stmt{},
			channelUpdateMessageStmts:           map[ChannelID]*sql.Stmt{},
			channelGetMessageStmts:              map[ChannelID]*sql.Stmt{},
			channelGetMessageBySignatureStmts:   map[ChannelID]*sql.Stmt{},
			channelGetMessageByContentHashStmts: map[ChannelID]*sql.Stmt{},
			channelGetMostRecentMessagesStmts:   map[ChannelID]*sql.Stmt{},
			channelGetCountStmts:                map[ChannelID]*sql.Stmt{},
			channelRowNumberStmts:               map[ChannelID]*sql.Stmt{},
		},
		nil
}

// NewMemoryCwtchProfileStorage constructs a profile storage backed by an in-memory database.
func NewMemoryCwtchProfileStorage(db *sql.DB, profileDirectory string) (*CwtchProfileStorage, error) {
	cps, err := NewCwtchProfileStorage(db, profileDirectory)
	if err != nil {
		return nil, err
	}
	cps.memoryStore = true
	return cps, nil
}

// IsMemoryStore returns true when the storage is backed by an in-memory database.
func (cps *CwtchProfileStorage) IsMemoryStore() bool {
	return cps.memoryStore
}

// StoreProfileKeyValue allows storing of typed Key/Value attribute in the Storage Engine
func (cps *CwtchProfileStorage) StoreProfileKeyValue(keyType StorageKeyType, key string, value []byte) error {
	_, err := cps.insertProfileKeyValueStmt.Exec(keyType, key, value)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return err
	}
	return nil
}

// FindProfileKeysByPrefix allows fetching of typed values via a known Key from the Storage Engine
func (cps *CwtchProfileStorage) FindProfileKeysByPrefix(keyType StorageKeyType, prefix string) ([]string, error) {
	rows, err := cps.findProfileKeySQLStmt.Query(keyType, prefix+"%")
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}

	var keys []string
	defer rows.Close()
	for {
		result := rows.Next()

		if !result {
			return keys, nil
		}

		var key []byte
		err = rows.Scan(&key)
		if err != nil {
			log.Errorf("error fetching rows: %v", err)
			rows.Close()
			return nil, err
		}
		keys = append(keys, string(key))
	}
}

// LoadProfileKeyValue allows fetching of typed values via a known Key from the Storage Engine
func (cps *CwtchProfileStorage) LoadProfileKeyValue(keyType StorageKeyType, key string) ([]byte, error) {
	rows, err := cps.selectProfileKeyValueStmt.Query(keyType, key)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}

	result := rows.Next()

	if !result {
		return nil, errors.New("no result found")
	}

	var keyValue []byte
	err = rows.Scan(&keyValue)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return nil, err
	}
	rows.Close()
	return keyValue, nil
}

// NewConversation stores a new conversation in the data store
func (cps *CwtchProfileStorage) NewConversation(handle string, attributes model.Attributes, acl model.AccessControlList, accepted bool) (int, error) {
	tx, err := cps.db.Begin()

	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, err
	}

	result, err := tx.Stmt(cps.insertConversationStmt).Exec(handle, attributes.Serialize(), acl.Serialize(), accepted)
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, tx.Rollback()
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, tx.Rollback()
	}

	result, err = tx.Exec(fmt.Sprintf(createTableConversationMessagesSQLStmt, id))
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, tx.Rollback()
	}

	conversationID, err := result.LastInsertId()
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, tx.Rollback()
	}

	err = tx.Commit()
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return -1, tx.Rollback()
	}

	return int(conversationID), nil
}

// GetConversationByHandle is a convenience method to fetch an active conversation by a handle
// Usage Notes: This should **only** be used to look up p2p conversations by convention.
// Ideally this function should not exist, and all lookups should happen by ID (this is currently
// unavoidable in some circumstances because the event bus references conversations by handle, not by id)
func (cps *CwtchProfileStorage) GetConversationByHandle(handle string) (*model.Conversation, error) {
	rows, err := cps.selectConversationByHandleStmt.Query(handle)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}

	result := rows.Next()

	if !result {
		return nil, errors.New("no result found")
	}

	var id int
	var acl []byte
	var attributes []byte
	var accepted bool
	err = rows.Scan(&id, &handle, &attributes, &acl, &accepted)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return nil, err
	}
	rows.Close()

	return &model.Conversation{ID: id, Handle: handle, ACL: model.DeserializeAccessControlList(acl), Attributes: model.DeserializeAttributes(attributes), Accepted: accepted}, nil
}

// FetchConversations returns *all* active conversations. This method should only be called
// on app start up to build a summary of conversations for the UI. Any further updates should be integrated
// through the event bus.
func (cps *CwtchProfileStorage) FetchConversations() ([]*model.Conversation, error) {
	rows, err := cps.fetchAllConversationsStmt.Query()
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}

	var conversations []*model.Conversation

	defer rows.Close()
	for {
		result := rows.Next()

		if !result {
			return conversations, nil
		}

		var id int
		var handle string
		var acl []byte
		var attributes []byte
		var accepted bool
		err = rows.Scan(&id, &handle, &attributes, &acl, &accepted)
		if err != nil {
			log.Errorf("error fetching rows: %v", err)
			rows.Close()
			return nil, err
		}
		conversations = append(conversations, &model.Conversation{ID: id, Handle: handle, ACL: model.DeserializeAccessControlList(acl), Attributes: model.DeserializeAttributes(attributes), Accepted: accepted})

	}
}

// GetConversation looks up a particular conversation by id
func (cps *CwtchProfileStorage) GetConversation(id int) (*model.Conversation, error) {
	rows, err := cps.selectConversationStmt.Query(id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}

	result := rows.Next()

	if !result {
		return nil, errors.New("no result found")
	}

	var handle string
	var acl []byte
	var attributes []byte
	var accepted bool
	err = rows.Scan(&id, &handle, &attributes, &acl, &accepted)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return nil, err
	}
	rows.Close()

	return &model.Conversation{ID: id, Handle: handle, ACL: model.DeserializeAccessControlList(acl), Attributes: model.DeserializeAttributes(attributes), Accepted: accepted}, nil
}

// AcceptConversation sets the accepted status of a conversation to true in the backing datastore
func (cps *CwtchProfileStorage) AcceptConversation(id int) error {
	_, err := cps.acceptConversationStmt.Exec(id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return err
	}
	return nil
}

// DeleteConversation purges the conversation and any associated message history from the conversation store.
func (cps *CwtchProfileStorage) DeleteConversation(id int) error {
	_, err := cps.deleteConversationStmt.Exec(id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return err
	}
	return nil
}

// SetConversationACL sets a new ACL on a given conversation.
func (cps *CwtchProfileStorage) SetConversationACL(id int, acl model.AccessControlList) error {
	_, err := cps.setConversationACLStmt.Exec(acl.Serialize(), id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return err
	}
	return nil
}

// SetConversationAttribute sets a new attribute on a given conversation.
func (cps *CwtchProfileStorage) SetConversationAttribute(id int, path attr.ScopedZonedPath, value string) error {
	ci, err := cps.GetConversation(id)
	if err != nil {
		return err
	}
	ci.Attributes[path.ToString()] = value
	_, err = cps.setConversationAttributesStmt.Exec(ci.Attributes.Serialize(), id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return err
	}
	return nil
}

// InsertMessage appends a message to a conversation channel, with a given set of attributes
func (cps *CwtchProfileStorage) InsertMessage(conversation int, channel int, body string, attributes model.Attributes, signature string, contentHash string) (int, error) {

	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelInsertStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(insertMessageIntoConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return -1, err
		}
		cps.channelInsertStmts[channelID] = conversationStmt
	}

	result, err := cps.channelInsertStmts[channelID].Exec(body, attributes.Serialize(), signature, contentHash)
	if err != nil {
		log.Errorf("error inserting message: %v %v", signature, err)
		return -1, err
	}

	id, err := result.LastInsertId()
	return int(id), err
}

// UpdateMessageAttributes updates the attributes associated with a message of a given conversation
func (cps *CwtchProfileStorage) UpdateMessageAttributes(conversation int, channel int, messageID int, attributes model.Attributes) error {

	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelUpdateMessageStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(updateMessageIntoConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return err
		}
		cps.channelUpdateMessageStmts[channelID] = conversationStmt
	}

	_, err := cps.channelUpdateMessageStmts[channelID].Exec(attributes.Serialize(), messageID)
	if err != nil {
		log.Errorf("error updating message: %v", err)
		return err
	}

	return nil
}

// GetChannelMessageBySignature looks up a conversation message by signature instead of identifier. Both are unique but
// signatures are common between conversation participants (in groups) and so are a more useful message to index.
func (cps *CwtchProfileStorage) GetChannelMessageBySignature(conversation int, channel int, signature string) (int, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelGetMessageBySignatureStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getMessageBySignatureFromConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return -1, err
		}
		cps.channelGetMessageBySignatureStmts[channelID] = conversationStmt
	}

	rows, err := cps.channelGetMessageBySignatureStmts[channelID].Query(signature)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return -1, err
	}

	result := rows.Next()

	if !result {
		return -1, errors.New("no result found")
	}

	var id int
	err = rows.Scan(&id)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return -1, err
	}
	rows.Close()
	return id, nil
}

// GetChannelMessageByContentHash looks up a conversation message by hash instead of identifier.
func (cps *CwtchProfileStorage) GetChannelMessageByContentHash(conversation int, channel int, hash string) (int, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelGetMessageByContentHashStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getMessageByContentHashFromConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return -1, err
		}
		cps.channelGetMessageByContentHashStmts[channelID] = conversationStmt
	}

	rows, err := cps.channelGetMessageByContentHashStmts[channelID].Query(hash)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return -1, err
	}

	result := rows.Next()

	if !result {
		return -1, errors.New("no result found")
	}

	var id int
	err = rows.Scan(&id)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return -1, err
	}
	rows.Close()

	return id, nil
}

// GetRowNumberByMessageID looks up the row number of a message by the message ID
func (cps *CwtchProfileStorage) GetRowNumberByMessageID(conversation int, channel int, id int) (int, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelRowNumberStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getLocalIndexOfMessageIDSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return -1, err
		}
		cps.channelRowNumberStmts[channelID] = conversationStmt
	}

	rows, err := cps.channelRowNumberStmts[channelID].Query(id)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return -1, err
	}

	result := rows.Next()

	if !result {
		return -1, errors.New("no result found")
	}

	var rownum int
	err = rows.Scan(&rownum)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return -1, err
	}
	rows.Close()
	// Return the offset **not** the count
	return rownum - 1, nil
}

// GetChannelMessage looks up a channel message by conversation, channel and message id. On success it
// returns the message body and the attributes associated with the message. Otherwise an error is returned.
func (cps *CwtchProfileStorage) GetChannelMessage(conversation int, channel int, messageID int) (string, model.Attributes, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelGetMessageStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getMessageFromConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return "", nil, err
		}
		cps.channelGetMessageStmts[channelID] = conversationStmt
	}

	rows, err := cps.channelGetMessageStmts[channelID].Query(messageID)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return "", nil, err
	}

	result := rows.Next()

	if !result {
		return "", nil, errors.New("no result found")
	}

	// Deserialize the Row
	var body string
	var attributes []byte
	err = rows.Scan(&body, &attributes)
	if err != nil {
		log.Errorf("error fetching rows: %v", err)
		rows.Close()
		return "", nil, err
	}
	rows.Close()

	return body, model.DeserializeAttributes(attributes), nil
}

// GetChannelMessageCount returns the number of messages in a channel
func (cps *CwtchProfileStorage) GetChannelMessageCount(conversation int, channel int) (int, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelGetCountStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getMessageCountFromConversationSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return -1, err
		}
		cps.channelGetCountStmts[channelID] = conversationStmt
	}

	var count int
	err := cps.channelGetCountStmts[channelID].QueryRow().Scan(&count)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return -1, err
	}
	return count, nil
}

// GetMostRecentMessages returns the most recent messages in a channel up to a given limit at a given offset
func (cps *CwtchProfileStorage) GetMostRecentMessages(conversation int, channel int, offset int, limit int) ([]model.ConversationMessage, error) {
	channelID := ChannelID{Conversation: conversation, Channel: channel}

	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	_, exists := cps.channelGetMostRecentMessagesStmts[channelID]
	if !exists {
		conversationStmt, err := cps.db.Prepare(fmt.Sprintf(getMostRecentMessagesSQLStmt, conversation, channel))
		if err != nil {
			log.Errorf("error executing transaction: %v", err)
			return nil, err
		}
		cps.channelGetMostRecentMessagesStmts[channelID] = conversationStmt
	}

	rows, err := cps.channelGetMostRecentMessagesStmts[channelID].Query(limit, offset)
	if err != nil {
		log.Errorf("error executing query: %v", err)
		return nil, err
	}
	var conversationMessages []model.ConversationMessage
	defer rows.Close()
	for {
		result := rows.Next()
		if !result {
			return conversationMessages, nil
		}
		var id int
		var body string
		var attributes []byte
		var sig string
		var contenthash string
		err = rows.Scan(&id, &body, &attributes, &sig, &contenthash)
		if err != nil {
			return conversationMessages, err
		}
		conversationMessages = append(conversationMessages, model.ConversationMessage{ID: id, Body: body, Attr: model.DeserializeAttributes(attributes), Signature: sig, ContentHash: contenthash})
	}
}

// PurgeConversationChannel deletes all message for a conversation channel.
func (cps *CwtchProfileStorage) PurgeConversationChannel(conversation int, channel int) error {
	conversationStmt, err := cps.db.Prepare(fmt.Sprintf(purgeMessagesFromConversationSQLStmt, conversation, channel))
	if err != nil {
		log.Errorf("error executing transaction: %v", err)
		return err
	}
	conversationStmt.Exec()
	return conversationStmt.Close()
}

// PurgeNonSavedMessages deletes all message conversations that are not explicitly set to saved.
func (cps *CwtchProfileStorage) PurgeNonSavedMessages() {
	// Purge Messages that are not stored...
	ci, err := cps.FetchConversations()
	if err == nil {
		for _, conversation := range ci {
			if !conversation.IsGroup() && !conversation.IsServer() {
				if conversation.Attributes[attr.LocalScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey)).ToString()] != event.SaveHistoryConfirmed {
					log.Infof("purging conversation...")
					// TODO: At some point in the future this needs to iterate over channels and make a decision for each on..
					cps.PurgeConversationChannel(conversation.ID, 0)
				}
			}
		}
	}
}

// Close closes the underlying database and prepared statements
func (cps *CwtchProfileStorage) Close(purgeAllNonSavedMessages bool) {
	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	if cps.db != nil {
		if purgeAllNonSavedMessages {
			cps.PurgeNonSavedMessages()
		}

		cps.insertProfileKeyValueStmt.Close()
		cps.selectProfileKeyValueStmt.Close()

		cps.insertConversationStmt.Close()
		cps.fetchAllConversationsStmt.Close()
		cps.selectConversationStmt.Close()
		cps.selectConversationByHandleStmt.Close()
		cps.acceptConversationStmt.Close()
		cps.deleteConversationStmt.Close()
		cps.setConversationAttributesStmt.Close()
		cps.setConversationACLStmt.Close()

		for _, v := range cps.channelInsertStmts {
			v.Close()
		}
		for _, v := range cps.channelUpdateMessageStmts {
			v.Close()
		}
		for _, v := range cps.channelGetMessageStmts {
			v.Close()
		}
		for _, v := range cps.channelGetMessageBySignatureStmts {
			v.Close()
		}
		for _, v := range cps.channelGetCountStmts {
			v.Close()
		}
		for _, v := range cps.channelGetMostRecentMessagesStmts {
			v.Close()
		}
		for _, v := range cps.channelGetMessageByContentHashStmts {
			v.Close()
		}

		cps.db.Close()
	}
}

// Delete unconditionally destroys the profile directory associated with the store.
// This is unrecoverable.
func (cps *CwtchProfileStorage) Delete() {
	if cps.memoryStore || strings.HasPrefix(cps.ProfileDirectory, "memory://") {
		return
	}
	err := os.RemoveAll(cps.ProfileDirectory)
	if err != nil {
		log.Errorf("error deleting profile directory", err)
	}
}

// Rekey re-encrypts the datastore with the new key.
// **note* this is technically a very dangerous API and should only be called after
// checks on the current password and the derived new password.
func (cps *CwtchProfileStorage) Rekey(newkey [32]byte) error {
	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	// PRAGMA queries don't allow subs...
	_, err := cps.db.Exec(fmt.Sprintf(`PRAGMA rekey="x'%x'";`, newkey))
	return err
}

// PromoteToEncryptedStore exports an in-memory database to an encrypted on-disk profile.
func (cps *CwtchProfileStorage) PromoteToEncryptedStore(profileDirectory string, password string) error {
	// 1. Initialize V2 directory (creates SALT and VERSION)
	key, _, err := initV2Directory(profileDirectory, password)
	if err != nil {
		return err
	}
	
	// 2. Attach new DB and export
	cps.mutex.Lock()
	defer cps.mutex.Unlock()
	
	dbPath := filepath.Join(profileDirectory, "db")
	attachStmt := fmt.Sprintf(`ATTACH DATABASE '%s' AS encrypted KEY "x'%x'";`, dbPath, key)
	_, err = cps.db.Exec(attachStmt)
	if err != nil {
		return fmt.Errorf("failed to attach encrypted db: %v", err)
	}
	
	_, err = cps.db.Exec(`SELECT sqlcipher_export('encrypted');`)
	if err != nil {
		// Clean up the attach if export failed
		cps.db.Exec(`DETACH DATABASE encrypted;`)
		return fmt.Errorf("failed to export to encrypted db: %v", err)
	}
	
	_, err = cps.db.Exec(`DETACH DATABASE encrypted;`)
	if err != nil {
		return fmt.Errorf("failed to detach encrypted db: %v", err)
	}
	
	return nil
}

// Export takes in a file name and creates an exported cwtch profile file (which in reality is a compressed tarball).
func (cps *CwtchProfileStorage) Export(filename string) error {
	profileDB := filepath.Join(cps.ProfileDirectory, dbFile)
	profileSalt := filepath.Join(cps.ProfileDirectory, saltFile)
	profileVersion := filepath.Join(cps.ProfileDirectory, versionFile)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create tarball file '%s', got error '%s'", filename, err.Error())
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// We need to know the base directory so we can import it later (and prevent duplicates)...
	profilePath := filepath.Base(cps.ProfileDirectory)

	err = addFileToTarWriter(profilePath, profileDB, tarWriter)
	if err != nil {
		return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileDB, err.Error())
	}

	err = addFileToTarWriter(profilePath, profileSalt, tarWriter)
	if err != nil {
		return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileDB, err.Error())
	}

	err = addFileToTarWriter(profilePath, profileVersion, tarWriter)
	if err != nil {
		return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileDB, err.Error())
	}
	return nil
}

func addFileToTarWriter(profilePath string, filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open file '%s', got error '%s'", filePath, err.Error())
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not get stat for file '%s', got error '%s'", filePath, err.Error())
	}

	header := &tar.Header{
		// Note: we are using strings.Join here deliberately so that we can import the profile
		// in a cross platform way (e.g. using filepath here would result in different names on Windows v.s Linux)
		Name:    strings.Join([]string{profilePath, stat.Name()}, "/"),
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("could not write header for file '%s', got error '%s'", filePath, err.Error())
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return fmt.Errorf("could not copy the file '%s' data to the tarball, got error '%s'", filePath, err.Error())
	}

	return nil
}
