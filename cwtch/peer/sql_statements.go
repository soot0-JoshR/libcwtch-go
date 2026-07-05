package peer

import (
	"database/sql"
	"fmt"
)

// SQLCreateTableProfileKeyValue creates the Profile Key Value Table
const SQLCreateTableProfileKeyValue = `create table if not exists profile_kv (KeyType text, KeyName text, KeyValue blob, UNIQUE  (KeyType,KeyName));`

// SQLCreateTableConversations creates the Profile Key Value Table
const SQLCreateTableConversations = `create table if not exists conversations (ID integer unique primary key autoincrement, Handle text, Attributes blob, ACL blob, Accepted bool);`

// initializeDatabase executes all the sql statements necessary to construct the base of the database.
// db must be open
func initializeDatabase(db *sql.DB) error {

	_, err := db.Exec(SQLCreateTableProfileKeyValue)
	if err != nil {
		return fmt.Errorf("error On Executing Query: %v %v", SQLCreateTableProfileKeyValue, err)
	}

	_, err = db.Exec(SQLCreateTableConversations)
	if err != nil {
		return fmt.Errorf("error On Executing Query: %v %v", SQLCreateTableConversations, err)
	}

	return nil
}
