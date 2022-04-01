package constants

// We offer "un-passworded" profiles but our storage encrypts everything with a password. We need an agreed upon
// password to use in that case, that the app case use behind the scenes to password and unlock with
// https://docs.openprivacy.ca/cwtch-security-handbook/profile_encryption_and_storage.html
const DefactoPasswordForUnencryptedProfiles = "be gay do crime"

const (
	// StatusSuccess is an event response for event.Status signifying a call succeeded
	StatusSuccess = "success"
	// StatusError is an event response for event.Status signifying a call failed in error, ideally accompanied by a event.Error
	StatusError = "error"
)

type NotificationType string

const (
	// NotificationNone enum for message["notification"] that means no notification
	NotificationNone = NotificationType("None")
	// NotificationEvent enum for message["notification"] that means emit a notification that a message event happened only
	NotificationEvent = NotificationType("SimpleEvent")
	// NotificationConversation enum for message["notification"] that means emit a notification event with Conversation handle included
	NotificationConversation = NotificationType("ContactInfo")
)

const (
	// ConversationNotificationPolicyDefault enum for conversations indicating to use global notification policy
	ConversationNotificationPolicyDefault = "ConversationNotificationPolicy.Default"
	// ConversationNotificationPolicyOptIn enum for conversation indicating to opt in to nofitications when allowed
	ConversationNotificationPolicyOptIn = "ConversationNotificationPolicy.OptIn"
	// ConversationNotificationPolicyNever enum for conversation indicating to opt in to never do notifications
	ConversationNotificationPolicyNever = "ConversationNotificationPolicy.Never"
)

const DartIso8601 = "2006-01-02T15:04:05.999Z"
