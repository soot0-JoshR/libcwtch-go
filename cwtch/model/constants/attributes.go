package constants

// Name refers to a Profile Name
const Name = "name"

// Onion refers the Onion address of the profile
const Onion = "onion"

// Tag describes the type of a profile e.g. default password / encrypted etc.
const Tag = "tag"

// ProfileTypeV1DefaultPassword is a tag describing a profile protected with the default password.
const ProfileTypeV1DefaultPassword = "v1-defaultPassword"

// ProfileTypeV1Password is a tag describing a profile encrypted derived from a user-provided password.
const ProfileTypeV1Password = "v1-userPassword"

// GroupID is the ID of a group
const GroupID = "groupid"

// GroupServer identifies the Server the legacy group is hosted on
const GroupServer = "groupserver"

// GroupKey is the name of the group key attribute...
const GroupKey = "groupkey"

// True - true
const True = "true"

// False - false
const False = "false"

// AttrAuthor - conversation attribute for author of the message - referenced by pub key rather than conversation id because of groups.
const AttrAuthor = "author"

// AttrAck - conversation attribute for acknowledgement status
const AttrAck = "ack"

// AttrErr - conversation attribute for errored status
const AttrErr = "error"

// AttrSentTimestamp - conversation attribute for the time the message was (nominally) sent
const AttrSentTimestamp = "sent"

// Legacy MessageFlags

// AttrRejected - conversation attribute for storing rejected prompts (for invites)
const AttrRejected = "rejected-invite"

// AttrDownloaded - conversation attribute for storing downloaded prompts (for file downloads)
const AttrDownloaded = "file-downloaded"

const CustomProfileImageKey = "custom-profile-image"

const SyncPreLastMessageTime = "SyncPreLastMessageTime"
const SyncMostRecentMessageTime = "SyncMostRecentMessageTime"

const AttrLastConnectionTime = "last-connection-time"
