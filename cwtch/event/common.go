package event

import "time"

var CwtchEpoch = time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)

// Type captures the definition of many common Cwtch application events
type Type string

// Defining Common Event Types
const (
	StatusRequest        = Type("StatusRequest")
	ProtocolEngineStatus = Type("ProtocolEngineStatus")

	// Attempt to outbound peer with a given remote peer
	// attributes:
	// RemotePeer: [eg "chpr7qm6op5vfcg2pi4vllco3h6aa7exexc4rqwnlupqhoogx2zgd6qd"
	PeerRequest = Type("PeerRequest")

	// QueuePeerRequest
	// When peer has too many peers to try and wants to ease off Tor throttling, use this to notify ContactRetry plugin to schedule a peer for later try
	// LastSeen: last seen time of the contact
	// And one of
	//		RemotePeer
	//		GroupServer
	QueuePeerRequest = Type("QueuePeerRequest")

	// RetryPeerRequest
	// Identical to PeerRequest, but allows Engine to make decisions regarding blocked peers
	// attributes:
	// RemotePeer: [eg "chpr7qm6op5vfcg2pi4vllco3h6aa7exexc4rqwnlupqhoogx2zgd6qd"
	RetryPeerRequest = Type("RetryPeerRequest")

	// RetryServerRequest
	// Asks CwtchPeer to retry a server connection...
	// GroupServer: [eg "chpr7qm6op5vfcg2pi4vllco3h6aa7exexc4rqwnlupqhoogx2zgd6qd"
	RetryServerRequest = Type("RetryServerRequest")

	// RemotePeer
	// ConversationID
	// Accepted
	// Blocked
	UpdateConversationAuthorization = Type("UpdateConversationAuthorization")

	// Turn on/off blocking of unknown peers (if peers aren't in the contact list then they will be autoblocked
	BlockUnknownPeers = Type("BlockUnknownPeers")
	AllowUnknownPeers = Type("AllowUnknownPeers")

	// GroupServer
	QueueJoinServer = Type("QueueJoinServer")
	JoinServer      = Type("JoinServer")

	// attributes GroupServer - the onion of the server to leave
	LeaveServer = Type("LeaveServer")

	ProtocolEngineCreated     = Type("ProtocolEngineCreated")
	ProtocolEngineShutdown    = Type("ProtocolEngineShutdown")
	ProtocolEngineStartListen = Type("ProtocolEngineStartListen")
	ProtocolEngineStopped     = Type("ProtocolEngineStopped")

	InvitePeerToGroup = Type("InvitePeerToGroup")

	// a group invite has been received from a remote peer
	// attributes:
	// TimestampReceived [eg time.Now().Format(time.RFC3339Nano)]
	// RemotePeer: [eg "chpr7qm6op5vfcg2pi4vllco3h6aa7exexc4rqwnlupqhoogx2zgd6qd"]
	// GroupInvite: [eg "torv3....."]
	// Imported
	NewGroupInvite = Type("NewGroupInvite")

	// Inform the UI about a new group
	// GroupID: groupID (allows them to fetch from the peer)
	NewGroup = Type("NewGroup")

	SendMessageToGroup = Type("SendMessagetoGroup")

	//Ciphertext, Signature:
	EncryptedGroupMessage = Type("EncryptedGroupMessage")
	//TimestampReceived, TimestampSent, Data(Message), GroupID, Signature, PreviousSignature, RemotePeer
	NewMessageFromGroup = Type("NewMessageFromGroup")

	// Sent if a Group Key is detected as being used outside of expected parameters (e.g. with tampered signatures)
	// GroupID: The ID of the Group that is presumed compromised
	GroupCompromised = Type("GroupCompromised")

	// an error was encountered trying to send a particular Message to a group
	// attributes:
	// GroupServer: The server the Message was sent to
	// Signature: The signature of the Message that failed to send
	// Error: string describing the error
	SendMessageToGroupError = Type("SendMessageToGroupError")

	SendMessageToPeer        = Type("SendMessageToPeer")
	NewMessageFromPeer       = Type("NewMessageFromPeer")
	NewMessageFromPeerEngine = Type("NewMessageFromPeerEngine")

	// RemotePeer, scope, path
	NewGetValMessageFromPeer = Type("NewGetValMessageFromPeer")

	// RemotePeer, val, exists
	SendRetValMessageToPeer = Type("SendRetValMessageToPeer")

	// RemotePeer, scope, val
	SendGetValMessageToPeer = Type("SendGetValMessageToPeer")

	// RemotePeer, scope, path, data, exists
	NewRetValMessageFromPeer = Type("NewRetValMessageFromPeer")

	// Peer acknowledges a previously sent message
	// attributes
	// EventID: The original event id that the peer is responding too.
	// RemotePeer: The peer associated with the acknowledgement
	PeerAcknowledgement = Type("PeerAcknowledgement")

	// Like PeerAcknowledgement but with message index instead of event ID
	// attributes
	// Index: The original index of the message that the peer is responding too.
	// RemotePeer: The peer associated with the acknowledgement
	IndexedAcknowledgement = Type("IndexedAcknowledgement")

	// Like PeerAcknowledgement but with message index instead of event ID
	// attributes
	// Index: The original index of the message that the peer is responding too.
	// RemotePeer: The peer associated with the acknowledgement
	IndexedFailure = Type("IndexedFailure")

	// attributes:
	// RemotePeer: [eg "chpr7qm6op5vfcg2pi4vllco3h6aa7exexc4rqwnlupqhoogx2zgd6qd"]
	// Error: string describing the error
	SendMessageToPeerError = Type("SendMessageToPeerError")

	// REQUESTS TO STORAGE ENGINE

	// a peer contact has been added
	// attributes:
	// RemotePeer [eg ""]
	ContactCreated = Type("ContactCreated")

	// Password, NewPassword
	ChangePassword = Type("ChangePassword")

	// a group has been successfully added or newly created
	// attributes:
	// Data [serialized *model.Group]
	GroupCreated = Type("GroupCreated")

	// RemotePeer
	DeleteContact = Type("DeleteContact")

	// PeerStateChange servers as a new incoming connection message as well, and can/is consumed by frontends to alert of new p2p connections
	// RemotePeer
	// ConnectionState
	PeerStateChange = Type("PeerStateChange")

	// GroupServer
	// ConnectionState
	ServerStateChange = Type("ServerStateChange")

	/***** Application client / service messages *****/

	// app: Identity(onion), Created(bool)
	// service -> client: Identity(localId), Password, [Status(new/default=blank || from reload='running')], Created(bool)
	NewPeer = Type("NewPeer")

	// Identity(onion)
	DeletePeer = Type("DeletePeer")
	// Identity(onion)
	PeerDeleted = Type("PeerDeleted")

	// Identity(onion)
	ShutdownPeer = Type("ShutdownPeer")

	Shutdown = Type("Shutdown")

	// Error(err)
	// Error creating peer
	PeerError = Type("PeerError")

	// Error(err)
	AppError = Type("AppError")

	// Progress, Status
	ACNStatus = Type("ACNStatus")

	// ID, Key, Data
	ACNInfo = Type("ACNInfo")

	// Data
	ACNVersion = Type("ACNVersion")

	// Network Status
	// Status: Success || Error
	// Error: Description of the Error
	// Onion: the local onion we attempt to check
	NetworkStatus = Type("NetworkError")

	// For debugging. Allows test to emit a Syn and get a response Ack(eventID) when the subsystem is done processing a queue
	Syn = Type("Syn")
	Ack = Type("Ack")

	// File Handling Events
	StopFileShare              = Type("StopFileShare")
	StopAllFileShares          = Type("StopAllFileShares")
	ShareManifest              = Type("ShareManifest")
	ManifestSizeReceived       = Type("ManifestSizeReceived")
	ManifestError              = Type("ManifestError")
	ManifestReceived           = Type("ManifestReceived")
	ManifestSaved              = Type("ManifestSaved")
	FileDownloadProgressUpdate = Type("FileDownloadProgressUpdate")
	FileDownloaded             = Type("FileDownloaded")
	FileVerificationFailed     = Type("FileVerificationFailed")

	// Profile Attribute Event
	UpdatedProfileAttribute = Type("UpdatedProfileAttribute")

	StartingStorageMiragtion = Type("StartingStorageMigration")
	DoneStorageMigration     = Type("DoneStorageMigration")

	TokenManagerInfo     = Type("TokenManagerInfo")
	TriggerAntispamCheck = Type("TriggerAntispamCheck")
	MakeAntispamPayment  = Type("MakeAntispamPayment")
)

// Field defines common event attributes
type Field string

// Defining Common Field Types
const (

	// A peers local onion address
	Onion = Field("Onion")

	RemotePeer        = Field("RemotePeer")
	LastSeen          = Field("LastSeen")
	Ciphertext        = Field("Ciphertext")
	Signature         = Field("Signature")
	CachedTokens      = Field("CachedTokens")
	PreviousSignature = Field("PreviousSignature")
	TimestampSent     = Field("TimestampSent")
	TimestampReceived = Field("TimestampReceived")

	Identity = Field("Identity")

	ConversationID   = Field("ConversationID")
	GroupID          = Field("GroupID")
	GroupServer      = Field("GroupServer")
	GroupName        = Field("GroupName")
	ServerTokenY     = Field("ServerTokenY")
	ServerTokenOnion = Field("ServerTokenOnion")
	GroupInvite      = Field("GroupInvite")
	ServerTokenCount = Field("ServerTokenCount")

	ProfileName = Field("ProfileName")
	Password    = Field("Password")
	NewPassword = Field("NewPassword")

	Created = Field("Created")

	ConnectionState = Field("ConnectionState")

	Key    = Field("Key")
	Data   = Field("Data")
	Scope  = Field("Scope")
	Path   = Field("Path")
	Exists = Field("Exists")

	Salt = Field("Salt")

	Error = Field("Error")

	Progress     = Field("Progress")
	Status       = Field("Status")
	EventID      = Field("EventID")
	EventContext = Field("EventContext")
	Index        = Field("Index")
	ContentHash  = Field("ContentHash")

	// Handle denotes a contact handle of any type.
	Handle = Field("Handle")

	// Flags denotes a set of message flags
	Flags = Field("Flags")

	Accepted = Field("Accepted")
	Blocked  = Field("Blocked")

	KeyBundle = Field("KeyBundle")

	// Indicate whether an event was triggered by a user import
	Imported = Field("Imported")

	Source = Field("Source")

	FileKey              = Field("FileKey")
	FileSizeInChunks     = Field("FileSizeInChunks")
	ManifestSize         = Field("ManifestSize")
	SerializedManifest   = Field("SerializedManifest")
	TempFile             = Field("TempFile")
	FilePath             = Field("FilePath")
	FileDownloadFinished = Field("FileDownloadFinished")
	NameSuggestion       = Field("NameSuggestion")
)

// Defining Common errors
const (
	AppErrLoaded0      = "Loaded 0 profiles"
	PasswordMatchError = "Password did not match"
)

// Defining Protocol Contexts
const (
	ContextAck             = "im.cwtch.acknowledgement"
	ContextInvite          = "im.cwtch.invite"
	ContextRaw             = "im.cwtch.raw"
	ContextGetVal          = "im.cwtch.getVal"
	ContextVersion         = "im.cwtch.version"
	ContextRetVal          = "im.cwtch.retVal"
	ContextRequestManifest = "im.cwtch.file.request.manifest"
	ContextSendManifest    = "im.cwtch.file.send.manifest"
	ContextRequestFile     = "im.cwtch.file.request.chunk"
	ContextSendFile        = "im.cwtch.file.send.chunk"
)

// Define Default Attribute Keys
const (
	SaveHistoryKey = "SavePeerHistory"
)

// Define Default Attribute Values
const (
	// Save History has 3 distinct states. By default we don't save history (DefaultDeleteHistory), if the peer confirms this
	// we change to DeleteHistoryConfirmed, if they confirm they want to save then this becomes SaveHistoryConfirmed
	// We use this distinction between default and confirmed to drive UI
	DeleteHistoryDefault   = "DefaultDeleteHistory"
	SaveHistoryConfirmed   = "SaveHistory"
	DeleteHistoryConfirmed = "DeleteHistoryConfirmed"
)

// Bool strings
const (
	True  = "true"
	False = "false"
)
