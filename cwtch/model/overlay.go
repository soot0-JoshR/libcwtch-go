package model

// MessageWrapper is the canonical Cwtch overlay wrapper
type MessageWrapper struct {
	Overlay int    `json:"o"`
	Data    string `json:"d"`
}

// OverlayChat is the canonical identifier for chat overlays
const OverlayChat = 1

// OverlayInviteContact is the canonical identifier for the contact invite overlay
const OverlayInviteContact = 100

// OverlayInviteGroup is the canonical identifier for the group invite overlay
const OverlayInviteGroup = 101

// OverlayFileSharing is the canonical identifier for the file sharing overlay
const OverlayFileSharing = 200
