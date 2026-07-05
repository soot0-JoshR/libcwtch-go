package app

import (
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"cwtch.im/cwtch/peer"
	"time"
)

// WaitGetPeer is a helper function for utility apps not written using the event bus
// Proper use of an App is to call CreatePeer and then process the NewPeer event
// however for small utility use, this function which polls the app until the peer is created
// may fill that usecase better
func WaitGetPeer(app Application, name string) peer.CwtchPeer {
	for {
		for _, handle := range app.ListProfiles() {
			peer := app.GetPeer(handle)
			localName, _ := peer.GetScopedZonedAttribute(attr.PublicScope, attr.ProfileZone, constants.Name)
			if localName == name {
				return peer
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}
