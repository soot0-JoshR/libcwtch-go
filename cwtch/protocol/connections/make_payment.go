package connections

import (
	"cwtch.im/cwtch/utils"
	"git.openprivacy.ca/cwtch.im/tapir/applications"
	"git.openprivacy.ca/cwtch.im/tapir/networks/tor"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	"git.openprivacy.ca/cwtch.im/tapir/primitives/privacypass"
	"git.openprivacy.ca/openprivacy/connectivity"
	"git.openprivacy.ca/openprivacy/log"
	"reflect"
	"time"
)

// MakePayment uses the PoW based token protocol to obtain more tokens
func MakePayment(tokenServiceOnion string, tokenService *privacypass.TokenServer, acn connectivity.ACN, handler TokenBoardHandler) error {
	log.Debugf("making a payment")
	id, sk := primitives.InitializeEphemeralIdentity()
	client := new(tor.BaseOnionService)
	client.Init(acn, sk, &id)
	defer client.Shutdown()

	tokenApplication := new(applications.TokenApplication)
	tokenApplication.TokenService = tokenService
	powTokenApp := new(applications.ApplicationChain).
		ChainApplication(new(applications.ProofOfWorkApplication), applications.SuccessfulProofOfWorkCapability).
		ChainApplication(tokenApplication, applications.HasTokensCapability)

	log.Debugf("waiting for successful PoW auth...")
	tp := utils.TimeoutPolicy(time.Second * 30)
	err := tp.ExecuteAction(func() error {
		connected, err := client.Connect(tokenServiceOnion, powTokenApp)
		if connected && err == nil {
			log.Debugf("waiting for successful token acquisition...")
			conn, err := client.WaitForCapabilityOrClose(tokenServiceOnion, applications.HasTokensCapability)
			if err == nil {
				powtapp, ok := conn.App().(*applications.TokenApplication)
				if ok {
					log.Debugf("updating tokens")
					handler.NewTokenHandler(tokenServiceOnion, powtapp.Tokens)
					log.Debugf("transcript: %v", powtapp.Transcript().OutputTranscriptToAudit())
					conn.Close()
					return nil
				}
				log.Errorf("invalid cast of powapp. this should never happen %v %v", powtapp, reflect.TypeOf(conn.App()))
				return nil
			}
			return nil
		}
		return err
	})

	// we timed out
	if err != nil {
		log.Debugf("make payment timeout...")
		return err
	}
	return err
}
