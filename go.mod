module git.openprivacy.ca/cwtch.im/libcwtch-go

go 1.25.0

require (
	cwtch.im/cwtch v0.18.10
	git.openprivacy.ca/cwtch.im/server v1.4.5
	git.openprivacy.ca/openprivacy/connectivity v1.8.6
	git.openprivacy.ca/openprivacy/log v1.0.3
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	git.openprivacy.ca/cwtch.im/tapir v0.6.0 // indirect
	git.openprivacy.ca/openprivacy/bine v0.0.4 // indirect
	github.com/gtank/merlin v0.1.1 // indirect
	github.com/gtank/ristretto255 v0.1.3-0.20210930101514-6bb39798585c // indirect
	github.com/mimoo/StrobeGo v0.0.0-20220103164710-9a04d6ca976b // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/mobile v0.0.0-20260611195102-4dd8f1dbf5d2 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/tools v0.46.0 // indirect
)

replace cwtch.im/cwtch => ./cwtch

tool golang.org/x/mobile/cmd/gobind
