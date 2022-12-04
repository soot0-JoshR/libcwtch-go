module git.openprivacy.ca/cwtch.im/libcwtch-go

go 1.17

require (
	cwtch.im/cwtch v0.18.5
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
	golang.org/x/crypto v0.0.0-20220826181053-bd7e27e6170d // indirect
	// go mobile should stay pinned to golang.org/x/mobile v0.0.0-20210220033013-bdb1ca9a1e08
	// until we intentionally upgrade it, requiring upgrading our docker container
	// android_go_mobile as well (matching version there), and possibly after upgrading past go 1.17
	golang.org/x/mobile v0.0.0-20210220033013-bdb1ca9a1e08 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/net v0.0.0-20220826154423-83b083e8dc8b // indirect
	golang.org/x/sys v0.0.0-20220825204002-c680a09ffe64 // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)