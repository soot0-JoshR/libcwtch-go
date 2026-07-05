#!/bin/bash

set -e
pwd
GORACE="haltonerror=1"
go test -race ${1} -coverprofile=plugins.cover.out -v ./app/plugins
go test -race ${1} -coverprofile=model.cover.out -v ./model
go test -race ${1} -coverprofile=event.cover.out -v ./event
go test -race ${1} -coverprofile=storage.v1.cover.out -v ./storage/v1
go test -race ${1} -coverprofile=storage.cover.out -v ./storage
go test -race ${1} -coverprofile=peer.connections.cover.out -v ./protocol/connections
go test -race ${1} -coverprofile=peer.filesharing.cover.out -v ./protocol/files
echo "mode: set" > coverage.out && cat *.cover.out | grep -v mode: | sort -r | \
awk '{if($1 != last) {print $0;last=$1}}' >> coverage.out
rm -rf *.cover.out
