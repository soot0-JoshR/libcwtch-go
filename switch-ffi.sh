#!/bin/sh
# using '-i.bak' and 'rm .bak' for gnu sed (linux) and bsd sed (macosx) compat
sed -i.bak "s/^package cwtch/\/\/package cwtch/" lib.go
sed -i.bak "s/^\/\/package main/package main/" lib.go
sed -i.bak "s/^\/\/func main()/func main()/" lib.go
rm lib.go.bak
