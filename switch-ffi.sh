#!/bin/sh

sed -i "s/^package cwtch/\/\/package cwtch/" lib.go
sed -i "s/^\/\/package main/package main/" lib.go
sed -i "s/^\/\/func main()/func main()/" lib.go