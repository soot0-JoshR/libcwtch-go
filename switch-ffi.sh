#!/bin/sh

perl -pi -e "s/^package cwtch/\/\/package cwtch/" lib.go
perl -pi -e "s/^\/\/package main/package main/" lib.go
perl -pi -e "s/^\/\/func main\(\)/func main\(\)/" lib.go
