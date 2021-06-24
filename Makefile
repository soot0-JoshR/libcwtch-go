.PHONY: all clean linux android

DEFAULT_GOAL: linux

all: linux android

linux: libCwtch.so

android: cwtch.aar

windows: libCwtch.dll

libCwtch.so: lib.go 
	./switch-ffi.sh
	go build -buildmode c-shared -o libCwtch.so

cwtch.aar: lib.go
	./switch-gomobile.sh
	gomobile bind -target android

libCwtch.dll: lib.go
	./switch-ffi.sh
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc-win32 go build -buildmode c-shared -o libCwtch.dll

clean: 
	rm -f cwtch.aar cwtch_go.apk libCwtch.h libCwtch.so cwtch-sources.jar libCwtch.dll
