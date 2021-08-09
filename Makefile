IOS_OUT := ./ios

.PHONY: all linux android windows macos clean ios

DEFAULT_GOAL: linux

all: linux android windows

linux: libCwtch.so

macos: libCwtch.so

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

# iOS - for testing purposes only for now, not officially supported

ios-arm64:
	CGO_ENABLED=1 \
	GOOS=darwin \
	GOARCH=arm64 \
	SDK=iphoneos \
	CGO_CFLAGS="-fembed-bitcode" \
	CC=$(PWD)/clangwrap.sh \
	go build -buildmode=c-archive -tags ios -o $(IOS_OUT)/arm64.a .

ios-x86_64:
	CGO_ENABLED=1 \
	GOOS=darwin \
	GOARCH=amd64 \
	SDK=iphonesimulator \
	CC=$(PWD)/clangwrap.sh \
	go build -buildmode=c-archive -tags ios -o $(IOS_OUT)/x86_64.a .

ios: ios-arm64 ios-x86_64
	lipo $(IOS_OUT)/x86_64.a $(IOS_OUT)/arm64.a -create -output $(IOS_OUT)/cwtch.a
	cp $(IOS_OUT)/arm64.h $(IOS_OUT)/cwtch.h
