IOS_OUT := ./ios

.PHONY: all linux android windows macos clean ios

DEFAULT_GOAL: linux

all: linux android windows

linux: libCwtch.so

macos: libCwtch.x64.dylib libCwtch.arm64.dylib

android: cwtch.aar

windows: libCwtch.dll

libCwtch.so: lib.go 
	./switch-ffi.sh
	go build -trimpath -ldflags "-buildid=$(shell git describe --tags) -X main.buildVer=$(shell git describe --tags) -X main.buildDate=$(shell git log -1 --format=%cd --date=format:%G-%m-%d-%H-%M)" -buildmode c-shared -o libCwtch.so

libCwtch.x64.dylib: lib.go
	./switch-ffi.sh
	go build -trimpath -ldflags "-buildid=$(shell git describe --tags) -X main.buildVer=$(shell git describe --tags) -X main.buildDate=$(shell git log -1 --format=%cd --date=format:%G-%m-%d-%H-%M)" -buildmode c-shared -o libCwtch.x64.dylib

libCwtch.arm64.dylib: lib.go
	./switch-ffi.sh
	env GOARCH=arm64 GOOS=darwin CGO_ENABLED=1 go build -trimpath -ldflags "-buildid=$(shell git describe --tags)  -X main.buildVer=$(shell git describe --tags) -X main.buildDate=$(shell git log -1 --format=%cd --date=format:%G-%m-%d-%H-%M)" -buildmode c-shared -o libCwtch.arm64.dylib

cwtch.aar: lib.go
	./switch-gomobile.sh
	gomobile bind -androidapi 19 -trimpath -target android/arm,android/arm64,android/amd64 -ldflags="-buildid=$(shell git describe --tags) -X cwtch.buildVer=$(shell git describe --tags) -X cwtch.buildDate=$(shell git log -1 --format=%cd --date=format:%G-%m-%d-%H-%M)"

libCwtch.dll: lib.go
	./switch-ffi.sh
	# '-Xlinker --no-insert-timestamp` sets the output dll PE timestamp header to all zeros, instead of the actual time
	# this is necessary for reproducible builds (see: https://wiki.debian.org/ReproducibleBuilds/TimestampsInPEBinaries for additional information)
	# note: the above documentation also references an ability to set an optional timestamp - this behaviour seems to no longer be supported in more recent versions of mingw32-gcc (the help docs no longer reference that functionality)
	# these flags have to be passed through to the underlying gcc process using the -extldflags option in the underlying go linker, note that the whole flag is quoted...this is necessary.
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -trimpath -ldflags "-buildid=$(shell git describe --tags)  -X main.buildVer=$(shell git describe --tags) -X main.buildDate=$(shell git log -1 --format=%cd --date=format:%G-%m-%d-%H-%M) '-extldflags=-Xlinker --no-insert-timestamp'" -buildmode c-shared -o libCwtch.dll

clean: 
	rm -f cwtch.aar cwtch_go.apk libCwtch.h libCwtch.so cwtch-sources.jar libCwtch.dll libCwtch.dylib

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
