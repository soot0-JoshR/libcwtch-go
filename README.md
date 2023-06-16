# NOTE: libcwtch-go has been deprecated in favour of [autobindings](https://git.openprivacy.ca/cwtch.im/autobindings). This repository has been archived and is now longer maintained.

# libcwtch-go

C-bindings for the Go Cwtch Library.

# Build Instructions
    make linux
    make android
    make windows
    make macos

## Android Build Notes

Our build infrastructure is using Go 1.15.10, NDK 21.0.6113669, 
and gomobile commit bdb1ca9a1e083af5929a8214e8a056d638ebbf2d (2021 07 16)

Go 1.17.4, NDK 22.1.7171670, and gomobile 4e6c2922fdeed32d3596616518aaee7b0d79ce55 (2021 12 07) appear to compile as well.

Other version combinations untested and some definitely do not work.

## Windows

Cwtch relies on sqlite which in turn requires the use of CGO. As per [this issue](https://github.com/golang/go/issues/12029) 
that means [TDM-GCC](https://jmeubank.github.io/tdm-gcc/download/) is required to be installed and used to compile on Windows. 
Install it and add it to your path and `make windows` should then work.

## Experimental iOS support
    make ios

# Using

## General Environment Variables

- `LOG_FILE` if defined will mean all go logging will go to a file instead of stdout
- `LOG_LEVEL` if set to `debug` will cause debug logging to be included in log output
- `CWTCH_PROFILE` if set to `1` will cause a memory profile to be written to `mem.prof` and all active goroutines
written to `stdout` when `DebugInfo()` is called.

## Linux Desktop:
 
 - `LD_LIBRARY_PATH` set to point to `libCwtch.so`
 - or drop a symlink into `/usr/lib`
 
## Android

- copy `cwtch.aar` into `flutter_app/android/cwtch`

## Windows

- copy libCwtch.dll into the directory of the `.exe` using it

## MacOS

- copy libCwtch.x64.dylib and libCwtch.arm.dylib into the directory you are executing from
