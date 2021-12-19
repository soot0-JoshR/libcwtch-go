# libcwtch-go

C-bindings for the Go Cwtch Library.

# Build Instructions
    make linux
    make android
    make windows

## Android Build Notes

Our build infrastructure is using Go 1.15.10, NDK 21.0.6113669, 
and gomobile commit bdb1ca9a1e083af5929a8214e8a056d638ebbf2d (2021 07 16)

Go 1.17.4, NDK 22.1.7171670, and gomobile 4e6c2922fdeed32d3596616518aaee7b0d79ce55 (2021 12 07) appear to compile as well.

Other version combinations untested and some definitely do not work.

## Experimental iOS support
    make ios

# Using

## Linux Desktop:
 
 - `LD_LIBRARY_PATH` set to point to `libCwtch.so`
 - or drop a symlink into `/usr/lib`
 
## Android

- copy `cwtch.aar` into `flutter_app/android/cwtch`

## Windows

- copy libCwtch.dll into the directory of the `.exe` using it
