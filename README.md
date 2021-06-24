# libcwtch-go

C-bindings for the Go Cwtch Library.

# Build Instructions...
    make linux
    make android

# Using

## Linux Desktop:
 
 - `LD_LIBRARY_PATH` set to point to `libCwtch.so`
 - or drop a symlink into `/usr/lib`
 
## Android

- copy `cwtch.aar` into `flutter_app/android/cwtch`
