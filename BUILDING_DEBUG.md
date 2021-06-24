
*sometimes: rm -rf $GOPATH/pkg*

*sometimes: rm -rf /tmp/gomobile*

rm -rf vendor

go clean --modcache

go mod download

go get -u golang.org/x/mobile

go get -u golang.org/x/mobile/bind

gomobile clean

gomobile init

make android

# errors

```
# runtime/cgo
gcc_android.c:6:10: fatal error: android/log.h: No such file or directory
 #include <android/log.h>
          ^~~~~~~~~~~~~~~
compilation terminated.```
```

*solution:* run `gomobile init`
