package utils

import (
	"runtime"
	"testing"
	"time"
)

// Test timeout policy, checking for goroutine leaks in addition to successful timeouts
func TestTimeoutPolicy(t *testing.T) {

	gonumStart := runtime.NumGoroutine()

	tp := TimeoutPolicy(time.Second)

	// test with timeout
	err := tp.ExecuteAction(func() error {
		time.Sleep(time.Second * 2)
		return nil
	})
	if err == nil {
		t.Fatalf("timeout should have occurred")
	}

	// test without timeout
	err = tp.ExecuteAction(func() error {
		return nil
	})

	if err != nil {
		t.Fatalf("timeout should not have occurred")
	}

	// wait for gorutine clean up
	time.Sleep(time.Second * 4)

	// final check
	gonumEnd := runtime.NumGoroutine()
	if gonumStart != gonumEnd {
		t.Fatalf("goroutine leak in execute action")
	}
}
