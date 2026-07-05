package utils

import (
	"context"
	"fmt"
	"time"
)

// TimeoutPolicy is an interface for enforcing common timeout patterns
type TimeoutPolicy time.Duration

// ExecuteAction runs a function and returns an error if it hasn't returned
// by the time specified by TimeoutPolicy
func (tp *TimeoutPolicy) ExecuteAction(action func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*tp))
	defer cancel()

	// channel is buffered- this is important!
	c := make(chan error, 1)
	go func() {
		// this write is non-blocking as this goroutine has sole access to the channel
		c <- action()
	}()

	select {
	case err := <-c:
		return err
	case <-ctx.Done():
		return fmt.Errorf("ActionTimedOutError")
	}
}
