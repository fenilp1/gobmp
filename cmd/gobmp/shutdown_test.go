package main

import (
	"testing"
	"time"
)

func TestStopWithin_Returns(t *testing.T) {
	called := false
	if err := stopWithin(func() { called = true }, time.Second); err != nil {
		t.Fatalf("stopWithin() error = %v, want nil", err)
	}
	if !called {
		t.Error("stopWithin() did not call stop")
	}
}

func TestStopWithin_Timeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	err := stopWithin(func() { <-release }, 50*time.Millisecond)
	if err == nil {
		t.Fatal("stopWithin() error = nil, want a timeout error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stopWithin() returned after %s, want about 50ms", d)
	}
}
