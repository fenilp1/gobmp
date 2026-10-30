//go:build unix

package message

import (
	"syscall"
	"time"
)

// benchCPUTime returns the user and system CPU time the process has used.
func benchCPUTime() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), true
}
