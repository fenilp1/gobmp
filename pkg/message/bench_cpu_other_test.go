//go:build !unix

package message

import "time"

// benchCPUTime reports that the process CPU time is not known.
func benchCPUTime() (time.Duration, bool) { return 0, false }
