package parser

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/internal/fuzzseed"
)

// FuzzParsingWorker feeds arbitrary BMP streams through the parser. It calls
// parse directly so that a decoder panic fails the fuzzer instead of being
// recovered by parsingWorker.
func FuzzParsingWorker(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, m := range fuzzseed.BMPMessages() {
		f.Add(m, false)
	}
	f.Add(fuzzseed.BMPMessages()[0], true)
	f.Fuzz(func(t *testing.T, b []byte, raw bool) {
		NewParser(nil, nil, nil, &Config{EnableRawMode: raw}).parse(b)
	})
}
