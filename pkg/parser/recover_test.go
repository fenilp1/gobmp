package parser

import "testing"

// parsingWorker must contain a panic to the message that caused it. A parser
// with no config dereferences nil, standing in for any decoder bug. The
// second panic takes the path that logs without a stack trace.
func TestParsingWorkerRecoversPanic(t *testing.T) {
	p := &parser{}
	p.parsingWorker(buildInitiationMsg())
	p.parsingWorker(buildInitiationMsg())
	if !p.panicked.Load() {
		t.Fatal("recovered panic not recorded")
	}
}
