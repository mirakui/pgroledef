package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandReportsInjectedValues(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	t.Cleanup(func() { version, commit, date = origVersion, origCommit, origDate })
	version, commit, date = "1.2.3", "abc1234", "2026-09-17T00:00:00Z"

	var out bytes.Buffer
	cmd := newVersionCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	got := strings.TrimRight(out.String(), "\n")
	want := "pgroledef 1.2.3 (abc1234, 2026-09-17T00:00:00Z)"
	if got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestVersionDefaultsAreSetForSourceBuilds(t *testing.T) {
	if version == "" || commit == "" || date == "" {
		t.Fatalf("version vars must have non-empty defaults: %q %q %q", version, commit, date)
	}
}
