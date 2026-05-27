package xldlogchecker

import (
	"os"
	"reflect"
	"testing"
)

// TestParseLog mirrors the original Python test suite (test.py).
// Log fixtures live in ../logs/ — identical files to the Python project.
var parseLogTests = []struct {
	path     string
	expected Result
}{
	// Non-existent file.
	{"../logs/not_real.log", Result{Message: "error: cannot open file", Status: "ERROR"}},
	// Valid XLD logs with correct signatures.
	{"../logs/01.log", Result{Message: "OK", Status: "OK"}},
	{"../logs/02.log", Result{Message: "OK", Status: "OK"}},
	// Tampered log — signature present but wrong.
	{"../logs/03.log", Result{Message: "Malformed", Status: "BAD"}},
	// Not an XLD log — no signature block.
	{"../logs/04.log", Result{Message: "Not a logfile", Status: "ERROR"}},
}

func TestParseLog(t *testing.T) {
	for _, tc := range parseLogTests {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			got := ParseLog(tc.path)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("ParseLog(%q)\n  got  %+v\n  want %+v", tc.path, got, tc.expected)
			}
		})
	}
}

// TestVerifyContent ensures VerifyContent produces identical results to
// ParseLog when given the same file bytes as a string.
func TestVerifyContent(t *testing.T) {
	contentTests := []struct {
		path     string
		expected Result
	}{
		{"../logs/01.log", Result{Message: "OK", Status: "OK"}},
		{"../logs/02.log", Result{Message: "OK", Status: "OK"}},
		{"../logs/03.log", Result{Message: "Malformed", Status: "BAD"}},
		{"../logs/04.log", Result{Message: "Not a logfile", Status: "ERROR"}},
	}

	for _, tc := range contentTests {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			data, err := os.ReadFile(tc.path)
			if err != nil {
				t.Skipf("cannot read %s: %v", tc.path, err)
			}
			got := VerifyContent(string(data))
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("VerifyContent(%q)\n  got  %+v\n  want %+v", tc.path, got, tc.expected)
			}
		})
	}
}

// TestSHA256XLD verifies the custom SHA-256 against a known-good value
// computed from the Python reference implementation.
// Input:  "hello" (UTF-8)
// Expected: the hex digest from sha256("hello".encode(), INITIAL_STATE)
func TestSHA256XLD(t *testing.T) {
	got := sha256XLD([]byte("hello"))
	// Pre-computed with the Python reference: sha256(b"hello", INITIAL_STATE)
	want := "a89021968e621062b267c46c968865794dd5c131cfd0c6db16a5991fe710efde"
	if got != want {
		t.Errorf("sha256XLD(\"hello\")\n  got  %s\n  want %s", got, want)
	}
}
