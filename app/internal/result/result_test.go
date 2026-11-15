package result

import "testing"

func TestExitCodes(t *testing.T) {
	cases := map[Status]int{
		OK: 0,
		InputError: 2,
		FormatError: 1,
		InvalidSignature: 1,
		ArtifactMismatch: 1,
	}

	for status, expected := range cases {
		got := ExitCode(status)
		if got != expected {
			t.Errorf(
				"%s: got %d, want %d",
				status,
				got, 
				expected,
			)
		}
	}
}
