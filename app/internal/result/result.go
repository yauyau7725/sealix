package result

import (
	"errors"
	"fmt"
)

type Status string

const (
	OK                   Status = "OK"
	InputError           Status = "INPUT_ERROR"
	FormatError          Status = "FORMAT_ERROR"
	UnsupportedAlgorithm Status = "UNSUPPORTED_ALGORITHM"
	KeyNotTrusted        Status = "KEY_NOT_TRUSTED"
	InvalidSignature     Status = "INVALID_SIGNATURE"
	MetadataMismatch     Status = "METADATA_MISMATCH"
	ArtifactMismatch     Status = "ARTIFACT_MISMATCH"
)

type Error struct {
	Status Status
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Status, e.Msg)
}

func New(s Status, msg string) error {
	return &Error{
		Status: s,
		Msg:    msg,
	}
}

func StatusOf(err error) Status {
	var resultErr *Error
	if errors.As(err, &resultErr) {
		return resultErr.Status
	}
	return ""
}

func ExitCode(s Status) int {
	if s == OK {
		return 0
	}
	if s == InputError {
		return 2
	}
	return 1
}
