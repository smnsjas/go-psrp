package winrs

import "errors"

// Sentinel errors for WinRS operations.
var (
	// ErrShellClosed indicates the shell has already been closed.
	ErrShellClosed = errors.New("winrs: shell is closed")

	// ErrProcessDone indicates the process has already completed.
	ErrProcessDone = errors.New("winrs: process already completed")

	// ErrCommandFailed indicates the command execution failed.
	ErrCommandFailed = errors.New("winrs: command execution failed")

	// ErrInvalidExecutable indicates the executable path is invalid.
	ErrInvalidExecutable = errors.New("winrs: invalid executable")
)
