package client

import (
	"testing"
)

func TestValidatePaths(t *testing.T) {
	tests := []struct {
		name        string
		localPath   string
		remotePath  string
		expectError bool
	}{
		{
			name:        "valid_absolute_paths",
			localPath:   "/tmp/file.txt",
			remotePath:  "C:\\Users\\admin\\file.txt",
			expectError: false,
		},
		{
			name:        "valid_unc_path",
			localPath:   "/tmp/file.txt",
			remotePath:  "\\\\server\\share\\file.txt",
			expectError: false,
		},
		{
			name:        "empty_local_path",
			localPath:   "",
			remotePath:  "C:\\file.txt",
			expectError: true,
		},
		{
			name:        "empty_remote_path",
			localPath:   "/tmp/file.txt",
			remotePath:  "",
			expectError: true,
		},
		{
			name:        "relative_remote_path",
			localPath:   "/tmp/file.txt",
			remotePath:  "file.txt",
			expectError: true,
		},
		{
			name:        "remote_path_with_traversal",
			localPath:   "/tmp/file.txt",
			remotePath:  "C:\\Users\\..\\Windows\\file.txt",
			expectError: true,
		},
		{
			name:        "local_path_with_traversal",
			localPath:   "/tmp/../etc/file.txt",
			remotePath:  "C:\\file.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePaths(tt.localPath, tt.remotePath)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

func TestSanitizeForPowerShell(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no_quotes",
			input:    "simple string",
			expected: "simple string",
		},
		{
			name:     "single_quote",
			input:    "it's a string",
			expected: "it''s a string",
		},
		{
			name:     "multiple_quotes",
			input:    "can't won't don't",
			expected: "can''t won''t don''t",
		},
		{
			name:     "path_with_quote",
			input:    "C:\\Users\\O'Brien\\file.txt",
			expected: "C:\\Users\\O''Brien\\file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForPowerShell(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDefaultFileTransferOptions(t *testing.T) {
	opts := DefaultFileTransferOptions()

	// Default is 256KB (safe for 500KB WSMan envelope)
	if opts.ChunkSize != 256*1024 {
		t.Errorf("Expected ChunkSize 256KB (262144), got %d", opts.ChunkSize)
	}
	if opts.MaxConcurrency != 4 {
		t.Errorf("Expected MaxConcurrency 4, got %d", opts.MaxConcurrency)
	}
	if opts.UseCompression {
		t.Error("Expected UseCompression false by default")
	}
	if opts.VerifyChecksum {
		t.Error("Expected VerifyChecksum false by default")
	}
}

func TestDefaultFileTransferOptionsForTransport(t *testing.T) {
	// WSMan should use 256KB (safe for 500KB envelope)
	wsmanOpts := DefaultFileTransferOptionsForTransport(TransportWSMan)
	if wsmanOpts.ChunkSize != 256*1024 {
		t.Errorf("WSMan: Expected ChunkSize 256KB, got %d", wsmanOpts.ChunkSize)
	}

	// HvSocket should use 1MB (no envelope limit)
	hvOpts := DefaultFileTransferOptionsForTransport(TransportHvSocket)
	if hvOpts.ChunkSize != 1024*1024 {
		t.Errorf("HvSocket: Expected ChunkSize 1MB, got %d", hvOpts.ChunkSize)
	}
}

func TestTransferProgress_Update(t *testing.T) {
	var lastTransferred, lastTotal int64
	callback := func(transferred, total int64) {
		lastTransferred = transferred
		lastTotal = total
	}

	progress := &transferProgress{
		totalBytes:       1000,
		progressCallback: callback,
	}

	// Update with 100 bytes
	progress.update(100)
	if lastTransferred != 100 || lastTotal != 1000 {
		t.Errorf("Expected (100, 1000), got (%d, %d)", lastTransferred, lastTotal)
	}

	// Update with another 200 bytes
	progress.update(200)
	if lastTransferred != 300 || lastTotal != 1000 {
		t.Errorf("Expected (300, 1000), got (%d, %d)", lastTransferred, lastTotal)
	}
}

func TestTransferProgress_NoCallback(t *testing.T) {
	progress := &transferProgress{
		totalBytes: 1000,
		// No callback set
	}

	// Should not panic
	progress.update(100)
}
