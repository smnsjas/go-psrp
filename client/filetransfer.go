package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileTransferOptions configures file transfer behavior.
type FileTransferOptions struct {
	// ChunkSize specifies the size of each file chunk in bytes.
	// Default: 256KB (262144 bytes).
	ChunkSize int

	// MaxConcurrency limits the number of parallel chunk uploads/downloads.
	// Default: 4 goroutines.
	MaxConcurrency int

	// UseCompression enables gzip compression for file chunks.
	// Default: false (will auto-detect based on file type in future).
	UseCompression bool

	// ProgressCallback receives transfer progress updates.
	// Called with (bytesTransferred, totalBytes).
	ProgressCallback func(bytesTransferred, totalBytes int64)

	// VerifyChecksum enables SHA256 checksum verification after transfer.
	// Default: false (will be true in Phase 3).
	VerifyChecksum bool

	// Timeout overrides the automatic timeout calculation.
	// If zero, timeout is calculated based on file size.
	Timeout int
}

// DefaultFileTransferOptions returns sensible defaults.
func DefaultFileTransferOptions() FileTransferOptions {
	return FileTransferOptions{
		ChunkSize:      256 * 1024, // 256KB
		MaxConcurrency: 4,
		UseCompression: false,
		VerifyChecksum: false,
	}
}

// transferProgress tracks progress for a file transfer operation.
type transferProgress struct {
	mu               sync.Mutex
	bytesTransferred int64
	totalBytes       int64
	progressCallback func(int64, int64)
}

// update increments the bytes transferred and calls the progress callback.
func (p *transferProgress) update(bytes int64) {
	if p == nil || p.progressCallback == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.bytesTransferred += bytes
	p.progressCallback(p.bytesTransferred, p.totalBytes)
}

// validatePaths performs basic validation on file paths.
// This prevents common errors and potential security issues.
func validatePaths(localPath, remotePath string) error {
	// Validate local path
	if localPath == "" {
		return fmt.Errorf("local path cannot be empty")
	}

	// Check for directory traversal attempts in local path
	cleanLocal := filepath.Clean(localPath)
	if strings.Contains(localPath, "..") && cleanLocal != localPath {
		return fmt.Errorf("local path contains invalid traversal: %s", localPath)
	}

	// Validate remote path
	if remotePath == "" {
		return fmt.Errorf("remote path cannot be empty")
	}

	// Basic validation for Windows paths on remote
	// Allow UNC paths (\\server\share) and drive letters (C:\)
	if !strings.Contains(remotePath, ":") && !strings.HasPrefix(remotePath, "\\\\") {
		return fmt.Errorf("remote path must be absolute (e.g., C:\\path or \\\\server\\share): %s", remotePath)
	}

	// Check for directory traversal in remote path
	if strings.Contains(remotePath, "/../") || strings.Contains(remotePath, "\\..\\") {
		return fmt.Errorf("remote path contains invalid traversal: %s", remotePath)
	}

	return nil
}

// sanitizeForPowerShell escapes single quotes in strings for PowerShell script safety.
func sanitizeForPowerShell(s string) string {
	// In PowerShell single-quoted strings, single quotes are escaped by doubling them
	return strings.ReplaceAll(s, "'", "''")
}

// CopyFile uploads a local file to the remote host.
// This is a placeholder for Step 1.2 implementation.
func (c *Client) CopyFile(ctx context.Context, localPath, remotePath string, opts ...FileTransferOptions) error {
	// Apply defaults
	opt := DefaultFileTransferOptions()
	if len(opts) > 0 {
		if opts[0].ChunkSize > 0 {
			opt.ChunkSize = opts[0].ChunkSize
		}
		if opts[0].MaxConcurrency > 0 {
			opt.MaxConcurrency = opts[0].MaxConcurrency
		}
		opt.UseCompression = opts[0].UseCompression
		opt.ProgressCallback = opts[0].ProgressCallback
		opt.VerifyChecksum = opts[0].VerifyChecksum
		if opts[0].Timeout > 0 {
			opt.Timeout = opts[0].Timeout
		}
	}

	// Validate paths
	if err := validatePaths(localPath, remotePath); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Open local file
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	// Get file info
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	totalSize := stat.Size()

	// Initialize progress tracking
	var progress *transferProgress
	if opt.ProgressCallback != nil {
		progress = &transferProgress{
			totalBytes:       totalSize,
			progressCallback: opt.ProgressCallback,
		}
	}

	// Calculate number of chunks
	numChunks := (totalSize + int64(opt.ChunkSize) - 1) / int64(opt.ChunkSize)

	// Sanitize remote path for PowerShell
	safeRemotePath := sanitizeForPowerShell(remotePath)

	// Step 1: Initialize remote file (create empty file)
	initScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$stream = [IO.File]::Create('%s')
			$stream.Close()
		} catch {
			Write-Error "Failed to create file: $_"
			exit 1
		}
	`, safeRemotePath)

	c.logInfo("CopyFile: Initializing remote file %s", remotePath)
	_, err = c.Execute(ctx, initScript)
	if err != nil {
		return fmt.Errorf("failed to initialize remote file: %w", err)
	}

	// Step 2: Upload chunks sequentially (serial mode for Phase 1)
	c.logInfo("CopyFile: Uploading %d chunks (%d bytes)", numChunks, totalSize)

	buf := make([]byte, opt.ChunkSize)
	for i := int64(0); i < numChunks; i++ {
		// Read chunk
		n, readErr := file.Read(buf)
		if readErr != nil && n == 0 {
			return fmt.Errorf("failed to read chunk %d: %w", i, readErr)
		}

		chunk := buf[:n]

		// Encode to Base64
		b64 := base64.StdEncoding.EncodeToString(chunk)

		// Append chunk to remote file
		appendScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			try {
				$bytes = [Convert]::FromBase64String('%s')
				$stream = [IO.File]::Open('%s', [IO.FileMode]::Append)
				$stream.Write($bytes, 0, $bytes.Length)
				$stream.Close()
			} catch {
				Write-Error "Failed to write chunk: $_"
				exit 1
			}
		`, b64, safeRemotePath)

		_, err = c.Execute(ctx, appendScript)
		if err != nil {
			return fmt.Errorf("failed to upload chunk %d/%d: %w", i+1, numChunks, err)
		}

		// Update progress
		if progress != nil {
			progress.update(int64(n))
		}

		// Log progress every 10 chunks
		if (i+1)%10 == 0 || i == numChunks-1 {
			c.logInfo("CopyFile: Uploaded chunk %d/%d", i+1, numChunks)
		}
	}

	c.logInfo("CopyFile: Transfer complete (%d bytes)", totalSize)
	return nil
}

// FetchFile downloads a remote file to the local host.
// This is a placeholder for Step 1.3 implementation.
func (c *Client) FetchFile(ctx context.Context, remotePath, localPath string, opts ...FileTransferOptions) error {
	// Apply defaults
	opt := DefaultFileTransferOptions()
	if len(opts) > 0 {
		if opts[0].ChunkSize > 0 {
			opt.ChunkSize = opts[0].ChunkSize
		}
		if opts[0].MaxConcurrency > 0 {
			opt.MaxConcurrency = opts[0].MaxConcurrency
		}
		opt.UseCompression = opts[0].UseCompression
		opt.ProgressCallback = opts[0].ProgressCallback
		opt.VerifyChecksum = opts[0].VerifyChecksum
		if opts[0].Timeout > 0 {
			opt.Timeout = opts[0].Timeout
		}
	}

	// Validate paths
	if err := validatePaths(localPath, remotePath); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// TODO: Implement in Step 1.3
	return fmt.Errorf("FetchFile not yet implemented")
}
