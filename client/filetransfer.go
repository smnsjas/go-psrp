package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/smnsjas/go-psrpcore/serialization"
)

// Buffer pool for chunk allocation (zero-copy optimization)
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 256*1024) // 256KB default
		return &b
	},
}

const (
	// maxChunkBase64Size limits Base64 encoded chunk size (defense in depth)
	maxChunkBase64Size = 2 * 1024 * 1024 // 2MB Base64 (~1.5MB raw)
)

// FileTransferOptions configures file transfer behavior.
type FileTransferOptions struct {
	// ChunkSize specifies the size of each file chunk in bytes.
	// Default: 256KB (262144 bytes).
	ChunkSize int

	// MaxConcurrency limits the number of parallel chunk uploads/downloads.
	// Default: 4 goroutines (Phase 2).
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

	// MaxFileSize limits the total file size in bytes to prevent resource exhaustion.
	// Default: 1GB (can be disabled by setting to -1).
	MaxFileSize int64
}

// FileTransferOption is a functional option for configuring file transfers.
type FileTransferOption func(*FileTransferOptions)

// WithChunkSize sets the chunk size for file transfer.
func WithChunkSize(size int) FileTransferOption {
	return func(o *FileTransferOptions) { o.ChunkSize = size }
}

// WithMaxConcurrency sets the maximum number of concurrent chunk transfers.
func WithMaxConcurrency(n int) FileTransferOption {
	return func(o *FileTransferOptions) { o.MaxConcurrency = n }
}

// WithCompression enables or disables compression.
func WithCompression(enabled bool) FileTransferOption {
	return func(o *FileTransferOptions) { o.UseCompression = enabled }
}

// WithProgressCallback sets a progress callback function.
func WithProgressCallback(cb func(int64, int64)) FileTransferOption {
	return func(o *FileTransferOptions) { o.ProgressCallback = cb }
}

// WithChecksumVerification enables or disables checksum verification.
func WithChecksumVerification(enabled bool) FileTransferOption {
	return func(o *FileTransferOptions) { o.VerifyChecksum = enabled }
}

// WithTimeout sets a custom timeout.
func WithTimeout(seconds int) FileTransferOption {
	return func(o *FileTransferOptions) { o.Timeout = seconds }
}

// WithMaxFileSize sets the maximum allowed file size in bytes.
// Set to -1 to disable the limit (use with caution).
func WithMaxFileSize(bytes int64) FileTransferOption {
	return func(o *FileTransferOptions) { o.MaxFileSize = bytes }
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

// generateInitScript creates the PowerShell script to initialize the destination file.
// It uses Base64 encoding for the path to prevent command injection.
func generateInitScript(remotePath string) string {
	remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
	return fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$pathBytes = [System.Convert]::FromBase64String('%s')
			$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
			$stream = [IO.File]::Create($path)
			$stream.Close()
		} catch {
			Write-Error "Failed to create file: $_"
			exit 1
		}
	`, remotePathB64)
}

// generateAppendScript creates the PowerShell script to append a chunk to the destination file.
// It uses Base64 encoding for the path to prevent command injection.
func generateAppendScript(remotePath, chunkB64 string) string {
	remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
	return fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$pathBytes = [System.Convert]::FromBase64String('%s')
			$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
			
			$bytes = [Convert]::FromBase64String('%s')
			$stream = [IO.File]::Open($path, [IO.FileMode]::Append)
			$stream.Write($bytes, 0, $bytes.Length)
			$stream.Close()
		} catch {
			Write-Error "Failed to write chunk: $_"
			exit 1
		}
	`, remotePathB64, chunkB64)
}

// CopyFile uploads a local file to the remote host.
// Files are transferred in chunks using Base64 encoding over PowerShell remoting.
// For large files, consider enabling compression or adjusting the chunk size.
func (c *Client) CopyFile(ctx context.Context, localPath, remotePath string, opts ...FileTransferOption) error {
	// Apply defaults and options
	opt := DefaultFileTransferOptions()
	for _, fn := range opts {
		fn(&opt)
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

	// Security: Validate file type (prevent symlink/device readout)
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file (mode: %s)", stat.Mode())
	}

	totalSize := stat.Size()

	// Security: Enforce MaxFileSize limit (Resource Exhaustion protection)
	maxSize := opt.MaxFileSize
	if maxSize == 0 {
		maxSize = 1024 * 1024 * 1024 // Default 1GB safety limit
	}

	// Allow explicitly disabling limit with negative value, but default to safe 1GB
	if opt.MaxFileSize > 0 {
		maxSize = opt.MaxFileSize
	} else if opt.MaxFileSize < 0 {
		maxSize = 0 // Disabled
	}

	if maxSize > 0 && totalSize > maxSize {
		return fmt.Errorf("file too large: %d bytes (max allowed: %d)", totalSize, maxSize)
	}

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

	// Security Event: Log transfer start
	c.logSecurityEvent("FILE_TRANSFER_START", map[string]interface{}{
		"operation":   "CopyFile",
		"source":      localPath,
		"destination": remotePath,
		"size_bytes":  totalSize,
		"chunk_count": numChunks,
	})

	// Step 1: Initialize remote file (create empty file)
	initScript := generateInitScript(remotePath)

	c.logInfo("CopyFile: Initializing remote file %s", remotePath)
	_, err = c.Execute(ctx, initScript)
	if err != nil {
		c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
			"operation": "CopyFile",
			"phase":     "initialize",
			"error":     err.Error(),
		})
		// Sanitize error (Finding 4)
		if strings.Contains(err.Error(), "Access is denied") {
			return fmt.Errorf("initialization failed: permission denied")
		}
		return fmt.Errorf("initialization failed: remote operation error")
	}

	// Step 2: Upload chunks sequentially (serial mode for Phase 1)
	c.logInfo("CopyFile: Uploading %d chunks (%d bytes)", numChunks, totalSize)

	// Get buffer from pool
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := (*bufPtr)[:opt.ChunkSize]

	// Initialize Hasher if verification is enabled
	var hasher hash.Hash
	if opt.VerifyChecksum {
		hasher = sha256.New()
	}

	for i := int64(0); i < numChunks; i++ {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("transfer cancelled: %w", ctx.Err())
		default:
		}

		// Read chunk
		n, readErr := file.Read(buf)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("failed to read chunk %d: %w", i, readErr)
		}
		if n == 0 {
			break // End of file
		}

		chunk := buf[:n]

		// Update hash if verification is enabled
		if hasher != nil {
			hasher.Write(chunk)
		}

		// Encode to Base64
		b64 := base64.StdEncoding.EncodeToString(chunk)

		// Validate Base64 size (defense in depth)
		if len(b64) > maxChunkBase64Size {
			return fmt.Errorf("chunk %d too large after encoding: %d bytes", i, len(b64))
		}

		// Append chunk to remote file
		appendScript := generateAppendScript(remotePath, b64)

		_, err = c.Execute(ctx, appendScript)
		if err != nil {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation": "CopyFile",
				"phase":     "upload_chunk",
				"chunk":     i,
				"error":     err.Error(),
			})
			return fmt.Errorf("failed to upload chunk %d/%d: remote operation error", i+1, numChunks)
		}

		// Update progress
		if progress != nil {
			progress.update(int64(n))
		}

		// Log progress every 10 chunks (only if logging is enabled)
		if (i+1)%10 == 0 || i == numChunks-1 {
			c.logInfo("CopyFile: Uploaded chunk %d/%d", i+1, numChunks)
		}
	}

	// Step 3: Verify Checksum (if enabled)
	if opt.VerifyChecksum {
		c.logInfo("CopyFile: Verifying checksum...")
		localHash := hex.EncodeToString(hasher.Sum(nil))

		// Check remote hash using Get-FileHash
		// Re-encode path for verification script
		remotePathB64ForVerify := base64.StdEncoding.EncodeToString([]byte(remotePath))

		verifyScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			try {
				$pathBytes = [System.Convert]::FromBase64String('%s')
				$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
				(Get-FileHash -Algorithm SHA256 -Path $path).Hash
			} catch {
				Write-Error "Failed to verify checksum: $_"
				exit 1
			}
		`, remotePathB64ForVerify)

		result, err := c.Execute(ctx, verifyScript)
		if err != nil {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation": "CopyFile",
				"phase":     "verify_checksum",
				"error":     err.Error(),
			})
			return fmt.Errorf("failed to verify checksum: remote operation error")
		}

		var output string
		if result != nil && len(result.Output) > 0 {
			// output from c.Execute result.Output is []interface{}
			// Handle various return types from PowerShell serialization
			if s, ok := result.Output[0].(string); ok {
				output = s
			} else if psObj, ok := result.Output[0].(*serialization.PSObject); ok {
				output = psObj.ToString
			} else {
				// Fallback generic string conversion for safety
				output = fmt.Sprintf("%v", result.Output[0])
			}
		}

		remoteHash := strings.TrimSpace(output)
		if !strings.EqualFold(remoteHash, localHash) {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation":   "CopyFile",
				"phase":       "checksum_mismatch",
				"local_hash":  localHash,
				"remote_hash": remoteHash,
			})
			return fmt.Errorf("checksum mismatch! local: %s, remote: %s", localHash, remoteHash)
		}

		c.logInfo("CopyFile: Checksum verified (SHA256: %s)", localHash)
	}

	// Security Event: Log completion
	c.logSecurityEvent("FILE_TRANSFER_COMPLETE", map[string]interface{}{
		"operation":   "CopyFile",
		"destination": remotePath,
		"bytes_sent":  totalSize,
		"status":      "success",
		"verified":    opt.VerifyChecksum,
	})

	c.logInfo("CopyFile: Transfer complete (%d bytes)", totalSize)
	return nil
}

// FetchFile downloads a remote file to the local host.
// This is a placeholder for Step 1.3 implementation.
func (c *Client) FetchFile(ctx context.Context, remotePath, localPath string, opts ...FileTransferOption) error {
	// Apply defaults and options
	opt := DefaultFileTransferOptions()
	for _, fn := range opts {
		fn(&opt)
	}

	// Validate paths
	if err := validatePaths(localPath, remotePath); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// TODO: Implement in Step 1.3
	return fmt.Errorf("FetchFile not yet implemented")
}
