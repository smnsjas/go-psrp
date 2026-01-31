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
	"time"

	"github.com/smnsjas/go-psrpcore/serialization"
	"golang.org/x/sync/errgroup"
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
	// DEPRECATED: Use ChunkTimeout instead. This field is ignored.
	Timeout int

	// ChunkTimeout is the timeout for each individual chunk operation.
	// Default: 60 seconds. If a single chunk takes longer than this, the
	// transfer fails. There is no overall transfer timeout - as long as
	// chunks keep completing within ChunkTimeout, the transfer continues.
	ChunkTimeout time.Duration

	// MaxFileSize limits the total file size in bytes to prevent resource exhaustion.
	// Default: 1GB (can be disabled by setting to -1).
	MaxFileSize int64

	// NoOverwrite prevents overwriting an existing destination file.
	// If true, the transfer fails if the file exists.
	NoOverwrite bool
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

// WithChunkTimeout sets the timeout for each individual chunk operation.
// Default: 60 seconds. As long as chunks complete within this timeout,
// the transfer will continue indefinitely.
func WithChunkTimeout(d time.Duration) FileTransferOption {
	return func(o *FileTransferOptions) { o.ChunkTimeout = d }
}

// WithNoOverwrite sets whether to fail if the destination file exists.
func WithNoOverwrite(noOverwrite bool) FileTransferOption {
	return func(o *FileTransferOptions) { o.NoOverwrite = noOverwrite }
}

// DefaultFileTransferOptions returns sensible defaults for WSMan transport.
// For HvSocket, use DefaultFileTransferOptionsForTransport(TransportHvSocket).
func DefaultFileTransferOptions() FileTransferOptions {
	return FileTransferOptions{
		ChunkSize:      256 * 1024, // 256KB safe for 500KB envelope (341KB after Base64)
		MaxConcurrency: 4,
		UseCompression: false,
		VerifyChecksum: false,
		ChunkTimeout:   60 * time.Second, // Per-chunk timeout (no overall timeout)
	}
}

// DefaultFileTransferOptionsForTransport returns optimal defaults based on transport type.
// WSMan: 256KB chunks (limited by MaxEnvelopeSizeKb, conservative to avoid edge cases)
// HvSocket: 1MB chunks (no envelope limit)
func DefaultFileTransferOptionsForTransport(transport TransportType) FileTransferOptions {
	opts := DefaultFileTransferOptions()

	switch transport {
	case TransportHvSocket:
		// HvSocket has no SOAP envelope limit - use larger chunks
		opts.ChunkSize = 1024 * 1024 // 1MB
	case TransportWSMan:
		// WSMan limited by MaxEnvelopeSizeKb (default 500KB)
		// 256KB raw = ~341KB Base64, leaving room for SOAP/script overhead
		opts.ChunkSize = 256 * 1024 // 256KB (conservative)
	}

	return opts
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

// generateOffsetWriteScript creates a PowerShell script to write a chunk at a specific offset.
// This enables parallel chunk uploads by allowing out-of-order writes.
func generateOffsetWriteScript(remotePath string, offset int64, chunkB64 string) string {
	remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
	return fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$pathBytes = [System.Convert]::FromBase64String('%s')
			$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
			
			$bytes = [Convert]::FromBase64String('%s')
			$stream = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::Write)
			$stream.Seek(%d, [IO.SeekOrigin]::Begin) | Out-Null
			$stream.Write($bytes, 0, $bytes.Length)
			$stream.Close()
		} catch {
			Write-Error "Failed to write chunk at offset %d: $_"
			exit 1
		}
	`, remotePathB64, chunkB64, offset, offset)
}

// generatePreallocateScript creates a PowerShell script to pre-allocate a file to a specific size.
// This is used for parallel uploads to ensure the file exists with correct size before chunks are written.
func generatePreallocateScript(remotePath string, size int64) string {
	remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
	return fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$pathBytes = [System.Convert]::FromBase64String('%s')
			$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
			$stream = [IO.File]::Create($path)
			$stream.SetLength(%d)
			$stream.Close()
		} catch {
			Write-Error "Failed to pre-allocate file: $_"
			exit 1
		}
	`, remotePathB64, size)
}

// CopyFile uploads a local file to the remote host.
// Files are transferred in chunks using Base64 encoding over PowerShell remoting.
// For large files, consider enabling compression or adjusting the chunk size.
func (c *Client) CopyFile(ctx context.Context, localPath, remotePath string, opts ...FileTransferOption) error {
	// Apply transport-aware defaults and user options
	opt := DefaultFileTransferOptionsForTransport(c.config.Transport)
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
		"parallel":    opt.MaxConcurrency > 1 && numChunks > 1,
	})

	// Determine optimization strategy
	// If concurrency > 1 and file size > chunk size, use parallel upload
	if opt.MaxConcurrency > 1 && numChunks > 1 {
		if err := c.copyFileParallel(ctx, file, remotePath, opt, totalSize, progress); err != nil {
			return err
		}
		return nil
	}

	// Use streaming mode for serial/small transfers
	// Streaming uses a single pipeline and feeds chunks as input, avoiding pipeline creation overhead.
	if err := c.copyFileStreaming(ctx, file, remotePath, opt, totalSize, progress); err != nil {
		return err
	}

	return nil
}

// copyFileStreaming uploads a file using a single streaming pipeline.
// This is more efficient than chunked uploads as it avoids per-chunk overhead (pipeline creation).
// It streams file chunks as pipeline input to a script that writes them to the destination.
func (c *Client) copyFileStreaming(ctx context.Context, file *os.File, remotePath string, opt FileTransferOptions, totalSize int64, progress *transferProgress) error {
	chunkSize := int64(opt.ChunkSize)
	numChunks := (totalSize + chunkSize - 1) / chunkSize

	c.logInfo("CopyFile: Streaming upload (chunks: %d, size: %d, chunk_size: %d)", numChunks, totalSize, chunkSize)

	// Prepare script that reads from input stream
	pathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
	// Prepare file creation command (overwrite vs check)
	createCmd := "$s = [System.IO.File]::Create($path)"
	if opt.NoOverwrite {
		// Use Open with CreateNew mode to atomically fail if file exists
		createCmd = "$s = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)"
	}

	// Script: Create file, read Base64 from input, write to file
	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		$path = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s'))
		%s
		$s.SetLength(%d)
		try {
			$input | ForEach-Object {
				$s.Write($_, 0, $_.Length)
			}
		} finally {
			$s.Close()
		}
	`, pathB64, createCmd, totalSize)

	// Start streaming pipeline
	sr, err := c.ExecuteStreamWithInput(ctx, script)
	if err != nil {
		return fmt.Errorf("start stream: %w", err)
	}

	// Prepare hasher if verification enabled
	var hasher hash.Hash
	if opt.VerifyChecksum {
		hasher = sha256.New()
	}

	// Send chunks in background or current goroutine?
	// Sending blocks on flow control, so we should do it here, but need to monitor output/errors?
	// StreamResult channels are buffered. If script fails, it might send error output.
	// But ExecuteStreamWithInput is non-blocking start.
	// We can loop send here.

	// Use a function to handle sending so we can defer CloseInput
	sendErr := func() error {
		defer func() {
			if err := sr.CloseInput(ctx); err != nil {
				c.logWarn("CopyFile: Failed to close input: %v", err)
			}
		}()

		buf := make([]byte, chunkSize)
		for i := int64(0); i < numChunks; i++ {
			// Check context
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			n, err := file.Read(buf)
			if err != nil && err != io.EOF {
				return fmt.Errorf("read chunk %d: %w", i, err)
			}
			if n == 0 {
				break
			}

			chunk := buf[:n]

			// Hash (before encoding)
			if opt.VerifyChecksum {
				hasher.Write(chunk)
			}

			// Send raw bytes to pipeline (efficiently serialized as <BA>)
			if err := sr.SendInput(ctx, chunk); err != nil {
				return fmt.Errorf("send chunk %d: %w", i, err)
			}

			// Update progress
			if progress != nil {
				progress.update(int64(n))
			}

			// Log occasionally
			if (i+1)%10 == 0 || i == numChunks-1 {
				c.logInfo("CopyFile: Streamed chunk %d/%d", i+1, numChunks)
			}
		}
		return nil
	}()

	// Wait for pipeline to complete (catches script errors)
	// If send failed, we might want to Cancel?
	if sendErr != nil {
		c.logError("CopyFile: Send failed, canceling pipeline: %v", sendErr)
		sr.Cancel()
	}

	// Wait for script completion
	waitErr := sr.Wait()

	if sendErr != nil {
		// If send failed because pipeline failed, prefer the pipeline error (waitErr)
		// because it contains the actual script exception (e.g. "File exists")
		if waitErr != nil && strings.Contains(sendErr.Error(), "invalid pipeline state") {
			return fmt.Errorf("transfer failed: %w", waitErr)
		}
		return sendErr
	}
	if waitErr != nil {
		c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
			"operation": "CopyFile",
			"phase":     "stream_wait",
			"error":     waitErr.Error(),
		})
		return fmt.Errorf("stream execution failed: %w", waitErr)
	}

	// Verify Checksum if enabled
	if opt.VerifyChecksum {
		c.logInfo("CopyFile: Verifying checksum...")
		localHash := hex.EncodeToString(hasher.Sum(nil))

		verifyScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			$path = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s'))
			(Get-FileHash -Algorithm SHA256 -Path $path).Hash
		`, pathB64)

		res, err := c.Execute(ctx, verifyScript)
		if err != nil {
			return fmt.Errorf("verify checksum execution failed: %w", err)
		}

		var remoteHash string
		if res != nil && len(res.Output) > 0 {
			if s, ok := res.Output[0].(string); ok {
				remoteHash = strings.TrimSpace(s)
			} else if psObj, ok := res.Output[0].(*serialization.PSObject); ok {
				remoteHash = strings.TrimSpace(psObj.ToString)
			} else {
				remoteHash = fmt.Sprintf("%v", res.Output[0])
			}
		}

		if !strings.EqualFold(localHash, remoteHash) {
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
		"mode":        "streaming",
	})
	c.logInfo("CopyFile: Transfer complete (%d bytes, streaming)", totalSize)

	return nil
}

// copyFileParallel uploads a file using concurrent pipelines.
// This is faster for large files as it utilizes multiple connections.
func (c *Client) copyFileParallel(ctx context.Context, file *os.File, remotePath string, opt FileTransferOptions, totalSize int64, progress *transferProgress) error {
	chunkSize := int64(opt.ChunkSize)
	numChunks := (totalSize + chunkSize - 1) / chunkSize

	c.logInfo("CopyFile: Parallel upload (chunks: %d, size: %d, concurrency: %d)", numChunks, totalSize, opt.MaxConcurrency)

	// Step 1: Pre-allocate file on server
	preallocScript := generatePreallocateScript(remotePath, totalSize)
	if _, err := c.Execute(ctx, preallocScript); err != nil {
		c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
			"operation": "CopyFile",
			"phase":     "preallocate",
			"error":     err.Error(),
		})
		if strings.Contains(err.Error(), "Access is denied") {
			return fmt.Errorf("initialization failed: permission denied")
		}
		return fmt.Errorf("initialization failed: remote operation error")
	}

	// Step 2: Upload chunks in parallel using a worker pool
	// We use a fixed number of workers to prevent connection storms and excessive auth.
	// Each worker maintains its own cloned client (and thus its own Authenticated Transport).
	concurrency := opt.MaxConcurrency
	if concurrency > int(numChunks) {
		concurrency = int(numChunks)
	}

	// Job channel
	type chunkJob struct {
		index  int64
		offset int64
	}
	jobCh := make(chan chunkJob, numChunks)
	for i := int64(0); i < numChunks; i++ {
		jobCh <- chunkJob{index: i, offset: i * chunkSize}
	}
	close(jobCh)

	// Result map for checksum
	type chunkResult struct {
		index int64
		data  []byte
	}
	chunkResults := make(map[int64]chunkResult)
	var resultsMu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)

	// Semaphore to limit concurrency (re-added for shared client)
	sem := make(chan struct{}, opt.MaxConcurrency)

	for w := 0; w < concurrency; w++ {
		// Capture worker ID for logging/debugging
		workerID := w

		g.Go(func() error {
			// Acquire semaphore to limit concurrency
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return ctx.Err()
			}

			// Reusable buffer for this worker
			buf := make([]byte, chunkSize)

				// Create a worker for this goroutine
				// This ensures each worker gets its own Authentication Context to avoid race conditions.
				workerClient, err := c.CreateWorker()
				if err != nil {
					return fmt.Errorf("create worker %d: %w", workerID, err)
				}
				if err := workerClient.Connect(ctx); err != nil {
					_ = workerClient.Close(context.Background())
					return fmt.Errorf("connect worker %d: %w", workerID, err)
				}
				defer workerClient.Close(context.Background())

			for job := range jobCh {
				// Check cancellation
				if ctx.Err() != nil {
					return ctx.Err()
				}

				// Read chunk
				// Use ReadAt on the shared file handle (thread-safe on *os.File)
				n, err := file.ReadAt(buf, job.offset)
				if err != nil && err != io.EOF {
					return fmt.Errorf("read chunk %d: %w", job.index, err)
				}
				if n == 0 {
					continue
				}
				chunkData := buf[:n]

				// Encode chunk
				chunkB64 := base64.StdEncoding.EncodeToString(chunkData)

				// Validate Base64 size
				if len(chunkB64) > maxChunkBase64Size {
					return fmt.Errorf("chunk %d too large after encoding: %d bytes (limit: %d)", job.index, len(chunkB64), maxChunkBase64Size)
				}

				// Write chunk at specific offset
				script := generateOffsetWriteScript(remotePath, job.offset, chunkB64)

				// Use per-chunk timeout - each chunk gets its own deadline
				chunkTimeout := opt.ChunkTimeout
				if chunkTimeout == 0 {
					chunkTimeout = 60 * time.Second
				}
				chunkCtx, chunkCancel := context.WithTimeout(ctx, chunkTimeout)

				// Execute using dedicated worker client
				_, execErr := workerClient.Execute(chunkCtx, script)
				chunkCancel()

				if execErr != nil {
					c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
						"operation": "CopyFile",
						"phase":     "upload_chunk",
						"chunk":     job.index,
						"error":     execErr.Error(),
					})
					return fmt.Errorf("failed to upload chunk %d (worker %d): %w", job.index, workerID, execErr)
				}

				// Store for later hash computation (in order)
				if opt.VerifyChecksum {
					// Make a copy of the chunk data because buffer is reused
					dataCopy := make([]byte, len(chunkData))
					copy(dataCopy, chunkData)

					resultsMu.Lock()
					chunkResults[job.index] = chunkResult{index: job.index, data: dataCopy}
					resultsMu.Unlock()
				}

				// Update progress
				if progress != nil {
					progress.update(int64(n))
				}

				// Log progress (but not too often to avoid spam)
				if (job.index+1)%10 == 0 || job.index == numChunks-1 {
					c.logInfo("CopyFile: Uploaded chunk %d/%d", job.index+1, numChunks)
				}
			}
			return nil
		})
	}

	// Wait for all chunks to complete
	if err := g.Wait(); err != nil {
		return err
	}

	// Compute hash in order if verification enabled
	if opt.VerifyChecksum {
		// Use a temporary hasher to assemble results
		var hasher hash.Hash
		if opt.VerifyChecksum {
			hasher = sha256.New()
		}

		for i := int64(0); i < numChunks; i++ {
			if cr, ok := chunkResults[i]; ok {
				hasher.Write(cr.data)
			}
		}

		localHash := hex.EncodeToString(hasher.Sum(nil))

		// Verify remote hash
		remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))
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
		`, remotePathB64)

		// Retry verification up to 3 times
		// Large uploads can cause temporary stability issues or timeouts on the next command
		var result *Result
		var verifyErr error

		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(1 * time.Second)
				c.logInfo("CopyFile: Retrying checksum verification (attempt %d/3)...", attempt+1)
			}

			// Use a fresh context for verification to avoid inheriting timeout from upload if it's tight
			verifyCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			result, verifyErr = c.Execute(verifyCtx, verifyScript)
			cancel()

			if verifyErr == nil {
				break
			}
		}

		if verifyErr != nil {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation": "CopyFile",
				"phase":     "verify_checksum",
				"error":     verifyErr.Error(),
			})
			return fmt.Errorf("failed to verify checksum: remote operation error: %v", verifyErr)
		}

		var output string
		if result != nil && len(result.Output) > 0 {
			if s, ok := result.Output[0].(string); ok {
				output = s
			} else if psObj, ok := result.Output[0].(*serialization.PSObject); ok {
				output = psObj.ToString
			} else {
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

	return nil
}

// FetchFile downloads a remote file to the local host.
// Files are transferred in chunks using Base64 encoding over PowerShell remoting.
// For large files, consider enabling compression or adjusting the chunk size.
func (c *Client) FetchFile(ctx context.Context, remotePath, localPath string, opts ...FileTransferOption) error {
	// Apply transport-aware defaults and user options
	opt := DefaultFileTransferOptionsForTransport(c.config.Transport)
	for _, fn := range opts {
		fn(&opt)
	}

	// Validate paths
	if err := validatePaths(localPath, remotePath); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Encode remote path for safe embedding in PowerShell
	remotePathB64 := base64.StdEncoding.EncodeToString([]byte(remotePath))

	// Step 1: Get remote file size
	sizeScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$pathBytes = [System.Convert]::FromBase64String('%s')
			$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
			$file = Get-Item -LiteralPath $path -ErrorAction Stop
			$file.Length
		} catch {
			Write-Error "Failed to get file info: $_"
			exit 1
		}
	`, remotePathB64)

	result, err := c.Execute(ctx, sizeScript)
	if err != nil {
		c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
			"operation": "FetchFile",
			"phase":     "get_size",
			"error":     err.Error(),
		})
		if strings.Contains(err.Error(), "Cannot find path") {
			return fmt.Errorf("remote file not found")
		}
		return fmt.Errorf("failed to get remote file size: remote operation error")
	}

	// Parse file size from output
	var totalSize int64
	if result != nil && len(result.Output) > 0 {
		switch v := result.Output[0].(type) {
		case int64:
			totalSize = v
		case int:
			totalSize = int64(v)
		case float64:
			totalSize = int64(v)
		case string:
			if _, parseErr := fmt.Sscanf(strings.TrimSpace(v), "%d", &totalSize); parseErr != nil {
				return fmt.Errorf("failed to parse file size: %w", parseErr)
			}
		default:
			return fmt.Errorf("unexpected file size type: %T", v)
		}
	}

	if totalSize == 0 {
		// Empty file - just create it locally
		file, createErr := os.Create(localPath)
		if createErr != nil {
			return fmt.Errorf("failed to create local file: %w", createErr)
		}
		file.Close()
		c.logInfo("FetchFile: Created empty file %s", localPath)
		return nil
	}

	// Security: Enforce MaxFileSize limit
	maxSize := opt.MaxFileSize
	if maxSize == 0 {
		maxSize = 1024 * 1024 * 1024 // Default 1GB
	}
	if opt.MaxFileSize > 0 {
		maxSize = opt.MaxFileSize
	} else if opt.MaxFileSize < 0 {
		maxSize = 0 // Disabled
	}

	if maxSize > 0 && totalSize > maxSize {
		return fmt.Errorf("remote file too large: %d bytes (max allowed: %d)", totalSize, maxSize)
	}

	// Calculate number of chunks
	chunkSize := int64(opt.ChunkSize)
	numChunks := (totalSize + chunkSize - 1) / chunkSize

	// Security Event: Log transfer start
	c.logSecurityEvent("FILE_TRANSFER_START", map[string]interface{}{
		"operation":   "FetchFile",
		"source":      remotePath,
		"destination": localPath,
		"size_bytes":  totalSize,
		"chunk_count": numChunks,
	})

	// Create local file
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Initialize progress tracking
	var progress *transferProgress
	if opt.ProgressCallback != nil {
		progress = &transferProgress{
			totalBytes:       totalSize,
			progressCallback: opt.ProgressCallback,
		}
	}

	// Initialize Hasher if verification is enabled
	var hasher hash.Hash
	if opt.VerifyChecksum {
		hasher = sha256.New()
	}

	c.logInfo("FetchFile: Downloading %d chunks (%d bytes)", numChunks, totalSize)

	// Step 2: Download chunks sequentially
	for i := int64(0); i < numChunks; i++ {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("transfer cancelled: %w", ctx.Err())
		default:
		}

		offset := i * chunkSize
		length := chunkSize
		if offset+length > totalSize {
			length = totalSize - offset
		}

		// Read chunk from remote as Base64
		readScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			try {
				$pathBytes = [System.Convert]::FromBase64String('%s')
				$path = [System.Text.Encoding]::UTF8.GetString($pathBytes)
				$stream = [IO.File]::OpenRead($path)
				$stream.Seek(%d, [IO.SeekOrigin]::Begin) | Out-Null
				$buffer = New-Object byte[] %d
				$bytesRead = $stream.Read($buffer, 0, %d)
				$stream.Close()
				if ($bytesRead -gt 0) {
					[Convert]::ToBase64String($buffer, 0, $bytesRead)
				}
			} catch {
				Write-Error "Failed to read chunk: $_"
				exit 1
			}
		`, remotePathB64, offset, length, length)

		chunkResult, chunkErr := c.Execute(ctx, readScript)
		if chunkErr != nil {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation": "FetchFile",
				"phase":     "download_chunk",
				"chunk":     i,
				"error":     chunkErr.Error(),
			})
			return fmt.Errorf("failed to download chunk %d/%d: remote operation error", i+1, numChunks)
		}

		// Extract Base64 string from output
		var b64Data string
		if chunkResult != nil && len(chunkResult.Output) > 0 {
			if s, ok := chunkResult.Output[0].(string); ok {
				b64Data = strings.TrimSpace(s)
			} else if psObj, ok := chunkResult.Output[0].(*serialization.PSObject); ok {
				b64Data = strings.TrimSpace(psObj.ToString)
			} else {
				b64Data = strings.TrimSpace(fmt.Sprintf("%v", chunkResult.Output[0]))
			}
		}

		if b64Data == "" {
			return fmt.Errorf("chunk %d returned empty data", i)
		}

		// Decode Base64
		chunkData, decodeErr := base64.StdEncoding.DecodeString(b64Data)
		if decodeErr != nil {
			return fmt.Errorf("failed to decode chunk %d: %w", i, decodeErr)
		}

		// Write to local file
		if _, writeErr := file.Write(chunkData); writeErr != nil {
			return fmt.Errorf("failed to write chunk %d: %w", i, writeErr)
		}

		// Update hash if verification is enabled
		if hasher != nil {
			hasher.Write(chunkData)
		}

		// Update progress
		if progress != nil {
			progress.update(int64(len(chunkData)))
		}

		// Log progress every 10 chunks
		if (i+1)%10 == 0 || i == numChunks-1 {
			c.logInfo("FetchFile: Downloaded chunk %d/%d", i+1, numChunks)
		}
	}

	// Step 3: Verify Checksum (if enabled)
	if opt.VerifyChecksum {
		c.logInfo("FetchFile: Verifying checksum...")
		localHash := hex.EncodeToString(hasher.Sum(nil))

		// Get remote hash
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
		`, remotePathB64)

		verifyResult, verifyErr := c.Execute(ctx, verifyScript)
		if verifyErr != nil {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation": "FetchFile",
				"phase":     "verify_checksum",
				"error":     verifyErr.Error(),
			})
			return fmt.Errorf("failed to verify checksum: remote operation error")
		}

		var remoteHash string
		if verifyResult != nil && len(verifyResult.Output) > 0 {
			if s, ok := verifyResult.Output[0].(string); ok {
				remoteHash = strings.TrimSpace(s)
			} else if psObj, ok := verifyResult.Output[0].(*serialization.PSObject); ok {
				remoteHash = strings.TrimSpace(psObj.ToString)
			} else {
				remoteHash = strings.TrimSpace(fmt.Sprintf("%v", verifyResult.Output[0]))
			}
		}

		if !strings.EqualFold(remoteHash, localHash) {
			c.logSecurityEvent("FILE_TRANSFER_FAILED", map[string]interface{}{
				"operation":   "FetchFile",
				"phase":       "checksum_mismatch",
				"local_hash":  localHash,
				"remote_hash": remoteHash,
			})
			return fmt.Errorf("checksum mismatch! local: %s, remote: %s", localHash, remoteHash)
		}

		c.logInfo("FetchFile: Checksum verified (SHA256: %s)", localHash)
	}

	// Security Event: Log completion
	c.logSecurityEvent("FILE_TRANSFER_COMPLETE", map[string]interface{}{
		"operation":      "FetchFile",
		"destination":    localPath,
		"bytes_received": totalSize,
		"status":         "success",
		"verified":       opt.VerifyChecksum,
	})

	c.logInfo("FetchFile: Transfer complete (%d bytes)", totalSize)
	return nil
}
