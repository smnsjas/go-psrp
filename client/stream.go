package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/smnsjas/go-psrpcore/messages"
	"github.com/smnsjas/go-psrpcore/pipeline"
)

// StreamResult represents the streaming result of a PowerShell command execution.
// Use Wait() to block until completion or consume channels directly.
type StreamResult struct {
	pipeline *pipeline.Pipeline
	ctx      context.Context
	cleanup  func()

	// Output streams - consume these channels to get output as it arrives
	Output      <-chan *messages.Message
	Errors      <-chan *messages.Message
	Warnings    <-chan *messages.Message
	Verbose     <-chan *messages.Message
	Debug       <-chan *messages.Message
	Progress    <-chan *messages.Message
	Information <-chan *messages.Message
}

// Wait blocks until the pipeline completes and returns the final error (if any).
// After Wait returns, all channels are closed.
func (sr *StreamResult) Wait() error {
	err := sr.pipeline.Wait()
	sr.cleanup()
	return err
}

// Cancel cancels the pipeline execution.
func (sr *StreamResult) Cancel() {
	sr.pipeline.Cancel()
}

// ExecuteStream runs a PowerShell script asynchronously and returns a StreamResult
// that provides access to output as it is produced.
// The caller is responsible for consuming the output channels and calling Wait().
func (c *Client) ExecuteStream(ctx context.Context, script string) (*StreamResult, error) {
	// Acquire semaphore first
	c.mu.Lock()
	if c.semaphore == nil {
		c.mu.Unlock()
		return nil, errors.New("semaphore not initialized")
	}
	sem := c.semaphore
	c.mu.Unlock() // Unlock before acquire to avoid holding lock while waiting

	if err := sem.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("pool busy: %w", err)
	}

	psrpPipeline, pipelineTransport, cleanupBackend, err := c.startPipeline(ctx, script)
	if err != nil {
		sem.Release()
		return nil, err
	}

	// Start per-pipeline receive loop (for WSMan) or global dispatch loop (for HvSocket)
	if pipelineTransport != nil {
		go c.runPipelineReceive(ctx, pipelineTransport, psrpPipeline)
	} else {
		// Ensure dispatch loop is running (idempotent)
		c.mu.Lock()
		pool := c.psrpPool
		c.mu.Unlock()
		if pool != nil {
			pool.StartDispatchLoop()
		}
	}

	// Close input for script execution
	_ = psrpPipeline.CloseInput(ctx)

	sr := &StreamResult{
		pipeline:    psrpPipeline,
		ctx:         ctx,
		Output:      psrpPipeline.Output(),
		Errors:      psrpPipeline.Error(),
		Warnings:    psrpPipeline.Warning(),
		Verbose:     psrpPipeline.Verbose(),
		Debug:       psrpPipeline.Debug(),
		Progress:    psrpPipeline.Progress(),
		Information: psrpPipeline.Information(),
		cleanup: func() {
			if cleanupBackend != nil {
				cleanupBackend()
			}
			sem.Release() // Release semaphore
		},
	}

	return sr, nil
}
