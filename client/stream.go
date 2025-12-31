package client

import (
	"context"
	"encoding/base64"
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
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, errors.New("client not connected")
	}
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client is closed")
	}
	psrpPool := c.psrpPool
	backend := c.backend
	semaphore := c.semaphore
	c.mu.Unlock()

	// Acquire semaphore
	select {
	case semaphore <- struct{}{}:
		// Acquired
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Create pipeline
	psrpPipeline, err := psrpPool.CreatePipeline(script)
	if err != nil {
		<-semaphore // Release on error
		return nil, fmt.Errorf("create pipeline: %w", err)
	}

	// Prepare payload (same as Execute)
	c.mu.Lock()
	c.messageID++
	msgID := c.messageID
	c.mu.Unlock()

	createPipelineData, err := psrpPipeline.GetCreatePipelineDataWithID(msgID)
	if err != nil {
		<-semaphore
		return nil, fmt.Errorf("get create pipeline data: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(createPipelineData)

	// Prepare pipeline via backend
	cleanupBackend, err := backend.PreparePipeline(ctx, psrpPipeline, payload)
	if err != nil {
		<-semaphore
		return nil, fmt.Errorf("prepare pipeline: %w", err)
	}

	// Invoke pipeline
	if err := psrpPipeline.Invoke(ctx); err != nil {
		cleanupBackend()
		<-semaphore
		return nil, fmt.Errorf("invoke pipeline: %w", err)
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
			cleanupBackend()
			<-semaphore // Release semaphore
		},
	}

	return sr, nil
}
