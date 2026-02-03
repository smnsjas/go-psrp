//go:build windows

package powershell

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/outofproc"
)

type hvOutOfProcAdapter struct {
	transport    *outofproc.Transport
	runspaceGUID uuid.UUID

	readMu   sync.Mutex
	notifyCh chan struct{}

	pending [][]byte
	closed  bool
	readErr error

	ctx    context.Context
	cancel context.CancelFunc

	readLoopDone chan struct{}

	handlerMu    sync.RWMutex
	onCommandAck func(pipelineGUID uuid.UUID)
	onCloseAck   func(psGuid uuid.UUID)
	onSignalAck  func(psGuid uuid.UUID)

	readTimeout time.Duration
}

func newHvOutOfProcAdapter(transport *outofproc.Transport, runspaceGUID uuid.UUID, readTimeout time.Duration) *hvOutOfProcAdapter {
	adapterCtx, cancel := context.WithCancel(context.Background())
	a := &hvOutOfProcAdapter{
		transport:    transport,
		runspaceGUID: runspaceGUID,
		pending:      make([][]byte, 0, 16),
		notifyCh:     make(chan struct{}, 1),
		ctx:          adapterCtx,
		cancel:       cancel,
		readLoopDone: make(chan struct{}),
		readTimeout:  readTimeout,
	}

	go a.readLoop()
	return a
}

func (a *hvOutOfProcAdapter) readLoop() {
	defer func() {
		close(a.readLoopDone)
		a.readMu.Lock()
		a.closed = true
		a.readMu.Unlock()
		select {
		case a.notifyCh <- struct{}{}:
		default:
		}
	}()

	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		packet, err := a.transport.ReceivePacket()
		if err != nil {
			a.readMu.Lock()
			a.readErr = err
			a.readMu.Unlock()
			select {
			case a.notifyCh <- struct{}{}:
			default:
			}
			return
		}

		switch packet.Type {
		case outofproc.PacketTypeData:
			if err := a.transport.SendDataAck(packet.PSGuid); err != nil {
				_ = err
			}
			a.readMu.Lock()
			a.pending = append(a.pending, packet.Data)
			a.readMu.Unlock()
			select {
			case a.notifyCh <- struct{}{}:
			default:
			}
		case outofproc.PacketTypeCommandAck:
			a.handlerMu.RLock()
			handler := a.onCommandAck
			a.handlerMu.RUnlock()
			if handler != nil {
				handler(packet.PSGuid)
			}
		case outofproc.PacketTypeCloseAck:
			a.handlerMu.RLock()
			handler := a.onCloseAck
			a.handlerMu.RUnlock()
			if handler != nil {
				handler(packet.PSGuid)
			}
		case outofproc.PacketTypeSignalAck:
			a.handlerMu.RLock()
			handler := a.onSignalAck
			a.handlerMu.RUnlock()
			if handler != nil {
				handler(packet.PSGuid)
			}
		case outofproc.PacketTypeClose:
			if err := a.transport.SendCloseAck(packet.PSGuid); err != nil {
				_ = err
			}
		case outofproc.PacketTypeSignal:
			if err := a.transport.SendSignalAck(packet.PSGuid); err != nil {
				_ = err
			}
		}
	}
}

func (a *hvOutOfProcAdapter) Read(p []byte) (n int, err error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()

	var deadline time.Time
	if a.readTimeout > 0 {
		deadline = time.Now().Add(a.readTimeout)
	}

	for len(a.pending) == 0 && !a.closed && a.readErr == nil {
		a.readMu.Unlock()

		timer := time.NewTimer(1 * time.Second)
		select {
		case <-a.notifyCh:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-a.ctx.Done():
			timer.Stop()
			a.readMu.Lock()
			return 0, a.ctx.Err()
		}

		a.readMu.Lock()

		if !deadline.IsZero() && time.Now().After(deadline) {
			if len(a.pending) > 0 || a.closed || a.readErr != nil {
				break
			}
			return 0, fmt.Errorf("read timeout: no data received in %s", a.readTimeout)
		}
	}

	if len(a.pending) > 0 {
		n = copy(p, a.pending[0])
		if n == len(a.pending[0]) {
			a.pending = a.pending[1:]
		} else {
			a.pending[0] = a.pending[0][n:]
		}
		return n, nil
	}

	if a.readErr != nil {
		return 0, a.readErr
	}
	if a.closed {
		return 0, io.EOF
	}
	return 0, nil
}

func (a *hvOutOfProcAdapter) Write(p []byte) (int, error) {
	err := a.transport.SendData(outofproc.NullGUID, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *hvOutOfProcAdapter) SendCommand(pipelineGUID uuid.UUID) error {
	return a.transport.SendCommand(pipelineGUID)
}

func (a *hvOutOfProcAdapter) SendPipelineData(pipelineGUID uuid.UUID, data []byte) error {
	time.Sleep(2 * time.Millisecond)
	return a.transport.SendData(pipelineGUID, data)
}

func (a *hvOutOfProcAdapter) SendSignal(pipelineGUID uuid.UUID) error {
	return a.transport.SendSignal(pipelineGUID)
}

func (a *hvOutOfProcAdapter) Close() error {
	a.cancel()
	select {
	case <-a.readLoopDone:
	case <-time.After(300 * time.Millisecond):
	}
	return nil
}

