package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/smnsjas/go-psrp/wsman"
)

// EventSubscription manages an active event subscription.
type EventSubscription struct {
	// Events receives the raw XML event items.
	Events <-chan []byte
	// Errors receives any errors encountered during polling.
	Errors <-chan error

	logger      *slog.Logger
	client      *wsman.Client
	sub         *wsman.Subscription
	resourceURI string
	events      chan []byte
	errors      chan error
	cancel      context.CancelFunc
	ctx         context.Context
}

// SubscribeOptions contains options for the Subscribe operation.
type SubscribeOptions struct {
	ResourceURI string        // Defaults to "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*"
	Expires     time.Duration // Defaults to 10 minutes
}

// Subscribe subscribes to specific events using a WQL query.
// It returns an EventSubscription which provides channels for events and errors.
// The subscription will automatically poll for events until Close() is called or the context is cancelled.
func (c *Client) Subscribe(ctx context.Context, query string, opts ...SubscribeOptions) (*EventSubscription, error) {
	// Default options
	opt := SubscribeOptions{
		ResourceURI: "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*",
		Expires:     10 * time.Minute,
	}
	if len(opts) > 0 {
		if opts[0].ResourceURI != "" {
			opt.ResourceURI = opts[0].ResourceURI
		}
		if opts[0].Expires > 0 {
			opt.Expires = opts[0].Expires
		}
	}

	// Validate inputs
	if len(query) > 16384 {
		return nil, fmt.Errorf("query too long (max 16KB)")
	}
	if len(opt.ResourceURI) > 2048 {
		return nil, fmt.Errorf("resource URI too long (max 2KB)")
	}

	// 1. Perform WS-Eventing Subscribe
	// Check if wsman is initialized (it should be if Connect/New was called)
	if c.wsman == nil {
		return nil, fmt.Errorf("wsman client not initialized")
	}

	sub, err := c.wsman.Subscribe(ctx, opt.ResourceURI, query)
	if err != nil {
		return nil, fmt.Errorf("subscribe failed: %w", err)
	}

	// 2. Setup subscription object
	ctx, cancel := context.WithCancel(context.Background()) // internal context for polling loop
	es := &EventSubscription{
		logger:      c.slogLogger, // Inherit logger from client
		client:      c.wsman,
		sub:         sub,
		resourceURI: opt.ResourceURI,
		events:      make(chan []byte, 100), // Buffer events
		errors:      make(chan error, 10),
		cancel:      cancel,
		ctx:         ctx,
	}

	c.logInfo("Subscribed to events: query='%s', sub_id='%s'", query, sub.SubscriptionID)

	// Expose read-only channels
	es.Events = es.events
	es.Errors = es.errors

	// 3. Start polling loop
	go es.pollLoop()

	return es, nil
}

// pollLoop handles the periodic Pull operations.
func (es *EventSubscription) pollLoop() {
	defer close(es.events)
	defer close(es.errors)

	ticker := time.NewTicker(2 * time.Second) // Poll every 2s
	defer ticker.Stop()

	enumContext := es.sub.EnumerationContext

	for {
		select {
		case <-es.ctx.Done():
			return
		case <-ticker.C:
			// Perform Pull
			// We use a longer timeout than the server-side limits (MaxTime PT5S / OperationTimeout PT20S)
			pullCtx, cancel := context.WithTimeout(es.ctx, 45*time.Second)
			resp, err := es.client.Pull(pullCtx, es.resourceURI, enumContext, 100)
			cancel()

			if err != nil {
				// Send error but don't stop unless it's fatal
				errMsg := err.Error()

				// Log warning
				if es.logger != nil {
					es.logger.Warn("Event poll failed", "error", err)
				}

				select {
				case es.errors <- fmt.Errorf("pull error: %w", err):
				default:
					// Drop error if channel full to avoid blocking or allocation
				}

				// If the context is invalid, we can't continue polling this subscription
				if strings.Contains(errMsg, "InvalidEnumerationContext") {
					if es.logger != nil {
						es.logger.Error("Subscription ended: Invalid Enumeration Context")
					}
					return
				}
				continue
			}

			// Update context for next pull
			if resp.EnumerationContext != "" {
				enumContext = resp.EnumerationContext
			}

			// Emit events
			if len(resp.Items.Raw) > 0 {
				// The Raw items might contain multiple XML elements if they are not wrapped?
				// Actually, Items.Raw is just the inner XML. It might be a blob of <Item>...</Item> or similar.
				// For now, emit the whole blob. Refining parsing is Phase 3.
				select {
				case es.events <- resp.Items.Raw:
				default:
					select {
					case es.errors <- fmt.Errorf("event buffer full, dropping events"):
					default:
					}
				}
			}

			// Check EndOfSequence
			if resp.EndOfSequence != nil {
				// Subscription ended server-side
				return
			}
		}
	}
}

// Close unsubscribes and stops the polling loop.
func (es *EventSubscription) Close() error {
	es.cancel() // Stop polling loop

	if es.logger != nil {
		es.logger.Info("Closing event subscription")
	}

	// Perform best-effort Unsubscribe
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return es.client.Unsubscribe(ctx, es.sub)
}
