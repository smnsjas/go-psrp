package wsman

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/wsman/transport"
)

// Client is a WSMan client for communicating with WinRM endpoints.
type Client struct {
	endpoint  string
	transport *transport.HTTPTransport
}

// NewClient creates a new WSMan client.
func NewClient(endpoint string, tr *transport.HTTPTransport) *Client {
	return &Client{
		endpoint:  endpoint,
		transport: tr,
	}
}

// ReceiveResult contains the result of a Receive operation.
type ReceiveResult struct {
	Stdout       []byte
	Stderr       []byte
	CommandState string
	ExitCode     int
	Done         bool
}

// Create creates a new shell (RunspacePool) and returns the shell ID.
func (c *Client) Create(ctx context.Context, options map[string]string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCreate).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:" + uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithShellNamespace()

	// Add shell options
	for name, value := range options {
		env.WithOption(name, value)
	}

	// Add shell body
	env.WithBody([]byte(`<rsp:Shell xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
</rsp:Shell>`))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return "", fmt.Errorf("create shell: %w", err)
	}

	// Parse response to extract ShellId
	var resp createResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse create response: %w", err)
	}

	return resp.Body.Shell.ShellID, nil
}

// Command creates a new command (Pipeline) in the shell and returns the command ID.
func (c *Client) Command(ctx context.Context, shellID, arguments string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCommand).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	// Add command body
	env.WithBody([]byte(`<rsp:CommandLine xmlns:rsp="` + NsShell + `">
  <rsp:Command></rsp:Command>
  <rsp:Arguments>` + arguments + `</rsp:Arguments>
</rsp:CommandLine>`))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return "", fmt.Errorf("create command: %w", err)
	}

	var resp commandResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse command response: %w", err)
	}

	return resp.Body.CommandResponse.CommandID, nil
}

// Send sends data to a command's input stream.
func (c *Client) Send(ctx context.Context, shellID, commandID, stream string, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)

	env := NewEnvelope().
		WithAction(ActionSend).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	env.WithBody([]byte(`<rsp:Send xmlns:rsp="` + NsShell + `">
  <rsp:Stream Name="` + stream + `" CommandId="` + commandID + `">` + encoded + `</rsp:Stream>
</rsp:Send>`))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	return nil
}

// Receive retrieves output from a command's output streams.
func (c *Client) Receive(ctx context.Context, shellID, commandID string) (*ReceiveResult, error) {
	env := NewEnvelope().
		WithAction(ActionReceive).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	env.WithBody([]byte(`<rsp:Receive xmlns:rsp="` + NsShell + `" SequenceId="0">
  <rsp:DesiredStream CommandId="` + commandID + `">stdout stderr</rsp:DesiredStream>
</rsp:Receive>`))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("receive: %w", err)
	}

	var resp receiveResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parse receive response: %w", err)
	}

	result := &ReceiveResult{}

	// Decode streams
	for _, stream := range resp.Body.ReceiveResponse.Streams {
		decoded, err := base64.StdEncoding.DecodeString(stream.Content)
		if err != nil {
			continue // Skip invalid base64
		}

		switch stream.Name {
		case "stdout":
			result.Stdout = append(result.Stdout, decoded...)
		case "stderr":
			result.Stderr = append(result.Stderr, decoded...)
		}
	}

	// Check command state
	result.CommandState = resp.Body.ReceiveResponse.CommandState.State
	if resp.Body.ReceiveResponse.CommandState.ExitCode != nil {
		result.ExitCode = *resp.Body.ReceiveResponse.CommandState.ExitCode
		result.Done = true
	}

	return result, nil
}

// Signal sends a signal to a command.
func (c *Client) Signal(ctx context.Context, shellID, commandID, code string) error {
	env := NewEnvelope().
		WithAction(ActionSignal).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	env.WithBody([]byte(`<rsp:Signal xmlns:rsp="` + NsShell + `" CommandId="` + commandID + `">
  <rsp:Code>` + code + `</rsp:Code>
</rsp:Signal>`))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("signal: %w", err)
	}

	return nil
}

// Delete deletes a shell.
func (c *Client) Delete(ctx context.Context, shellID string) error {
	env := NewEnvelope().
		WithAction(ActionDelete).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+uuid.New().String()).
		WithReplyTo(AddressAnonymous).
		WithSelector("ShellId", shellID)

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("delete shell: %w", err)
	}

	return nil
}

// sendEnvelope marshals and sends a SOAP envelope, returning the response body.
func (c *Client) sendEnvelope(ctx context.Context, env *Envelope) ([]byte, error) {
	body, err := env.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	return c.transport.Post(ctx, c.endpoint, body)
}

// Response types for XML parsing.

type createResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Shell struct {
			ShellID string `xml:"ShellId"`
		} `xml:"Shell"`
	} `xml:"Body"`
}

type commandResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		CommandResponse struct {
			CommandID string `xml:"CommandId"`
		} `xml:"CommandResponse"`
	} `xml:"Body"`
}

type receiveResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ReceiveResponse struct {
			Streams []struct {
				Name      string `xml:"Name,attr"`
				CommandID string `xml:"CommandId,attr"`
				Content   string `xml:",chardata"`
			} `xml:"Stream"`
			CommandState struct {
				CommandID string `xml:"CommandId,attr"`
				State     string `xml:"State,attr"`
				ExitCode  *int   `xml:"ExitCode"`
			} `xml:"CommandState"`
		} `xml:"ReceiveResponse"`
	} `xml:"Body"`
}
