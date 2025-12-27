package wsman

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/wsman/transport"
)

// Client is a WSMan client for communicating with WinRM endpoints.
type Client struct {
	endpoint  string
	transport *transport.HTTPTransport
	sessionID string
}

// NewClient creates a new WSMan client.
func NewClient(endpoint string, tr *transport.HTTPTransport) *Client {
	return &Client{
		endpoint:  endpoint,
		transport: tr,
		sessionID: "uuid:" + strings.ToUpper(uuid.New().String()),
	}
}

// SetSessionID sets the WS-Management SessionId for the client.
func (c *Client) SetSessionID(sessionID string) {
	c.sessionID = sessionID
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
// For PowerShell remoting, creationXml should contain base64-encoded PSRP fragments
// (SessionCapability + InitRunspacePool messages).
func (c *Client) Create(ctx context.Context, options map[string]string, creationXML string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCreate).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	// Add shell options
	for name, value := range options {
		if name == "protocolversion" {
			env.WithOptionMustComply(name, value)
		} else {
			env.WithOption(name, value)
		}
	}

	// Build shell body with optional creationXml for PSRP
	// Generate client-side ShellId like pypsrp does
	shellID := strings.ToUpper(uuid.New().String())
	var shellBody string
	if creationXML != "" {
		// PowerShell remoting requires creationXML with PSRP fragments
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
  <creationXml xmlns="http://schemas.microsoft.com/powershell">` + creationXML + `</creationXml>
</rsp:Shell>`
	} else {
		// Basic WinRS shell
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
</rsp:Shell>`
	}
	env.WithBody([]byte(shellBody))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return "", fmt.Errorf("create shell: %w", err)
	}

	// We already have the ShellId from our request
	return shellID, nil
}

// Command creates a new command (Pipeline) in the shell and returns the command ID.
// If commandID is provided (non-empty), it will be used as the CommandId in the request.
// Otherwise, the server will generate a CommandId.
func (c *Client) Command(ctx context.Context, shellID, commandID, arguments string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCommand).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithOption("WINRS_SKIP_CMD_SHELL", "FALSE").
		WithOption("WINRS_CONSOLEMODE_STDIN", "TRUE").
		WithMaxEnvelopeSize(153600).
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	// Build CommandLine with optional CommandId attribute
	var commandLine []byte
	if commandID != "" {
		commandLine = []byte(`<rsp:CommandLine CommandId="` + commandID + `" xmlns:rsp="` + NsShell + `">
  <rsp:Command></rsp:Command>
`)
	} else {
		commandLine = []byte(`<rsp:CommandLine xmlns:rsp="` + NsShell + `">
  <rsp:Command></rsp:Command>
`)
	}

	if arguments != "" {
		commandLine = append(commandLine, []byte(`  <rsp:Arguments>`+arguments+`</rsp:Arguments>
`)...)
	}

	commandLine = append(commandLine, []byte(`</rsp:CommandLine>
`)...)

	env.WithBody(commandLine)

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
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
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
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT20S").
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithOption("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "True").
		WithSelector("ShellId", shellID).
		WithShellNamespace()

	// Match pypsrp format: CommandId IS required on DesiredStream IF it's a command receive
	var streamNode string
	if commandID != "" {
		streamNode = `<rsp:DesiredStream CommandId="` + commandID + `">stdout</rsp:DesiredStream>`
	} else {
		streamNode = `<rsp:DesiredStream>stdout</rsp:DesiredStream>`
	}

	body := []byte(`<rsp:Receive xmlns:rsp="` + NsShell + `">
  ` + streamNode + `
</rsp:Receive>`)

	// Debug: print request body
	fmt.Printf("DEBUG: Receive Request: %s\n", string(body))

	respBody, err := c.sendEnvelope(ctx, env.WithBody(body))
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
	// Debug: print what we received
	fmt.Printf("DEBUG: Receive Response: State=%s ExitCode=%v StreamCount=%d\n",
		resp.Body.ReceiveResponse.CommandState.State,
		resp.Body.ReceiveResponse.CommandState.ExitCode,
		len(resp.Body.ReceiveResponse.Streams))
	if len(resp.Body.ReceiveResponse.Streams) > 0 {
		fmt.Printf("DEBUG: Stream 0 Name=%s ContentLen=%d\n",
			resp.Body.ReceiveResponse.Streams[0].Name,
			len(resp.Body.ReceiveResponse.Streams[0].Content))
	}

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
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
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

	// Debug: print the outgoing SOAP envelope
	fmt.Printf("\n=== OUTGOING SOAP ENVELOPE ===\n%s\n=== END SOAP ENVELOPE ===\n\n", string(body))

	return c.transport.Post(ctx, c.endpoint, body)
}

// CloseIdleConnections closes any idle connections in the underlying transport.
// This forces a fresh NTLM handshake for subsequent requests.
func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

// Response types for XML parsing.

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
