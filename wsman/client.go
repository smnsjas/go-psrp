package wsman

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
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
// Create creates a new shell (RunspacePool) and returns the EndpointReference.
// For PowerShell remoting, creationXml should contain base64-encoded PSRP fragments
// (SessionCapability + InitRunspacePool messages).
// Create creates a new shell (RunspacePool) and returns the EndpointReference.
// For PowerShell remoting, creationXml should contain base64-encoded PSRP fragments
// (SessionCapability + InitRunspacePool messages).
func (c *Client) Create(ctx context.Context, options map[string]string, creationXML string) (*EndpointReference, error) {
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
	// Generate client-side ShellId as base suggestion
	shellID := strings.ToUpper(uuid.New().String())
	var shellBody string
	if creationXML != "" {
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
  <rsp:IdleTimeOut>PT30M</rsp:IdleTimeOut>
  <creationXml xmlns="http://schemas.microsoft.com/powershell">` + creationXML + `</creationXml>
</rsp:Shell>`
	} else {
		// Basic WinRS shell
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
  <rsp:IdleTimeOut>PT30M</rsp:IdleTimeOut>
</rsp:Shell>`
	}
	env.WithBody([]byte(shellBody))

	// Debug logging
	// fmt.Fprintf(os.Stderr, "DEBUG: Sending Create Request for suggested ShellID: %s\n", shellID)

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("create shell: %w", err)
	}

	// Parse CreateResponse to get the authoritative Endpoint Reference
	var resp createResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parse create response: %w", err)
	}

	epr := &EndpointReference{
		Address:     resp.Body.ResourceCreated.Address,
		ResourceURI: resp.Body.ResourceCreated.ReferenceParameters.ResourceURI,
		Selectors:   resp.Body.ResourceCreated.ReferenceParameters.SelectorSet.Selectors,
	}

	// If ResourceURI is empty in response, use the default
	if epr.ResourceURI == "" {
		epr.ResourceURI = ResourceURIPowerShell
	}
	// If Address is empty, use current endpoint (sanity check)
	// (Address in response is often just the path or full URL)

	return epr, nil
}

// Command creates a new command (Pipeline) in the shell and returns the command ID.
func (c *Client) Command(ctx context.Context, epr *EndpointReference, commandID, arguments string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCommand).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithShellNamespace()

	// Add all selectors
	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

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
func (c *Client) Send(ctx context.Context, epr *EndpointReference, commandID, stream string, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)

	env := NewEnvelope().
		WithAction(ActionSend).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	var streamNode string
	if commandID != "" {
		streamNode = `<rsp:Stream Name="` + stream + `" CommandId="` + commandID + `">` + encoded + `</rsp:Stream>`
	} else {
		streamNode = `<rsp:Stream Name="` + stream + `">` + encoded + `</rsp:Stream>`
	}

	env.WithBody([]byte(`<rsp:Send xmlns:rsp="` + NsShell + `">
  ` + streamNode + `
</rsp:Send>`))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	return nil
}

// Receive retrieves output from a command's output streams.
func (c *Client) Receive(ctx context.Context, epr *EndpointReference, commandID string) (*ReceiveResult, error) {
	env := NewEnvelope().
		WithAction(ActionReceive).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT20S").
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithOption("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "True").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

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

	respBody, err := c.sendEnvelope(ctx, env.WithBody(body))
	if err != nil {
		// If the operation timed out, it just means no data was available.
		// We should return an empty result so the caller can poll again.
		if strings.Contains(err.Error(), "w:TimedOut") || strings.Contains(err.Error(), "OperationTimeout") {
			return &ReceiveResult{}, nil
		}
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
func (c *Client) Signal(ctx context.Context, epr *EndpointReference, commandID, code string) error {
	env := NewEnvelope().
		WithAction(ActionSignal).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

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
func (c *Client) Delete(ctx context.Context, epr *EndpointReference) error {
	env := NewEnvelope().
		WithAction(ActionDelete).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + uuid.New().String()).
		WithReplyTo(AddressAnonymous)

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

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

	respBody, err := c.transport.Post(ctx, c.endpoint, body)
	if err != nil {
		return nil, err
	}

	// Check for SOAP Fault even in successful HTTP responses
	if err := CheckFault(respBody); err != nil {
		return nil, fmt.Errorf("wsman: %w", err)
	}

	return respBody, nil
}

// CloseIdleConnections closes any idle connections in the underlying transport.
// This forces a fresh NTLM handshake for subsequent requests.
func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

// Response types for XML parsing.

type createResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ResourceCreated struct {
			Address             string `xml:"Address"`
			ReferenceParameters struct {
				ResourceURI string `xml:"ResourceURI"`
				SelectorSet struct {
					Selectors []Selector `xml:"Selector"`
				} `xml:"SelectorSet"`
			} `xml:"ReferenceParameters"`
		} `xml:"ResourceCreated"`
	} `xml:"Body"`
}

type commandResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		CommandResponse struct {
			CommandID string `xml:"CommandId"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell CommandResponse"`
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

type connectResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ConnectResponse struct {
			ConnectResponseXml string `xml:"connectResponseXml"`
		} `xml:"ConnectResponse"`
	} `xml:"Body"`
}

// Disconnect disconnects the shell on the server without closing it.
// The shell remains active and can be reconnected to later.
func (c *Client) Disconnect(ctx context.Context, epr *EndpointReference) error {
	env := NewEnvelope().
		WithAction(ActionDisconnect).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	// Payload is empty for Disconnect
	// But we need a Body with Disconnect element
	// <w:Disconnect />
	body := struct {
		XMLName xml.Name `xml:"rsp:Disconnect"`
		Rsp     string   `xml:"xmlns:rsp,attr"`
	}{
		Rsp: NsShell,
	}
	bodyBytes, err := xml.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal disconnect body: %w", err)
	}
	env.WithBody(bodyBytes)

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("disconnect: %w", err)
	}

	// Response should be just Empty or DisconnectResponse
	fmt.Fprintf(os.Stderr, "DEBUG: Disconnect Response: %s\n", string(respBody))

	if len(respBody) == 0 {
		return nil
	}
	// We could parse it, but we mainly care strictly about error (fault).
	return nil
}

// Reconnect reconnects to a disconnected shell.
func (c *Client) Reconnect(ctx context.Context, shellID string) error {
	// Reconnect is special: We only have the ShellID from the user.
	// We must assume standard ResourceURI and just ShellID selector.
	// NOTE: This assumes Reconnect doesn't require extra selectors the server generated during Create.
	// If it DOES, then the user must provide ALL selectors, which is hard.
	// For now, valid assumption is ShellID is unique enough for Reconnect.

	env := NewEnvelope().
		WithAction(ActionReconnect).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace().
		WithSelector("ShellId", shellID)

	// <w:Reconnect />
	body := struct {
		XMLName xml.Name `xml:"rsp:Reconnect"`
		Rsp     string   `xml:"xmlns:rsp,attr"`
	}{
		Rsp: NsShell,
	}
	bodyBytes, err := xml.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal reconnect body: %w", err)
	}
	env.WithBody(bodyBytes)

	_, err = c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("reconnect: %w", err)
	}

	return nil
}

// Connect connects to an existing disconnected shell using WSManConnectShellEx semantics.
// This is for NEW clients connecting to a session disconnected by a different client.
// The connectXML should contain base64-encoded PSRP handshake data
// (SessionCapability + ConnectRunspacePool messages).
// Returns the base64-decoded response data from the server.
func (c *Client) Connect(ctx context.Context, shellID string, connectXML string) ([]byte, error) {
	env := NewEnvelope().
		WithAction(ActionConnect).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace().
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithSelector("ShellId", shellID)

	// Build body with connectXml containing PSRP handshake data
	// Format matches pypsrp exactly: <rsp:Connect><connectXml xmlns="...">base64data</connectXml></rsp:Connect>
	body := `<rsp:Connect xmlns:rsp="` + NsShell + `">
  <connectXml xmlns="http://schemas.microsoft.com/powershell">` + connectXML + `</connectXml>
</rsp:Connect>`
	env.WithBody([]byte(body))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Parse response to extract connectResponseXml
	var resp connectResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		// Return raw response if parsing fails
		return respBody, nil
	}

	// Decode base64 response data
	if resp.Body.ConnectResponse.ConnectResponseXml != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.Body.ConnectResponse.ConnectResponseXml)
		if err != nil {
			return nil, fmt.Errorf("decode connect response: %w", err)
		}
		return decoded, nil
	}

	return respBody, nil
}

// Enumerate lists available shells on the server.
func (c *Client) Enumerate(ctx context.Context) ([]string, error) {
	env := NewEnvelope().
		WithAction(ActionEnumerate).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID)

	// Body: <wsen:Enumerate />
	body := struct {
		XMLName xml.Name `xml:"wsen:Enumerate"`
		Wsen    string   `xml:"xmlns:wsen,attr"`
	}{
		Wsen: NsEnumeration,
	}
	bodyBytes, err := xml.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal enumerate body: %w", err)
	}
	env.WithBody(bodyBytes)

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	// Parse full response to find Item/ShellId
	// This requires more complex XML parsing as EnumerateResponse contains Items.
	// For now, we will return raw XML string in a slice as a placeholder if parsing is too heavy to add right now.
	// TODO: Add proper EnumerateResponse struct.
	// Returning the raw bytes as string for now to unblock.
	return []string{string(respBody)}, nil
}
