// Package wsman provides namespace constants for WS-Management protocol.
//
// These constants define the XML namespaces used in SOAP envelopes for
// WS-Management (WSMan) and Windows Remote Shell (WinRS) operations.
package wsman

// XML Namespace URIs for WS-Management protocol.
const (
	// NsSoap is the SOAP 1.2 envelope namespace.
	NsSoap = "http://www.w3.org/2003/05/soap-envelope"

	// NsAddressing is the WS-Addressing namespace.
	NsAddressing = "http://schemas.xmlsoap.org/ws/2004/08/addressing"

	// NsWsman is the DMTF WS-Management namespace.
	NsWsman = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"

	// NsWsmanMicrosoft is the Microsoft WS-Management namespace extension.
	NsWsmanMicrosoft = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"

	// NsShell is the Windows Remote Shell namespace.
	NsShell = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"

	// NsTransfer is the WS-Transfer namespace.
	NsTransfer = "http://schemas.xmlsoap.org/ws/2004/09/transfer"

	// NsEnumeration is the WS-Enumeration namespace.
	NsEnumeration = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

	// NsXsi is the XML Schema Instance namespace.
	NsXsi = "http://www.w3.org/2001/XMLSchema-instance"
)

// WS-Addressing constants.
const (
	// AddressAnonymous is the WS-Addressing anonymous reply address.
	AddressAnonymous = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
)

// WSMan Action URIs for WS-Transfer operations.
const (
	// ActionCreate creates a new resource (used for RunspacePool shell creation).
	ActionCreate = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"

	// ActionCreateResponse is the response to Create.
	ActionCreateResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"

	// ActionDelete removes a resource (used for shell deletion).
	ActionDelete = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"

	// ActionDeleteResponse is the response to Delete.
	ActionDeleteResponse = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"
)

// WSMan Action URIs for Windows Remote Shell operations.
const (
	// ActionCommand creates a command/pipeline within a shell.
	ActionCommand = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"

	// ActionCommandResponse is the response to Command.
	ActionCommandResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse"

	// ActionSend sends input data to a command (PSRP fragments via stdin).
	ActionSend = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"

	// ActionSendResponse is the response to Send.
	ActionSendResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse"

	// ActionReceive retrieves output from a command (PSRP fragments via stdout).
	ActionReceive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"

	// ActionReceiveResponse is the response to Receive.
	ActionReceiveResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"

	// ActionSignal sends a control signal (terminate, disconnect).
	ActionSignal = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"

	// ActionSignalResponse is the response to Signal.
	ActionSignalResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse"
)

// Signal codes for the Signal action.
const (
	// SignalTerminate terminates a command.
	SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
)

// Resource URIs for PowerShell remoting.
const (
	// ResourceURIPowerShell is the resource URI for PowerShell remoting sessions.
	ResourceURIPowerShell = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
)

// WSMan Action URIs for Enumeration.
const (
	// ActionEnumerate enumerates resources.
	ActionEnumerate = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"

	// ActionEnumerateResponse is the response to Enumerate.
	ActionEnumerateResponse = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
)

// WSMan Action URIs for Disconnected Sessions.
const (
	// ActionDisconnect disconnects the shell (server-side keep alive).
	ActionDisconnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect"

	// ActionDisconnectResponse is the response to Disconnect.
	ActionDisconnectResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/DisconnectResponse"

	// ActionReconnect reconnects to a disconnected shell (same client).
	ActionReconnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect"

	// ActionReconnectResponse is the response to Reconnect.
	ActionReconnectResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReconnectResponse"

	// ActionConnect connects to a disconnected shell (new client - different from Reconnect).
	// This is WSManConnectShellEx semantics which includes PSRP handshake data.
	ActionConnect = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Connect"

	// ActionConnectResponse is the response to Connect.
	ActionConnectResponse = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ConnectResponse"
)
