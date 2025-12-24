// Package wsman implements a WS-Management (WSMan) client for communicating
// with WinRM endpoints.
//
// This package provides the transport layer for PowerShell Remoting Protocol (PSRP),
// handling SOAP envelope construction, WS-Addressing headers, and the core WSMan
// operations: Create, Delete, Command, Send, Receive, and Signal.
//
// # Subpackages
//
//   - auth: Authentication handlers (Basic, NTLM)
//   - transport: HTTP/TLS transport layer
//
// # WSMan Operations
//
// The following operations are supported for PSRP:
//
//   - Create: Open a RunspacePool shell
//   - Command: Create a Pipeline
//   - Send: Send PSRP fragments (stdin stream)
//   - Receive: Get PSRP fragments (stdout stream)
//   - Signal: Terminate pipeline or close shell
//   - Delete: Close RunspacePool shell
package wsman
