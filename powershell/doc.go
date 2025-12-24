// Package powershell provides the bridge between WSMan transport and go-psrpcore.
//
// This package implements:
//   - RunspacePool management over WSMan
//   - PowerShell pipeline execution
//   - Output stream handling (stdout, stderr, progress, etc.)
//   - io.ReadWriter adapter for WSMan Send/Receive
package powershell
