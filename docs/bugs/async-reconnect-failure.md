# Bug: Async Disconnect/Reconnect Fails

## Summary

The async execution feature allows disconnecting from a running command and reconnecting later to retrieve output. The disconnect works, but reconnecting fails with a WSMan error.

## Steps to Reproduce

```bash
# Step 1: Start async command
./psrp-client -server <host> -tls -insecure -ntlm -async -script "Start-Sleep 60; 'Done'"

# Step 2: Note the ShellID and CommandID from output

# Step 3: Reconnect
./psrp-client -server <host> -tls -insecure -ntlm \
  -reconnect <ShellID> -recover <CommandID>
```

## Error

```text
Error reconnecting: backend reattach: wsman connect: connect: transport: HTTP 500:
<f:ProviderFault provider="microsoft.powershell" path="C:\WINDOWS\system32\pwrshplugin.dll">
The server that is running Windows PowerShell cannot process the connect operation 
because the following information is not found or not valid: 
Client Capability information and Connect RunspacePool information.
</f:ProviderFault>
```

## Analysis

The error indicates the `connectXml` payload (containing SESSION_CAPABILITY + CONNECT_RUNSPACEPOOL) is rejected by the server. Possible causes:

1. Missing or malformed PSRP fragments in `GetConnectHandshakeFragments()`
2. PoolID mismatch between disconnect and reconnect
3. Session metadata not properly preserved

## Files to Investigate

- `go-psrpcore/runspace/runspace.go` - `GetConnectHandshakeFragments()`
- `go-psrp/powershell/runspace.go` - `WSManBackend.Reattach()`
- `go-psrp/wsman/client.go` - `Connect()` method

## Priority

Medium - Core functionality works, this is an advanced feature.
