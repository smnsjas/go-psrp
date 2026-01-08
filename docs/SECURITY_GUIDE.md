# Security Best Practices for go-psrp

This document outlines security considerations and best practices when using the go-psrp library.

## Fixed Security Issues

### 1. Credential Logging Prevention (Fixed)

**Issue**: Prior versions logged entire PowerShell scripts which could expose credentials in logs.

**Fix**: The library now automatically sanitizes scripts before logging using `sanitizeScriptForLogging()`:

- Scripts containing sensitive patterns (password, credential, secret, apikey, etc.) are redacted
- Long scripts are truncated to 100 characters
- The full script is never logged to prevent accidental credential exposure

**Recommendation**: When debugging, avoid using sensitive data in scripts or disable detailed logging.

### 2. Script Injection Prevention (Fixed)

**Issue**: `ExecuteAsync()` for HvSocket transport was vulnerable to PowerShell injection through unescaped user input.

**Fix**: User scripts are now encoded separately using Base64 encoding before execution via `-EncodedCommand`, preventing injection attacks.

**Recommendation**: Always use the library's built-in execution methods rather than constructing PowerShell commands manually.

## Security Features

### TLS Configuration

The library enforces secure TLS settings by default:

- **Minimum TLS version**: TLS 1.2
- **Certificate validation**: Enabled by default
- **InsecureSkipVerify**: Only for testing, displays prominent warnings

```go
// Secure - certificate validation enabled
cfg := client.DefaultConfig()
cfg.UseTLS = true
cfg.Port = 5986

// Insecure - only for testing!
cfg.InsecureSkipVerify = true  // Displays warning
```

### Authentication Options

The library supports multiple authentication methods with different security characteristics:

1. **Kerberos** (Recommended for domain environments)
   - Uses strong cryptography
   - Supports Single Sign-On (SSO)
   - No password in memory/logs

2. **NTLM with Channel Binding Tokens (CBT)**
   - Protects against relay attacks
   - Enable with `cfg.EnableCBT = true` (requires HTTPS)

3. **Basic Authentication** (Only over HTTPS)
   - Simple but requires HTTPS
   - Displays warning if used over HTTP

```go
// Recommended: Kerberos with SSO
cfg.AuthType = client.AuthKerberos
cfg.CCachePath = "/tmp/krb5cc_1000"

// Good: NTLM with CBT over HTTPS
cfg.AuthType = client.AuthNTLM
cfg.EnableCBT = true
cfg.UseTLS = true

// Avoid: Basic auth over HTTP
// (Automatically warns if not using TLS)
```

### Session State Protection

Session state files are created with restricted permissions (0600) to prevent unauthorized access:

```go
// State file created with mode 0600 (owner read/write only)
err := client.SaveState("/path/to/state.json")
```

## Best Practices

### 1. Always Use TLS in Production

```go
cfg := client.DefaultConfig()
cfg.UseTLS = true
cfg.Port = 5986
cfg.InsecureSkipVerify = false  // Default, ensure cert validation
```

### 2. Enable Extended Protection When Using NTLM

```go
cfg.AuthType = client.AuthNTLM
cfg.EnableCBT = true  // Requires HTTPS
cfg.UseTLS = true
```

### 3. Avoid Hardcoding Credentials

Use environment variables or secure credential stores:

```go
// Good: Use environment variables
cfg.Username = os.Getenv("PSRP_USERNAME")
cfg.Password = os.Getenv("PSRP_PASSWORD")

// Better: Use Kerberos with credential cache
cfg.AuthType = client.AuthKerberos
cfg.CCachePath = os.Getenv("KRB5CCNAME")
```

### 4. Sanitize User Input

When constructing PowerShell scripts from user input, validate and sanitize:

```go
// Avoid: Direct string interpolation
script := fmt.Sprintf("Get-User -Name %s", userInput)  // Dangerous!

// Better: Use parameters or validation
if !isValidUsername(userInput) {
    return errors.New("invalid username")
}
// Then use Execute() which handles encoding safely
```

### 5. Control Logging Verbosity

In production, avoid verbose logging that might expose sensitive data:

```go
// Development
os.Setenv("PSRP_LOG_LEVEL", "debug")

// Production - minimal logging
os.Setenv("PSRP_LOG_LEVEL", "warn")
```

### 6. Secure Session Files

Protect session state files with appropriate permissions:

```bash
# Unix/Linux - state files automatically created with 0600
chmod 600 /path/to/session-state.json

# Avoid storing in world-readable locations
# Good: /home/user/.psrp/
# Bad:  /tmp/ (unless you control permissions)
```

### 7. Handle Errors Securely

Don't expose sensitive information in error messages:

```go
result, err := client.Execute(ctx, script)
if err != nil {
    // Good: Generic error message
    log.Error("Command execution failed")
    
    // Avoid: Exposing script content or credentials
    // log.Errorf("Failed to run: %s", script)  // Bad!
}
```

## Security Checklist

- [ ] TLS enabled (`cfg.UseTLS = true`)
- [ ] Certificate validation enabled (`cfg.InsecureSkipVerify = false`)
- [ ] Using strongest available authentication (Kerberos > NTLM+CBT > NTLM > Basic)
- [ ] CBT enabled for NTLM (`cfg.EnableCBT = true`)
- [ ] Credentials not hardcoded in source code
- [ ] Logging level appropriate for environment
- [ ] Session state files protected (0600 permissions)
- [ ] User input validated before use in scripts
- [ ] Error messages don't leak sensitive data

## Reporting Security Issues

If you discover a security vulnerability, please report it to the maintainers privately before public disclosure. See SECURITY.md for contact information and our responsible disclosure policy.

## Security Updates

This library follows semantic versioning. Security fixes are released as patch versions and should be applied promptly:

```bash
# Check for updates
go get -u github.com/smnsjas/go-psrp

# Or pin to latest patch version
go get github.com/smnsjas/go-psrp@latest
```

## References

- [Microsoft PowerShell Remoting Protocol (MS-PSRP)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
- [WS-Management Protocol (MS-WSMV)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
