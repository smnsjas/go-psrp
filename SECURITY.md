# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of go-psrp seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to the repository maintainers:
- Primary contact: Repository owner (see GitHub profile for contact information)

You should receive a response within 48 hours. If for some reason you do not, please follow up via GitHub to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Disclosure Policy

We follow the principle of [Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD).

- You give us reasonable time to investigate and mitigate the issue before public disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will publicly disclose the vulnerability after a fix is available

## Security Update Process

When we receive a security bug report, we will:

1. Confirm the problem and determine the affected versions
2. Audit code to find any similar problems
3. Prepare fixes for all supported versions
4. Release new security fix versions as soon as possible

## Security Features

The go-psrp library implements several security features:

### Authentication & Credentials
- Multiple secure authentication methods (Kerberos, NTLM with CBT, Basic over HTTPS)
- Automatic credential sanitization in logs
- Channel Binding Tokens (CBT) support for NTLM to prevent relay attacks

### Encryption
- TLS 1.2+ enforced by default
- Certificate validation enabled by default
- Secure cipher suite selection (Go defaults)

### Input Validation
- Base64 encoding for PowerShell scripts to prevent injection attacks
- Safe XML parsing (Go's encoding/xml)
- No command injection vulnerabilities

### Logging
- Automatic redaction of sensitive data (passwords, tokens, secrets)
- Structured logging with security middleware
- Script sanitization before logging

For more details, see:
- [SECURITY_GUIDE.md](docs/SECURITY_GUIDE.md) - Best practices for using the library securely
- [SECURITY_REVIEW_2026-02-04.md](docs/SECURITY_REVIEW_2026-02-04.md) - Latest security assessment

## Automated Security

We use automated tools to help maintain security:

- **Dependabot**: Monitors dependencies for known vulnerabilities and outdated packages
- **gosec**: Static analysis tool that scans Go code for security issues
- **govulncheck**: Checks for known vulnerabilities in dependencies
- **CodeQL**: Advanced semantic code analysis for security vulnerabilities
- **golangci-lint**: Code quality and security linter (includes gosec)

These tools run automatically on:
- Every pull request
- Every commit to main/master branch
- Weekly scheduled scans

## Security Best Practices for Users

When using go-psrp in your application:

1. **Always use TLS in production** (`cfg.UseTLS = true`)
2. **Enable certificate validation** (`cfg.InsecureSkipVerify = false`)
3. **Use the strongest available authentication**:
   - Kerberos (recommended - no password in memory)
   - NTLM with CBT enabled (`cfg.EnableCBT = true`)
   - Basic auth only over HTTPS
4. **Don't hardcode credentials** - use environment variables or credential managers
5. **Control logging verbosity** - use `warn` level in production
6. **Keep dependencies updated** - run `go get -u` regularly
7. **Follow the security checklist** in [SECURITY_GUIDE.md](docs/SECURITY_GUIDE.md)

## Security Audit History

| Date | Auditor | Findings | Status |
|------|---------|----------|--------|
| 2026-02-04 | GitHub Copilot Security Agent | 0 vulnerabilities | ✅ Approved |
| 2026-01-08 | Antigravity | 2 issues (fixed) | ✅ Resolved |

See [SECURITY_AUDIT_SUMMARY.md](docs/SECURITY_AUDIT_SUMMARY.md) for detailed audit reports.

## Contact

For general questions about security, please open a public issue on GitHub.

For private security concerns, please email the maintainers directly.

## References

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Go Security Policy](https://go.dev/security)
- [Microsoft PowerShell Remoting Protocol (MS-PSRP)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
- [NIST SP 800-92 - Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
