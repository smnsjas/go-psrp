# Software Bill of Materials (SBOM)

This document tracks all dependencies used in go-psrp with their licenses, versions, and maintenance status.

## SBOM Generation

We use CycloneDX format for machine-readable SBOMs:

```bash
# Install generator
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# Generate SBOM
cyclonedx-gomod mod -output sbom.json -json
```

The generated `sbom.json` should be included with each release.

---

## Direct Dependencies

| Package | Version | License | Maintainer | Status |
|---------|---------|---------|------------|--------|
| `github.com/smnsjas/go-psrpcore` | latest | MIT | Project | ✅ Active |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | Google | ✅ Official |
| `github.com/Azure/go-ntlmssp` | v0.0.0-20221128193559 | MIT | Azure (Microsoft) | ✅ Active (Nov 2025) |

---

## Dependency Verification Criteria

1. **Official/Corporate backing preferred** (Google, Microsoft/Azure, etc.)
2. **Active maintenance** (commits within last 12 months)
3. **Permissive license** (MIT, BSD, Apache-2.0)
4. **Security track record** (no unpatched CVEs)

---

## Future Dependencies (Planned)

| Package | Version | License | Purpose | Status |
|---------|---------|---------|---------|--------|
| Kerberos TBD | - | - | Kerberos auth | ⚠️ Evaluating options |

### Kerberos Library Evaluation (Dec 2024)

| Library | Status | Notes |
|---------|--------|-------|
| `jcmturner/gokrb5/v8` | ⚠️ Unmaintained | 0 commits in 90 days, last release Feb 2023 |
| `golang-auth/go-gssapi` | ⚠️ Beta | v3 API unstable, not production ready |
| `dpotapov/go-spnego` | ⚠️ Unmaintained | Last commit Apr 2022, wraps gokrb5 |
| `alexbrainman/sspi` | ✅ Windows-only | Uses native Windows SSPI for Negotiate |

**Recommendation**: Defer Kerberos implementation until ecosystem matures. For Windows-only deployments, `alexbrainman/sspi` is the most viable option as it uses native OS APIs.

---

## TLS Security Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| MinVersion | TLS 1.2 | Compatibility with older Windows servers |
| MaxVersion | Not set | Allows TLS 1.3 (Go default) |
| CipherSuites | Not set | Go manages secure defaults for TLS 1.2/1.3 |

**TLS 1.3 Notes**:

- All TLS 1.3 cipher suites are secure; Go manages them automatically
- Go prioritizes AES-GCM on hardware-accelerated CPUs, ChaCha20-Poly1305 otherwise
- Forward secrecy is guaranteed in TLS 1.3

---

## Vulnerability Scanning

Run with each release:

```bash
govulncheck ./...
```

---

## Version Update Policy

- Check for updates monthly: `go list -m -u all`
- Run `go mod tidy` after updates
- Regenerate SBOM after dependency changes
- Run `govulncheck` after updates
