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

| Library | Status | Platform Support |
|---------|--------|------------------|
| `jcmturner/gokrb5/v8` | ⚠️ Unmaintained | All (pure Go) |
| `golang-auth/go-gssapi` v3 | 🔄 **Active (Beta)** | Linux, macOS (via C bindings) |
| `golang-auth/go-gssapi-c` | 🔄 **Active** | Linux (MIT/Heimdal), macOS (Apple/MIT/Heimdal) |
| `dpotapov/go-spnego` | ⚠️ Unmaintained | All (wraps gokrb5) |
| `alexbrainman/sspi` | ✅ Stable | Windows only (native SSPI) |

### Rust Alternative: sspi-rs (Devolutions)

| Feature | Details |
|---------|---------|
| **Library** | [`Devolutions/sspi-rs`](https://github.com/Devolutions/sspi-rs) |
| **Status** | ✅ **Actively maintained** (30 contributors, production use) |
| **License** | MIT or Apache-2.0 |
| **Protocols** | NTLM, Kerberos, Negotiate (SPNEGO) |
| **Platform** | ✅ **Cross-platform** (Windows, Linux, macOS) |
| **Pure Rust** | ✅ No C dependencies for core functionality |

**Production Users**: Devolutions Gateway, IronRDP, pyspnego, NetExec, Remote Desktop Manager

### Go ↔ Rust Interop Options

| Method | Pros | Cons |
|--------|------|------|
| **cgo + C ABI** | Standard approach | Requires C compiler, complicates build |
| **UniFFI** | Auto-generates bindings | Third-party Go support |
| **Purego** | No cgo, dynamic loading | Runtime overhead |
| **WebAssembly** | Portable, no cgo | WASM runtime overhead |

**Recommendation**:
For true cross-platform Kerberos, `sspi-rs` via Rust FFI is the most promising option:

- ✅ Pure Rust (no C dependencies)
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Actively maintained by Devolutions
- ⚠️ Requires Rust FFI integration (cgo or purego)

### go-gssapi Cross-Platform Details

| Platform | GSSAPI Provider | Notes |
|----------|-----------------|-------|
| **Linux** | MIT Kerberos, Heimdal | Requires `libkrb5-dev` or equivalent |
| **macOS** | Apple Kerberos (default), MIT, Heimdal | Apple Kerberos is Heimdal fork |
| **Windows** | ❌ Not supported | Windows uses SSPI, not GSSAPI |

**go-gssapi Requirements**:

- `cgo` enabled (C compiler required)
- System GSSAPI libraries installed
- `pkg-config` for library detection

**Recommendation**:

- **Linux/macOS**: `golang-auth/go-gssapi` v3 with `go-gssapi-c` provider (beta but actively developed)
- **Windows**: `alexbrainman/sspi` for native SSPI/Negotiate support
- **Cross-platform binary**: Build separately for each platform, or defer Kerberos support

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
