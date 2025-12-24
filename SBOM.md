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
| `github.com/jcmturner/gokrb5/v8` | v8.x | Apache-2.0 | Kerberos auth | ✅ Active |

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
