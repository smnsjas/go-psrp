# GitHub Configuration

This directory contains GitHub-specific configuration files for the go-psrp repository.

## Files

### `.github/dependabot.yml`
Configures Dependabot for automated dependency updates:
- **Go modules**: Weekly scans on Mondays at 09:00 UTC
- **GitHub Actions**: Monthly scans
- Automatically creates PRs for dependency updates
- Groups minor/patch updates to reduce noise

### `.github/workflows/`
Contains GitHub Actions workflow definitions:

#### `ci.yml` - Continuous Integration
- Runs on: push, pull request
- **Lint**: golangci-lint with gosec enabled
- **Test**: Cross-platform tests (Linux, Windows, macOS)
- **Coverage**: Uploads coverage reports to Codecov

#### `security.yml` - Security Scanning
- Runs on: push, pull request, weekly schedule (Mondays 09:00 UTC)
- **gosec**: Static security analysis with SARIF output
- **govulncheck**: Vulnerability database checks
- **nancy**: Dependency vulnerability scanning

#### `dependency-review.yml` - Dependency Review
- Runs on: pull requests
- Reviews dependency changes in PRs
- Fails on moderate+ severity vulnerabilities
- Checks license compatibility
- Posts summary comments on PRs

## Security Features

All workflows implement security best practices:
- ✅ Minimal permissions (read-only by default)
- ✅ Pinned action versions
- ✅ Separate security-events write permission only where needed
- ✅ SARIF upload for GitHub Security dashboard integration

## Workflow Status

You can view the status of all workflows in the repository's Actions tab:
`https://github.com/smnsjas/go-psrp/actions`

## Badges

Add these badges to your README to show workflow status:

```markdown
[![CI](https://github.com/smnsjas/go-psrp/actions/workflows/ci.yml/badge.svg)](https://github.com/smnsjas/go-psrp/actions/workflows/ci.yml)
[![Security](https://github.com/smnsjas/go-psrp/actions/workflows/security.yml/badge.svg)](https://github.com/smnsjas/go-psrp/actions/workflows/security.yml)
```

## Maintenance

### Updating Dependencies
Dependabot will automatically create PRs when updates are available. Review and merge them promptly.

### Security Alerts
GitHub will create Dependabot security alerts when vulnerabilities are detected. These appear in:
- Security tab → Dependabot alerts
- Email notifications (if enabled)

### Workflow Failures
If a workflow fails:
1. Check the workflow run logs in the Actions tab
2. Review the specific job that failed
3. Fix the issue and push a new commit (or re-run if transient)

## Resources

- [Dependabot documentation](https://docs.github.com/en/code-security/dependabot)
- [GitHub Actions documentation](https://docs.github.com/en/actions)
- [Security best practices](https://docs.github.com/en/code-security/getting-started/github-security-features)
