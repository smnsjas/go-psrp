---
description: Build psrp-client binaries for macOS and Windows
---

# Build Binaries Workflow

// turbo-all

## 1. Build macOS binary (Apple Silicon)

```bash
cd /Users/jasonsimons/Projects/go-psrp
GOOS=darwin GOARCH=arm64 go build -o ./cmd/psrp-client/psrp-client ./cmd/psrp-client
```

## 2. Build Windows binary (AMD64)

```bash
cd /Users/jasonsimons/Projects/go-psrp
GOOS=windows GOARCH=amd64 go build -o ./cmd/psrp-client/psrp-client.exe ./cmd/psrp-client
```

## Output

- macOS: `./cmd/psrp-client/psrp-client`
- Windows: `./cmd/psrp-client/psrp-client.exe`
