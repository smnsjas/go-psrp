//go:build !windows

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// SSPIRsProvider implements SecurityProvider using sspi-rs (Rust) via purego.
// This provides cross-platform Kerberos/NTLM without CGO.
type SSPIRsProvider struct {
	credHandle  secHandle
	ctxHandle   secHandle
	hasCtx      bool
	targetSPN   string
	packageName string
	complete    bool
	lib         uintptr
}

// secHandle matches SSPI SecHandle struct (2 x uintptr)
type secHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

// secWinntAuthIdentityA matches SEC_WINNT_AUTH_IDENTITY_A
type secWinntAuthIdentityA struct {
	User           *byte
	UserLength     uint32
	Domain         *byte
	DomainLength   uint32
	Password       *byte
	PasswordLength uint32
	Flags          uint32
}

// secBuffer matches SecBuffer - using uintptr for FFI compatibility
type secBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr // Must be uintptr for purego FFI
}

// secBufferDesc matches SecBufferDesc
type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *secBuffer
}

const (
	secpkgCredOutbound    = 2
	secWinntAuthIdentAnsi = 1
	secbufferToken        = 2
	secbufferVersion      = 0
	secEOK                = 0
	secIContinueNeeded    = 0x00090312
	secICompleteNeeded    = 0x00090313
	iscReqMutualAuth      = 0x00000002
	iscReqDelegate        = 0x00000001
)

// FFI function signatures - purego requires uintptr for pointers
var (
	sspiLibLoaded             bool
	acquireCredentialsHandleA func(
		pszPrincipal uintptr,
		pszPackage uintptr,
		fCredentialUse uint32,
		pvLogonId uintptr,
		pAuthData uintptr,
		pGetKeyFn uintptr,
		pvGetKeyArgument uintptr,
		phCredential uintptr,
		ptsExpiry uintptr,
	) int32

	initializeSecurityContextA func(
		phCredential uintptr,
		phContext uintptr,
		pszTargetName uintptr,
		fContextReq uint32,
		Reserved1 uint32,
		TargetDataRep uint32,
		pInput uintptr,
		Reserved2 uint32,
		phNewContext uintptr,
		pOutput uintptr,
		pfContextAttr uintptr,
		ptsExpiry uintptr,
	) int32

	freeCredentialsHandle func(phCredential uintptr) int32
	deleteSecurityContext func(phContext uintptr) int32
)

// findSSPILibrary locates the sspi-rs shared library
func findSSPILibrary() (string, error) {
	// Check environment variable first
	if path := os.Getenv("SSPI_RS_LIB"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Platform-specific library name
	var libName string
	switch runtime.GOOS {
	case "darwin":
		libName = "libsspi.dylib"
	case "linux":
		libName = "libsspi.so"
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	// Search paths
	searchPaths := []string{
		filepath.Join(".", "lib", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH), libName),
		filepath.Join(".", libName),
		filepath.Join("/usr/local/lib", libName),
		filepath.Join("/usr/lib", libName),
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			abs, _ := filepath.Abs(path)
			return abs, nil
		}
	}

	return "", fmt.Errorf("sspi-rs library not found. Set SSPI_RS_LIB environment variable or place %s in search path", libName)
}

// loadSSPILibrary loads the sspi-rs shared library
func loadSSPILibrary() (uintptr, error) {
	path, err := findSSPILibrary()
	if err != nil {
		return 0, err
	}

	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return 0, fmt.Errorf("dlopen %s: %w", path, err)
	}

	// Register functions
	purego.RegisterLibFunc(&acquireCredentialsHandleA, lib, "AcquireCredentialsHandleA")
	purego.RegisterLibFunc(&initializeSecurityContextA, lib, "InitializeSecurityContextA")
	purego.RegisterLibFunc(&freeCredentialsHandle, lib, "FreeCredentialsHandle")
	purego.RegisterLibFunc(&deleteSecurityContext, lib, "DeleteSecurityContext")

	sspiLibLoaded = true
	return lib, nil
}

// SSPIRsConfig holds configuration for the sspi-rs provider
type SSPIRsConfig struct {
	Username    string
	Password    string
	Domain      string
	PackageName string // "Negotiate", "Kerberos", or "NTLM"
}

// NewSSPIRsProvider creates a new sspi-rs based Kerberos/NTLM provider
func NewSSPIRsProvider(cfg SSPIRsConfig, targetSPN string) (*SSPIRsProvider, error) {
	lib, err := loadSSPILibrary()
	if err != nil {
		return nil, err
	}

	if cfg.PackageName == "" {
		cfg.PackageName = "Negotiate"
	}

	provider := &SSPIRsProvider{
		targetSPN:   targetSPN,
		packageName: cfg.PackageName,
		lib:         lib,
	}

	// Acquire credentials
	pkgName := append([]byte(cfg.PackageName), 0)

	var authData *secWinntAuthIdentityA
	if cfg.Username != "" {
		user := []byte(cfg.Username)
		domain := []byte(cfg.Domain)
		password := []byte(cfg.Password)

		authData = &secWinntAuthIdentityA{
			User:           &user[0],
			UserLength:     uint32(len(user)),
			Domain:         nil,
			DomainLength:   0,
			Password:       &password[0],
			PasswordLength: uint32(len(password)),
			Flags:          secWinntAuthIdentAnsi,
		}
		if len(domain) > 0 {
			authData.Domain = &domain[0]
			authData.DomainLength = uint32(len(domain))
		}
	}

	status := acquireCredentialsHandleA(
		0, // pszPrincipal (nil)
		uintptr(unsafe.Pointer(&pkgName[0])),
		secpkgCredOutbound,
		0, // pvLogonId (nil)
		uintptr(unsafe.Pointer(authData)),
		0, // pGetKeyFn (nil)
		0, // pvGetKeyArgument (nil)
		uintptr(unsafe.Pointer(&provider.credHandle)),
		0, // ptsExpiry (nil)
	)

	if status != secEOK {
		return nil, fmt.Errorf("AcquireCredentialsHandleA failed: 0x%08X", uint32(status))
	}

	return provider, nil
}

// Step performs an SSPI security context step
func (p *SSPIRsProvider) Step(ctx context.Context, inputToken []byte) ([]byte, bool, error) {
	targetName := append([]byte(p.targetSPN), 0)

	// Prepare output buffer
	outputBuf := make([]byte, 65536) // Max token size
	outSecBuffer := secBuffer{
		cbBuffer:   uint32(len(outputBuf)),
		BufferType: secbufferToken,
		pvBuffer:   uintptr(unsafe.Pointer(&outputBuf[0])),
	}
	outSecBufferDesc := secBufferDesc{
		ulVersion: secbufferVersion,
		cBuffers:  1,
		pBuffers:  &outSecBuffer,
	}

	// Prepare input buffer (if we have a token from server)
	var inSecBufferDesc *secBufferDesc
	if len(inputToken) > 0 {
		inSecBuffer := secBuffer{
			cbBuffer:   uint32(len(inputToken)),
			BufferType: secbufferToken,
			pvBuffer:   uintptr(unsafe.Pointer(&inputToken[0])),
		}
		inSecBufferDesc = &secBufferDesc{
			ulVersion: secbufferVersion,
			cBuffers:  1,
			pBuffers:  &inSecBuffer,
		}
	}

	var ctxInPtr uintptr
	if p.hasCtx {
		ctxInPtr = uintptr(unsafe.Pointer(&p.ctxHandle))
	}

	var inBufDescPtr uintptr
	if inSecBufferDesc != nil {
		inBufDescPtr = uintptr(unsafe.Pointer(inSecBufferDesc))
	}

	var contextAttr uint32

	status := initializeSecurityContextA(
		uintptr(unsafe.Pointer(&p.credHandle)),
		ctxInPtr,
		uintptr(unsafe.Pointer(&targetName[0])),
		iscReqMutualAuth,
		0, // Reserved1
		0, // TargetDataRep (SECURITY_NATIVE_DREP)
		inBufDescPtr,
		0, // Reserved2
		uintptr(unsafe.Pointer(&p.ctxHandle)),
		uintptr(unsafe.Pointer(&outSecBufferDesc)),
		uintptr(unsafe.Pointer(&contextAttr)),
		0, // ptsExpiry (nil)
	)

	p.hasCtx = true

	// Debug: Print token size info
	fmt.Printf("[DEBUG] InitializeSecurityContextA status: 0x%08X, output token size: %d bytes\n", uint32(status), outSecBuffer.cbBuffer)

	switch status {
	case secEOK:
		p.complete = true
		// Return token if generated
		if outSecBuffer.cbBuffer > 0 {
			return outputBuf[:outSecBuffer.cbBuffer], false, nil
		}
		return nil, false, nil

	case secIContinueNeeded, secICompleteNeeded:
		// Return the token, more steps needed
		return outputBuf[:outSecBuffer.cbBuffer], true, nil

	default:
		return nil, false, fmt.Errorf("InitializeSecurityContextA failed: 0x%08X", uint32(status))
	}
}

// Complete returns true if the context is established
func (p *SSPIRsProvider) Complete() bool {
	return p.complete
}

// Close releases SSPI resources
func (p *SSPIRsProvider) Close() error {
	var errs []error

	if p.hasCtx {
		if status := deleteSecurityContext(uintptr(unsafe.Pointer(&p.ctxHandle))); status != secEOK {
			errs = append(errs, fmt.Errorf("DeleteSecurityContext: 0x%08X", uint32(status)))
		}
	}

	if status := freeCredentialsHandle(uintptr(unsafe.Pointer(&p.credHandle))); status != secEOK {
		errs = append(errs, fmt.Errorf("FreeCredentialsHandle: 0x%08X", uint32(status)))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SSPIRsAvailable returns true if the sspi-rs library is available
func SSPIRsAvailable() bool {
	if sspiLibLoaded {
		return true
	}
	_, err := findSSPILibrary()
	return err == nil
}
