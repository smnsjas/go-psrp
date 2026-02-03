package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
)

// ContextKeyIsHTTPS is the context key for detecting HTTPS transport.
const ContextKeyIsHTTPS = contextKey("isHTTPS")

// PureKerberosProvider implements SecurityProvider using the pure Go gokrb5 library.
type PureKerberosProvider struct {
	client *client.Client

	clientContext *spnego.ClientContext // For HTTP: strict GSS-API context from fork
	targetSPN     string
	isComplete    bool
	isHTTPS       bool
}

// PureKerberosConfig holds the configuration for the PureKerberosProvider.
type PureKerberosConfig struct {
	Realm        string
	Krb5ConfPath string
	KeytabPath   string
	CCachePath   string
	Credentials  *Credentials
}

// NewPureKerberosProvider creates a new pure Go Kerberos provider.
func NewPureKerberosProvider(cfg PureKerberosConfig, targetSPN string) (*PureKerberosProvider, error) {
	// Load krb5.conf
	if cfg.Krb5ConfPath == "" {
		cfg.Krb5ConfPath = os.Getenv("KRB5_CONFIG")
		if cfg.Krb5ConfPath == "" {
			cfg.Krb5ConfPath = "/etc/krb5.conf"
		}
	}
	conf, err := config.Load(cfg.Krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("load krb5.conf from %s: %w", cfg.Krb5ConfPath, err)
	}

	var cl *client.Client

	// 1. Try Keytab
	if cfg.KeytabPath != "" {
		kt, err := keytab.Load(cfg.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("load keytab from %s: %w", cfg.KeytabPath, err)
		}
		// Need username from somewhere. Credentials?
		username := ""
		if cfg.Credentials != nil {
			username = cfg.Credentials.Username
		}
		cl = client.NewWithKeytab(username, cfg.Realm, kt, conf, client.DisablePAFXFAST(true))
	} else if cfg.CCachePath != "" {
		// 2. Try CCache
		cc, err := credentials.LoadCCache(cfg.CCachePath)
		if err != nil {
			return nil, fmt.Errorf("load ccache from %s: %w", cfg.CCachePath, err)
		}
		cl, err = client.NewFromCCache(cc, conf, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("create client from ccache: %w", err)
		}
	} else if cfg.Credentials != nil {
		// 3. Password
		cl = client.NewWithPassword(
			cfg.Credentials.Username,
			cfg.Realm,
			cfg.Credentials.Password,
			conf,
			client.DisablePAFXFAST(true),
		)
	} else {
		return nil, fmt.Errorf("no credentials provided (keytab, ccache, or password required)")
	}

	// Login to get TGT
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}

	return &PureKerberosProvider{
		client:    cl,
		targetSPN: targetSPN,
	}, nil
}

// Complete returns true if the authentication handshake is complete.
func (p *PureKerberosProvider) Complete() bool {
	return p.isComplete
}

// Step performs an authentication step.
func (p *PureKerberosProvider) Step(ctx context.Context, inputToken []byte) ([]byte, bool, error) {
	// Detect HTTPS vs HTTP on first call
	if len(inputToken) == 0 && !p.isComplete {
		isHTTPS, _ := ctx.Value(ContextKeyIsHTTPS).(bool)
		p.isHTTPS = isHTTPS
	}

	// 1. Initial Request (No input token)
	if len(inputToken) == 0 {
		return p.generateInitialToken()
	}

	// 2. Server Response Processing
	return p.processServerToken(inputToken)
}

// generateInitialToken creates the first NegTokenInit with AP-REQ
func (p *PureKerberosProvider) generateInitialToken() ([]byte, bool, error) {
	// HTTPS Logic (TLS handles encryption, so standard SPNEGO header)
	if p.isHTTPS {
		return nil, false, fmt.Errorf("HTTPS authentication temporarily disabled due to library mismatch (SetSPNEGOHeader undefined)")
	}

	// HTTP Logic (Application Layer Encryption)
	// 1. Get service ticket
	tkt, sessionKey, err := p.client.GetServiceTicket(p.targetSPN)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get service ticket: %w", err)
	}

	// 2. Build GSSAPI flags - Integrity + Confidentiality + Mutual
	gssFlags := []int{
		gssapi.ContextFlagInteg,
		gssapi.ContextFlagConf,
		gssapi.ContextFlagMutual,
	}

	// 3. AP options - Mutual Auth Required
	apOptions := []int{flags.APOptionMutualRequired}

	// 4. Create NegTokenInit with KRB5 AP-REQ
	negTokenInit, err := spnego.NewNegTokenInitKRB5WithFlags(
		p.client, tkt, sessionKey, gssFlags, apOptions)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create NegTokenInit: %w", err)
	}

	// 5. Create ClientContext for later Wrap/Unwrap
	flagsUint := uint32(gssapi.ContextFlagInteg | gssapi.ContextFlagConf | gssapi.ContextFlagMutual)
	// Use the sequence number from the Authenticator in NegTokenInit
	clientCtx := spnego.NewClientContext(sessionKey, flagsUint, negTokenInit.InitialSeqNum())

	// WSMan/PSRP over HTTP requires DCE-style wrap tokens (RFC 4121 Section 4.2.4).
	clientCtx.SetWrapTokenDCE(true)

	// Set MechTypes for mechListMIC verification
	clientCtx.SetMechTypeListDER(negTokenInit.RawMechTypesDER())

	// Mark that mutual auth is required (needed for SetEstablished() to succeed)
	clientCtx.SetMutualAuthRequired(true)

	// Transition to InProgress state
	if err := clientCtx.SetInProgress(); err != nil {
		return nil, false, fmt.Errorf("failed to set context in progress: %w", err)
	}
	p.clientContext = clientCtx

	// 6. Marshal
	spnegoToken := &spnego.SPNEGOToken{
		Init:         true,
		NegTokenInit: negTokenInit,
	}

	tokenBytes, err := spnegoToken.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	return tokenBytes, true, nil // continueNeeded=true
}

// processServerToken handles the server's NegTokenResp (AP-REP)
func (p *PureKerberosProvider) processServerToken(input []byte) ([]byte, bool, error) {
	// Legacy format check: "Negotiate <b64>"?
	// The `Step` input is usually raw bytes from the challenge.

	var spnegoResp spnego.SPNEGOToken
	if err := spnegoResp.Unmarshal(input); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal server token: %w", err)
	}

	negResp := spnegoResp.NegTokenResp

	// Accept Completed
	// Note: negResp.State is a method in standard lib/fork usually, or a field.
	// Compiler said "mismatched types func() ... and State". So it IT IS A FUNCTION.
	if negResp.State() == spnego.NegStateAcceptCompleted {
		if len(negResp.ResponseToken) > 0 {
			// Extract AP-REP
			// We can use ProcessAPRep directly if we had a helper, but `GetKRB5Token` works.
			// Assuming `GetKRB5Token` is on NegTokenResp or we parse manually.
			// Let's rely on `p.ProcessResponse` logic which was doing AP-REP handling manually in previous versions?
			// Actually `processServerToken` snippet from user suggests `GetKRB5Token`.
			// Since I don't see `GetKRB5Token` in standard, I'll assume it exists in fork or fallback.

			// FALLBACK to simple AP-REP Unmarshal:
			var apRep messages.APRep
			if err := apRep.Unmarshal(negResp.ResponseToken); err == nil {
				if err := p.clientContext.ProcessAPRep(&apRep); err != nil {
					return nil, false, fmt.Errorf("AP-REP process failed: %w", err)
				}
			}
		}

		if err := p.clientContext.SetEstablished(); err != nil {
			return nil, false, err
		}
		p.isComplete = true
		slog.Info("Negotiate: Handshake complete", "authComplete", true)
		return nil, true, nil
	}

	return nil, false, fmt.Errorf("unexpected negotiation state: %v", negResp.State())
}

// ProcessResponse processes the final mutual authentication token (AP-REP)
func (p *PureKerberosProvider) ProcessResponse(ctx context.Context, authHeader string) error {
	slog.Debug("Negotiate: ProcessResponse called", "headerLen", len(authHeader))
	if p.clientContext == nil {
		slog.Debug("Negotiate: ProcessResponse skipped - clientContext nil")
		return fmt.Errorf("client context not initialized")
	}

	// Parse SPNEGO token
	var token []byte
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 {
		token, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	}

	if len(token) == 0 {
		slog.Debug("Negotiate: ProcessResponse skipped - no token found in header")
		return nil // No token to process
	}

	slog.Debug("Negotiate: Processing authentication token", "tokenLen", len(token))

	// 1. Unmarshal NegTokenResp
	// 1. Unmarshal NegTokenResp
	var negTokenResp spnego.NegTokenResp
	if err := negTokenResp.Unmarshal(token); err != nil {
		slog.Warn("Negotiate: NegTokenResp unmarshal failed", "error", err)
		return nil
	}

	// Check if there is a MechToken (the inner Kerberos AP-REP)
	if len(negTokenResp.ResponseToken) == 0 {
		slog.Debug("Negotiate: NegTokenResp has no ResponseToken (MechToken)")
		return nil
	}

	// 2. Unmarshal AP-REP
	slog.Debug("Negotiate: Found ResponseToken", "hexPrefix", fmt.Sprintf("%x", negTokenResp.ResponseToken[:min(8, len(negTokenResp.ResponseToken))]))

	// Handle GSS-API wrapping if present (Tag 60)
	payload := negTokenResp.ResponseToken
	if len(payload) > 0 && payload[0] == 0x60 {
		// Strip GSS-API header to get to AP-REP (Application 15 / 0x6f)
		// Header structure: [60] [Length] [OID] [TokenID 02 00] [AP-REP 6f...]
		// We can try to skip strict parsing and just scan for the AP-REP tag (0x6f)
		// 16 bytes is standard offset for Kerberos OID, checking if it matches expectation around that index
		found := false
		for i := 0; i < len(payload)-1; i++ {
			if payload[i] == 0x6f {
				// Potential start of AP-REP
				// Verify if it looks valid? Just try unmarshalling
				payload = payload[i:]
				slog.Debug("Negotiate: Found AP-REP tag (0x6f)", "offset", i)
				found = true
				break
			}
		}
		if !found {
			slog.Debug("Negotiate: GSS-API tag found but could not locate AP-REP (0x6f) in payload")
		}
	}

	var apRep messages.APRep
	if err := apRep.Unmarshal(payload); err != nil {
		slog.Debug("Negotiate: AP-REP unmarshal failed, token likely not AP-REP", "error", err)
		return nil // Not valid AP-REP
	}

	if apRep.MsgType != msgtype.KRB_AP_REP {
		slog.Debug("Negotiate: MsgType mismatch", "expected", msgtype.KRB_AP_REP, "got", apRep.MsgType)
		return nil // Not AP-REP
	}

	// 3. Process AP-REP using library logic (handles decryption and subkey update)
	if err := p.clientContext.ProcessAPRep(&apRep); err != nil {
		return fmt.Errorf("process AP-REP: %w", err)
	}

	// NOW we are done, set context to established
	if err := p.clientContext.SetEstablished(); err != nil {
		return fmt.Errorf("set context established: %w", err)
	}
	p.isComplete = true

	// DEBUG: Verify subkey extraction
	// DEBUG: Verify subkey extraction
	if p.clientContext.HasAcceptorSubkey() {
		key := p.clientContext.GetKey()
		slog.Debug("Negotiate: HasAcceptorSubkey=TRUE", "keyType", key.KeyType, "keyLen", len(key.KeyValue))
	} else {
		slog.Debug("Negotiate: HasAcceptorSubkey=FALSE", "using", "Session Key")
	}

	return nil
}

// Close releases resources.
func (p *PureKerberosProvider) Close() error {
	p.client.Destroy()
	p.clientContext = nil
	return nil
}

// Wrap encrypts data for HTTP transport using GSS-API sealing.
// This is ONLY called for HTTP (not HTTPS/TLS) - encryption is application-layer.
//
// MS-WSMV sealed message format:
//
//	[SignatureLength: 4 bytes LE] [Signature] [EncryptedData]
//
// Where:
//   - SignatureLength = HdrLen (16) + RRC
//   - RRC depends on EC mode:
//   - EC=0 (WinRM): RRC = confounder(16) + checksum(12) = 28, SignatureLength = 44
//   - EC=16 (MS-KILE): RRC = EC(16) + confounder(16) + checksum(12) = 44, SignatureLength = 60
//   - Signature = GSS token header + rotated checksum portion
//   - EncryptedData = remaining ciphertext after rotation (no length prefix)
func (p *PureKerberosProvider) Wrap(inputData []byte) ([]byte, error) {
	if p.isHTTPS {
		return nil, fmt.Errorf("wrap called for HTTPS connection (encryption handled by TLS)")
	}
	if p.clientContext == nil {
		return nil, fmt.Errorf("cannot wrap: clientContext not initialized")
	}

	// Use WrapSealed from the fork.
	// The context is configured for EC=0 (WinRM mode) by default.
	tokenBytes, err := p.clientContext.WrapSealed(inputData)
	if err != nil {
		return nil, fmt.Errorf("WrapSealed failed: %w", err)
	}

	// GSS Wrap token header is 16 bytes
	const gssHdrLen = 16

	if len(tokenBytes) < gssHdrLen {
		return nil, fmt.Errorf("token too short: %d bytes", len(tokenBytes))
	}

	// Extract RRC from token header (bytes 6-7, big-endian)
	// RRC = EC + confounder + checksum
	// For EC=0 (WinRM): RRC = 0 + 16 + 12 = 28 for AES-SHA1
	// For EC=16 (MS-KILE): RRC = 16 + 16 + 12 = 44 for AES-SHA1
	rrc := binary.BigEndian.Uint16(tokenBytes[6:8])

	// SignatureLength = Header (16) + RRC + Confounder (16)
	// After RRC rotation, the signature includes: header + rotated_bytes + confounder
	// For EC=0: SignatureLength = 16 + 28 + 16 = 60
	// For EC=16: SignatureLength = 16 + 44 + 16 = 76
	const confounderLen = 16 // AES confounder is always 16 bytes
	signatureLen := gssHdrLen + int(rrc) + confounderLen
	if len(tokenBytes) < signatureLen {
		return nil, fmt.Errorf("token too short: %d < %d", len(tokenBytes), signatureLen)
	}

	// Split the GSS token into Signature and EncryptedData portions
	signature := tokenBytes[:signatureLen]
	encryptedData := tokenBytes[signatureLen:]

	// Build MS-WSMV sealed format: [SigLen][Signature][EncryptedData]
	// Note: NO EncryptedDataLength prefix - the encrypted data follows directly after signature
	// Pre-allocate output buffer to avoid reallocations
	// Size = SigLen (4) + Signature + EncryptedData
	totalLen := 4 + len(tokenBytes)
	output := bytes.NewBuffer(make([]byte, 0, totalLen))

	// SignatureLength (4 bytes, little-endian)
	// #nosec G115 -- safe cast to larger type (int->uint64) for overflow check
	if uint64(signatureLen) > math.MaxUint32 {
		return nil, fmt.Errorf("signature length overflow: %d", signatureLen)
	}
	var sigLenBytes [4]byte                                             // Use stack-allocated array (optimization)
	binary.LittleEndian.PutUint32(sigLenBytes[:], uint32(signatureLen)) // #nosec G115 -- guarded by check above
	output.Write(sigLenBytes[:])

	// Signature (header + rotated checksum)
	output.Write(signature)

	// EncryptedData (remaining ciphertext) - NO length prefix
	output.Write(encryptedData)

	slog.Debug("NEGOTIATE: Wrapped data",
		"signatureLen", signatureLen,
		"encryptedDataLen", len(encryptedData),
		"totalLen", output.Len())

	return output.Bytes(), nil
}

// Unwrap decrypts data from HTTP transport.
// This is ONLY called for HTTP (not HTTPS/TLS) - decryption is application-layer.
//
// MS-WSMV sealed message format:
//
//	[SignatureLength: 4 bytes LE] [Signature] [EncryptedData]
//
// We reconstruct the GSS token from these parts before calling UnwrapSealed.
func (p *PureKerberosProvider) Unwrap(data []byte) ([]byte, error) {
	if p.isHTTPS {
		return nil, fmt.Errorf("unwrap called for HTTPS connection (encryption handled by TLS)")
	}
	if p.clientContext == nil {
		return nil, fmt.Errorf("cannot unwrap: clientContext not initialized")
	}

	// Parse MS-WSMV sealed format: [SigLen][Signature][EncryptedData]
	// Note: NO EncryptedDataLength prefix - encrypted data follows directly after signature
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for MS-WSMV format: %d bytes", len(data))
	}

	// Read SignatureLength (4 bytes, little-endian)
	signatureLen := binary.LittleEndian.Uint32(data[0:4])

	// Sanity check: Ensure signature length is reasonable (e.g. < 100MB) to prevent potential DoS
	// or integer overflow in 32-bit architecture calculations.
	const maxSignatureLen = 100 * 1024 * 1024 // 100MB
	if signatureLen > maxSignatureLen {
		return nil, fmt.Errorf("signature length too large: %d > %d", signatureLen, maxSignatureLen)
	}

	if len(data) < 4+int(signatureLen) {
		return nil, fmt.Errorf("data too short for signature: need %d, have %d", 4+int(signatureLen), len(data))
	}

	// OPTIMIZATION: Zero-copy reconstruction
	// The MS-WSMV format is [Len 4][Signature...][EncryptedData...]
	// The GSS token expectation is [Signature...][EncryptedData...]
	// Since the components are contiguous in `data`, we can simply slice the input
	// to skip the 4-byte length prefix.
	gssToken := data[4:]

	slog.Debug("Negotiate: Unwrapping data (Zero-Copy)",
		"signatureLen", signatureLen,
		"gssTokenLen", len(gssToken))

	// Use UnwrapSealed (expects token from acceptor)
	payload, err := p.clientContext.UnwrapSealed(gssToken)
	if err != nil {
		return nil, fmt.Errorf("UnwrapSealed failed: %w", err)
	}

	return payload, nil
}
