package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
)

// maxNegotiateRetries is the maximum number of authentication attempts.
// This prevents infinite loops from malicious servers.
const maxNegotiateRetries = 5

// NegotiateAuth implements SPNEGO authentication using a pluggable SecurityProvider.
type NegotiateAuth struct {
	provider SecurityProvider
}

// NewNegotiateAuth creates a new Negotiate authenticator.
func NewNegotiateAuth(provider SecurityProvider) *NegotiateAuth {
	return &NegotiateAuth{
		provider: provider,
	}
}

// Name returns the scheme name.
func (a *NegotiateAuth) Name() string {
	return "Negotiate"
}

// Transport wraps the base transport with Negotiate authentication logic.
func (a *NegotiateAuth) Transport(base http.RoundTripper) http.RoundTripper {
	return &negotiateRoundTripper{
		base:     base,
		provider: a.provider,
	}
}

type negotiateRoundTripper struct {
	base     http.RoundTripper
	provider SecurityProvider
	mu       sync.Mutex
}

// contextKey is a context key type.
type contextKey string

// ContextKeyChannelBindings is the context key for Channel Binding Token (CBT) data.
// ContextKeyChannelBindings is the context key for Channel Binding Token (CBT) data.
const ContextKeyChannelBindings = contextKey("ChannelBindings")

// WinRM multipart encryption constants
const (
	// winrmBoundary includes the -- prefix per pypsrp format
	winrmBoundary     = "--Encrypted Boundary"
	winrmProtocol     = "application/HTTP-SPNEGO-session-encrypted"
	winrmContentType  = "multipart/encrypted;protocol=\"" + winrmProtocol + "\";boundary=\"Encrypted Boundary\""
	winrmOriginalType = "application/soap+xml;charset=UTF-8"
)

// wrapWinRMMultipart wraps encrypted data in WinRM's multipart/encrypted MIME format.
// Returns the formatted body and Content-Type header.
//
// The encryptedPayload parameter is expected to already be in MS-WSMV format:
// <SignatureLength 4><Signature><EncryptedDataLength 4><EncryptedData>
//
// This function wraps it in the WinRM multipart MIME structure:
// --Boundary
// Content-Type: application/HTTP-SPNEGO-session-encrypted
// OriginalContent: type=...;Length=...
// <blank line>
// --Boundary
// Content-Type: application/octet-stream
// <encryptedPayload as-is - NO blank line before binary data!>
// --Boundary--
func wrapWinRMMultipart(encryptedPayload []byte, originalLen int) ([]byte, string) {
	// Optimization: Pre-allocate buffer to avoid reallocations.
	// Approximate size: headers (~200b) + payload + boundaries (~100b)
	const overhead = 300
	buf := bytes.NewBuffer(make([]byte, 0, len(encryptedPayload)+overhead))

	// Part 1: Protocol header with OriginalContent
	buf.WriteString(winrmBoundary)
	buf.WriteString("\r\n")
	buf.WriteString("Content-Type: ")
	buf.WriteString(winrmProtocol)
	buf.WriteString("\r\n")
	buf.WriteString(fmt.Sprintf("OriginalContent: type=%s;Length=%d\r\n", winrmOriginalType, originalLen))
	// NOTE: NO blank line after OriginalContent header!
	// Windows WinRM expects the next boundary marker immediately.

	// Part 2: Encrypted payload (already in MS-WSMV format from Wrap())
	buf.WriteString(winrmBoundary)
	buf.WriteString("\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n")
	// NOTE: NO blank line after Content-Type for binary octet-stream!
	// Windows WinRM expects binary data to start immediately after the header.

	// Write the pre-formatted MS-WSMV payload as-is.
	// Format: [SignatureLength 4][Signature][EncryptedDataLength 4][EncryptedData]
	buf.Write(encryptedPayload)

	// Final boundary marker
	buf.WriteString(winrmBoundary)
	buf.WriteString("--\r\n")

	return buf.Bytes(), winrmContentType
}

// unwrapWinRMMultipart extracts encrypted payload from WinRM's multipart/encrypted format.
func unwrapWinRMMultipart(body []byte) ([]byte, error) {
	// Find content after "application/octet-stream" header
	octetMarker := []byte("Content-Type: application/octet-stream")
	octetIdx := bytes.Index(body, octetMarker)
	if octetIdx == -1 {
		// Fallback: might be raw encrypted data without multipart wrapper
		return body, nil
	}

	// Find the end of the Content-Type line
	lineEnd := bytes.Index(body[octetIdx:], []byte("\r\n"))
	if lineEnd == -1 {
		return nil, fmt.Errorf("malformed multipart: no CRLF after octet-stream header")
	}
	dataStart := octetIdx + lineEnd + 2 // Move past \r\n

	// Optional blank line before binary data
	if dataStart+2 <= len(body) && bytes.HasPrefix(body[dataStart:], []byte("\r\n")) {
		dataStart += 2
	}

	// Find the final boundary marker
	endBoundary := []byte("\r\n" + winrmBoundary + "--")
	dataEnd := bytes.Index(body[dataStart:], endBoundary)
	if dataEnd == -1 {
		// Fallback if no leading CRLF before boundary
		endBoundary = []byte(winrmBoundary + "--")
		dataEnd = bytes.Index(body[dataStart:], endBoundary)
	}
	if dataEnd == -1 {
		dataEnd = len(body) - dataStart
	}

	encryptedData := body[dataStart : dataStart+dataEnd]

	return encryptedData, nil
}

func getCBTHash(state *tls.ConnectionState) []byte {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	// Use hash algorithm based on certificate signature algorithm per RFC 5929
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		h = sha256.New()
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = sha512.New()
	default:
		// Default to SHA256 for older algos (MD5, SHA1) or unknown
		h = sha256.New()
	}

	h.Write(cert.Raw)
	return h.Sum(nil)
}

func (rt *negotiateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if this is an HTTP (not HTTPS) request with an already-established auth context
	isHTTP := req.URL.Scheme == "http"
	authComplete := rt.provider.Complete()

	// Buffer the request body upfront so we can retry
	var bodyBytes []byte
	if req.Body != nil && req.ContentLength > 0 {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close() // Error intentionally ignored; body already read
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	slog.Debug("Negotiate: Request details", "scheme", req.URL.Scheme, "authComplete", rt.provider.Complete(), "hasBody", len(bodyBytes) > 0)

	// SPECIAL HANDLING FOR HTTP KERBEROS:
	// We cannot simply encrypt headers and send. We must establish the security context first.
	// If the context is NOT complete, we must trigger the auth flow with an empty body first.
	// This is because the server sends the AP-REP (needed for mutual auth & session key) in the response.
	// Only AFTER processing the AP-REP can we encrypt the real payload.
	if isHTTP && !authComplete && len(bodyBytes) > 0 {
		slog.Info("Negotiate: HTTP pre-auth with body - Initiating HANDSHAKE-FIRST flow")

		// 1. Create a "Handshake" request (shallow copy, empty body)
		handshakeReq := req.Clone(req.Context())
		handshakeReq.Body = http.NoBody
		handshakeReq.ContentLength = 0
		handshakeReq.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }

		// 2. Perform the authentication loop with this empty request
		// This handles Step -> 401 -> Authorization -> 200/400 -> ProcessResponse (AP-REP)
		handshakeResp, err := rt.roundTripInternal(handshakeReq, nil)
		if err != nil {
			return nil, fmt.Errorf("handshake failed: %w", err)
		}

		// 3. Close the handshake response body unless it's a real failure we should return
		// If status is 200/OK, we discard it and proceed to send the REAL encrypted payload
		if handshakeResp != nil {
			if handshakeResp.StatusCode >= 400 {
				slog.Error("Negotiate: Handshake returned error", "status", handshakeResp.Status)
				return handshakeResp, nil
			}
			if handshakeResp.Body != nil {
				_ = handshakeResp.Body.Close()
			}
		}
		slog.Info("Negotiate: Handshake complete", "authComplete", rt.provider.Complete())

		// 4. Now that auth is supposedly complete, encrypt and send the real body
		// We fall through to the logic below, which checks rt.provider.Complete()
	}

	// Internal helper executes the standard auth loop or encrypted send
	return rt.roundTripInternal(req, bodyBytes)
}

// roundTripInternal handles the standard auth loop logic
func (rt *negotiateRoundTripper) roundTripInternal(req *http.Request, bodyBytes []byte) (*http.Response, error) {
	// Check auth state again (it might have changed during handshake)
	isHTTP := req.URL.Scheme == "http"

	// For HTTP with established auth, encrypt the body BEFORE sending
	// This applies if:
	// 1. We are retrying after a successful handshake (above)
	// 2. We are making subsequent requests on an already established context
	if isHTTP && rt.provider.Complete() && len(bodyBytes) > 0 {
		// Encrypt
		rt.mu.Lock()
		defer rt.mu.Unlock()
		slog.Debug("Negotiate: POST-AUTH HTTP REQUEST - Encrypting body", "plainLen", len(bodyBytes))

		encrypted, err := rt.provider.Wrap(bodyBytes)
		if err != nil {
			slog.Error("Negotiate: Encryption FAILED", "error", err)
			return nil, fmt.Errorf("encrypt request body: %w", err)
		}
		slog.Debug("Negotiate: Encryption SUCCESS", "encryptedLen", len(encrypted))

		// Wrap in WinRM multipart/encrypted format
		multipartBody, contentType := wrapWinRMMultipart(encrypted, len(bodyBytes))

		// Update request with multipart body and Content-Type
		req.Body = io.NopCloser(bytes.NewReader(multipartBody))
		req.ContentLength = int64(len(multipartBody))
		req.Header.Set("Content-Type", contentType)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(multipartBody)), nil
		}

		slog.Debug("Negotiate: Sending encrypted multipart request", "multipartLen", len(multipartBody))

		// Send the encrypted request directly (skip auth loop)
		resp, err := rt.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// Check for error response
		if resp.StatusCode >= 400 {
			if resp.StatusCode == 500 {
				slog.Debug("Negotiate: HTTP 500 response (possible timeout)", "status", resp.Status)
			} else {
				slog.Error("Negotiate: HTTP error response", "status", resp.Status)
			}
		}

		// Check if response is encrypted (multipart/encrypted)
		respContentType := resp.Header.Get("Content-Type")
		isEncryptedResponse := strings.Contains(respContentType, "multipart/encrypted")

		if isEncryptedResponse {
			slog.Debug("Negotiate: Received encrypted response", "contentType", respContentType)
			respBody, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("read encrypted response: %w", err)
			}

			// Unwrap multipart
			encryptedPayload, err := unwrapWinRMMultipart(respBody)
			if err != nil {
				return nil, fmt.Errorf("unwrap multipart: %w", err)
			}
			slog.Debug("Negotiate: Unwrapped multipart", "payloadLen", len(encryptedPayload))

			// Decrypt payload
			decrypted, err := rt.provider.Unwrap(encryptedPayload)
			if err != nil {
				slog.Error("Negotiate: Decryption FAILED", "error", err)
				return nil, fmt.Errorf("decrypt response body: %w", err)
			}
			slog.Debug("Negotiate: Decryption SUCCESS", "decryptedLen", len(decrypted))

			// Restore original response body
			resp.Body = io.NopCloser(bytes.NewReader(decrypted))
			resp.ContentLength = int64(len(decrypted))
			resp.Header.Set("Content-Type", winrmOriginalType)
		} else {
			slog.Info("Negotiate: Received UNENCRYPTED response (unexpected for established Kerberos context?)", "status", resp.Status)
		}

		return resp, nil
	}

	// ---- LEGACY/STANDARD AUTH LOOP (HTTPS or Handshake) ----

	// Capture TLS connection state for CBT if applicable
	var cbtData []byte
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				if tlsConn, ok := info.Conn.(*tls.Conn); ok {
					state := tlsConn.ConnectionState()
					cbtData = getCBTHash(&state)
				}
			} else if info.Conn == nil {
				slog.Warn("GotConn returned nil connection")
			}
		},
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)

	// Traditional challenge-response flow:
	// 1. First request without token
	// 2. Get 401 + Negotiate challenge
	// 3. Generate token and send
	// 4. Get 200 (or mutual auth response)

	var clientToken []byte
	var serverToken []byte

	// Initial call to Step() to generate first token
	// Note: We use nil serverToken for the first step
	var err error
	clientToken, _, err = rt.provider.Step(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("initial auth step failed: %w", err)
	}

	// Bounded retry loop for multi-leg SPNEGO (supports NTLM which needs 3 legs)
	for attempt := 0; attempt < maxNegotiateRetries; attempt++ {
		// Clone request to avoid data races and inject CBT data if available
		reqCtx := ctx
		if len(cbtData) > 0 {
			reqCtx = context.WithValue(reqCtx, ContextKeyChannelBindings, cbtData)
		}
		reqClone := req.Clone(reqCtx)
		if bodyBytes != nil {
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.ContentLength = int64(len(bodyBytes))
		}

		// Add auth header if we have a token from provider
		if clientToken != nil {
			authHeaderValue := fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(clientToken))
			slog.Debug("Sending Authorization header", "length", len(authHeaderValue), "tokenB64Len", len(base64.StdEncoding.EncodeToString(clientToken)))
			reqClone.Header.Set("Authorization", authHeaderValue)
		}

		// Execute request
		resp, err := rt.base.RoundTrip(reqClone)
		if err != nil {
			return nil, err
		}

		// Success - return response
		if resp.StatusCode != http.StatusUnauthorized {
			// Authentication complete!
			// Check for mutual auth token (final leg)
			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader != "" && strings.Contains(strings.ToLower(authHeader), "negotiate") {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 {
					serverTokenBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
					if len(serverTokenBytes) > 0 {
						slog.Info("Negotiate: Processing final mutual auth token")
						if err := rt.provider.ProcessResponse(ctx, authHeader); err != nil {
							slog.Warn("Negotiate: Failed to process final mutual auth token", "error", err)
						}
					}
				}
			}
			return resp, nil
		}

		// Check for Negotiate header in 401 response
		authHeader := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(strings.ToLower(authHeader), "negotiate") {
			// Not a Negotiate challenge, return as-is
			return resp, nil
		}

		// Extract server token if present
		serverToken = nil
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			token, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
			if decodeErr == nil {
				serverToken = token
			}
		}

		// If we already sent a token and server returns bare "Negotiate", auth was rejected
		if attempt > 0 && serverToken == nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("negotiate authentication rejected: server returned 401 with bare Negotiate after receiving our token")
		}

		// Generate our response token
		var continueNeeded bool
		clientToken, continueNeeded, err = rt.provider.Step(reqCtx, serverToken)
		if err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("negotiate step failed: %w", err)
		}

		// Close response body before retry
		_ = resp.Body.Close()

		// If no more steps needed and we already sent a token, we're done
		if !continueNeeded && attempt > 0 {
			break
		}
	}

	return nil, fmt.Errorf("negotiate authentication failed after %d attempts", maxNegotiateRetries)
}
