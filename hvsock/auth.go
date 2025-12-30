//go:build windows

package hvsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
)

// Service GUIDs for PowerShell Direct
var (
	// PsrpBrokerServiceID is the first connection (broker/vmicvmsession)
	PsrpBrokerServiceID = uuid.MustParse("999e53d4-3d5c-4c3e-8779-bed06ec056e1")
	// PsrpServerServiceID is the second connection (actual PowerShell process)
	PsrpServerServiceID = uuid.MustParse("a5201c21-2770-4c11-a68e-f182edb29220")
)

// Protocol constants
const (
	versionRequest = "VERSION"
	clientVersion  = "VERSION_2"
	versionPrefix  = "VERSION_"

	defaultAuthTimeout = 10 * time.Second
)

// Verbose enables debug logging
var Verbose = os.Getenv("PSRP_DEBUG") != ""

func debugf(format string, args ...interface{}) {
	if Verbose {
		log.Printf("[hvsock] "+format, args...)
	}
}

// dialServiceWithTimeout connects to a specific HvSocket service with a timeout
func dialServiceWithTimeout(ctx context.Context, vmID, serviceID uuid.UUID, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return DialService(dialCtx, vmID, serviceID)
}

// ConnectAndAuthenticate performs the full two-stage PowerShell Direct connection:
// 1. Connect to broker, exchange credentials, get token
// 2. Connect to PS process, exchange token
// Returns the final connection ready for PSRP protocol.
func ConnectAndAuthenticate(ctx context.Context, vmID uuid.UUID, domain, user, pass, configName string) (net.Conn, error) {
	debugf("=== Stage 1: Connecting to Broker ===")

	// Stage 1: Connect to broker service (vmicvmsession)
	brokerConn, err := dialServiceWithTimeout(ctx, vmID, PsrpBrokerServiceID, defaultAuthTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}

	// Authenticate with broker and get token
	token, err := authenticateWithBroker(brokerConn, domain, user, pass, configName)
	if err != nil {
		brokerConn.Close()
		return nil, fmt.Errorf("broker auth: %w", err)
	}

	// Close broker connection - we need to make a new connection to the PS process
	brokerConn.Close()
	debugf("Broker connection closed. Token: %q", token)

	if token == "" {
		return nil, fmt.Errorf("no token received from broker (legacy mode not supported)")
	}

	// Stage 2: Retry connection to PS process
	// The vmicvmsession service needs to spawn pwsh.exe and it needs to bind to the socket.
	// This can take varying amounts of time depending on VM load.
	debugf("=== Stage 2: Connecting to PowerShell Process ===")

	const (
		maxRetries   = 10
		initialDelay = 250 * time.Millisecond
		maxDelay     = 3 * time.Second
		dialTimeout  = 5 * time.Second
	)

	var psConn net.Conn
	var lastErr error
	delay := initialDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Small initial delay to let PS process start
		if attempt == 1 {
			time.Sleep(500 * time.Millisecond)
		}

		debugf("Stage 2 attempt %d/%d", attempt, maxRetries)

		psConn, lastErr = dialServiceWithTimeout(ctx, vmID, PsrpServerServiceID, dialTimeout)
		if lastErr == nil {
			debugf("Stage 2 connection succeeded on attempt %d", attempt)
			break
		}

		debugf("Stage 2 attempt %d failed: %v", attempt, lastErr)

		if attempt < maxRetries {
			debugf("Waiting %v before retry...", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during connection retry: %w", ctx.Err())
			}

			// Exponential backoff
			delay = time.Duration(float64(delay) * 1.5)
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("stage 2 failed after %d attempts: %w", maxRetries, lastErr)
	}

	// Authenticate with PS process using the token
	if err := authenticateWithToken(psConn, token); err != nil {
		psConn.Close()
		return nil, fmt.Errorf("ps auth: %w", err)
	}

	debugf("=== Both stages complete - connection ready for PSRP ===")
	return psConn, nil
}

// dialService connects to a specific HvSocket service on the VM
// Kept for backward compatibility if needed, but ConnectAndAuthenticate uses dialServiceWithTimeout
func dialService(ctx context.Context, vmID, serviceID uuid.UUID) (net.Conn, error) {
	return DialService(ctx, vmID, serviceID)
}

// authenticateWithBroker handles the first-stage authentication (credential exchange)
// Returns the authentication token for the second stage
func authenticateWithBroker(conn net.Conn, domain, user, pass, configName string) (string, error) {
	// Default domain to localhost if empty
	if domain == "" || domain == "." {
		domain = "localhost"
	}

	debugf("Starting broker authentication: domain=%q, user=%q, configName=%q", domain, user, configName)

	// Step 1: Version Exchange
	debugf("Sending VERSION request...")
	if _, err := conn.Write([]byte(versionRequest)); err != nil {
		return "", fmt.Errorf("send version request: %w", err)
	}

	versionResp, err := receiveASCII(conn, 16)
	if err != nil {
		return "", fmt.Errorf("read version response: %w", err)
	}
	debugf("Received version response: %q", versionResp)

	if !strings.HasPrefix(versionResp, versionPrefix) {
		return "", fmt.Errorf("server uses legacy protocol (got %q), VERSION_2+ required", versionResp)
	}

	debugf("Sending client version: %q", clientVersion)
	if _, err := conn.Write([]byte(clientVersion)); err != nil {
		return "", fmt.Errorf("send client version: %w", err)
	}

	ack, err := receiveASCII(conn, 4)
	if err != nil {
		return "", fmt.Errorf("read version ack: %w", err)
	}
	debugf("Received version ack: %q", ack)
	if ack != "PASS" {
		return "", fmt.Errorf("version negotiation failed: %s", ack)
	}

	// Step 2: Send Domain
	debugf("Sending domain: %q", domain)
	if _, err := conn.Write(encodeUTF16LE(domain)); err != nil {
		return "", fmt.Errorf("send domain: %w", err)
	}
	if _, err := receiveASCII(conn, 4); err != nil {
		return "", fmt.Errorf("read domain ack: %w", err)
	}

	// Step 3: Send Username
	debugf("Sending username: %q", user)
	if _, err := conn.Write(encodeUTF16LE(user)); err != nil {
		return "", fmt.Errorf("send user: %w", err)
	}
	if _, err := receiveASCII(conn, 4); err != nil {
		return "", fmt.Errorf("read user ack: %w", err)
	}

	// Step 4: Send Password
	emptyPassword := pass == ""
	if emptyPassword {
		debugf("Sending EMPTYPW")
		if _, err := conn.Write([]byte("EMPTYPW")); err != nil {
			return "", fmt.Errorf("send emptypw: %w", err)
		}
	} else {
		debugf("Sending NONEMPTYPW")
		if _, err := conn.Write([]byte("NONEMPTYPW")); err != nil {
			return "", fmt.Errorf("send nonemptypw: %w", err)
		}
		if _, err := receiveASCII(conn, 4); err != nil {
			return "", fmt.Errorf("read password prompt ack: %w", err)
		}
		debugf("Sending password")
		if _, err := conn.Write(encodeUTF16LE(pass)); err != nil {
			return "", fmt.Errorf("send password: %w", err)
		}
	}

	// Step 5: Receive credential response
	credResp, err := receiveASCII(conn, 4)
	if err != nil {
		return "", fmt.Errorf("read credential response: %w", err)
	}
	debugf("Received credential response: %q", credResp)

	switch credResp {
	case "FAIL":
		conn.Write([]byte("FAIL"))
		return "", errors.New("authentication failed: invalid credentials")

	case "PASS":
		// Legacy mode - no token
		conn.Write([]byte("PASS"))
		return "", nil

	case "CONF":
		emptyConfig := configName == ""
		if emptyConfig {
			debugf("Sending EMPTYCF")
			if _, err := conn.Write([]byte("EMPTYCF")); err != nil {
				return "", fmt.Errorf("send emptycf: %w", err)
			}
		} else {
			debugf("Sending NONEMPTYCF")
			if _, err := conn.Write([]byte("NONEMPTYCF")); err != nil {
				return "", fmt.Errorf("send nonemptycf: %w", err)
			}
			if _, err := receiveASCII(conn, 4); err != nil {
				return "", fmt.Errorf("read config prompt ack: %w", err)
			}
			if _, err := conn.Write(encodeUTF16LE(configName)); err != nil {
				return "", fmt.Errorf("send config name: %w", err)
			}
		}

		// Receive token
		tokenResp, err := receiveASCIIWithTimeout(conn, 1024, defaultAuthTimeout)
		if err != nil {
			return "", fmt.Errorf("read token: %w", err)
		}
		debugf("Received token response: %q", tokenResp)

		if !strings.HasPrefix(tokenResp, "TOKEN ") {
			return "", fmt.Errorf("expected token, got: %q", tokenResp)
		}

		token := strings.TrimPrefix(tokenResp, "TOKEN ")
		token = strings.TrimSpace(token)

		// Acknowledge token
		debugf("Sending token ack (PASS)")
		if _, err := conn.Write([]byte("PASS")); err != nil {
			return "", fmt.Errorf("send token ack: %w", err)
		}

		return token, nil

	default:
		return "", fmt.Errorf("unexpected credential response: %q", credResp)
	}
}

// authenticateWithToken handles the second-stage authentication (token exchange)
func authenticateWithToken(conn net.Conn, token string) error {
	debugf("Starting token authentication with token: %q", token)

	// Step 1: Version Exchange
	debugf("Sending VERSION request...")
	if _, err := conn.Write([]byte(versionRequest)); err != nil {
		return fmt.Errorf("send version request: %w", err)
	}

	versionResp, err := receiveASCII(conn, 16)
	if err != nil {
		return fmt.Errorf("read version response: %w", err)
	}
	debugf("Received version response: %q", versionResp)

	if !strings.HasPrefix(versionResp, versionPrefix) {
		return fmt.Errorf("server uses legacy protocol (got %q)", versionResp)
	}

	debugf("Sending client version: %q", clientVersion)
	if _, err := conn.Write([]byte(clientVersion)); err != nil {
		return fmt.Errorf("send client version: %w", err)
	}

	ack, err := receiveASCII(conn, 4)
	if err != nil {
		return fmt.Errorf("read version ack: %w", err)
	}
	debugf("Received version ack: %q", ack)
	if ack != "PASS" {
		return fmt.Errorf("version negotiation failed: %s", ack)
	}

	// Step 2: Send token
	tokenMsg := "TOKEN " + token
	debugf("Sending token: %q", tokenMsg)
	if _, err := conn.Write([]byte(tokenMsg)); err != nil {
		return fmt.Errorf("send token: %w", err)
	}

	// Receive token response
	tokenResp, err := receiveASCII(conn, 256)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}
	debugf("Received token response: %q", tokenResp)

	if tokenResp != "PASS" {
		return fmt.Errorf("token authentication failed: %s", tokenResp)
	}

	debugf("Token authentication successful!")
	return nil
}

// Authenticate is the legacy single-stage function. For new code, use ConnectAndAuthenticate.
// This continues to work for the current single-connection approach during testing.
func Authenticate(conn net.Conn, domain, user, pass, configName string) error {
	token, err := authenticateWithBroker(conn, domain, user, pass, configName)
	if err != nil {
		return err
	}
	// If we got a token, we're in VERSION_2 mode and need a second connection
	// But for now, we'll continue on the same connection (which won't work but allows testing)
	if token != "" {
		debugf("NOTE: Got token but continuing on same connection (this won't work for real use)")
	}
	return nil
}

// receiveASCII reads up to maxLen bytes and returns as ASCII string with default timeout
func receiveASCII(conn net.Conn, maxLen int) (string, error) {
	return receiveASCIIWithTimeout(conn, maxLen, defaultAuthTimeout)
}

// receiveASCIIWithTimeout reads up to maxLen bytes with specified timeout
func receiveASCIIWithTimeout(conn net.Conn, maxLen int, timeout time.Duration) (string, error) {
	buf := make([]byte, maxLen)
	debugf("  receiveASCII: waiting for up to %d bytes (timeout: %v)...", maxLen, timeout)

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			debugf("  receiveASCII: timeout after %v", timeout)
			return "", fmt.Errorf("read timeout: server did not respond within %v", timeout)
		}
		debugf("  receiveASCII: error: %v", err)
		return "", err
	}

	if n == 0 {
		debugf("  receiveASCII: got 0 bytes (EOF)")
		return "", io.EOF
	}

	debugf("  receiveASCII: got %d bytes: %x", n, buf[:n])
	result := string(buf[:n])
	result = strings.TrimRight(result, "\x00")
	return result, nil
}

// encodeUTF16LE converts string to UTF-16LE bytes
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}
