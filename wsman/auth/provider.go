package auth

import "context"

// SecurityProvider handles the low-level authentication token exchange.
// It abstracts the differences between NTLM, Kerberos (Pure Go), SSPI (Windows), and GSSAPI.
//
// # Thread Safety
//
// SecurityProvider implementations are NOT safe for concurrent use.
// Each goroutine should use its own provider instance. The provider
// maintains internal state during the authentication handshake.
//
// # Authentication Flow
//
// The typical flow is:
//  1. Client calls Step(nil) -> returns Initial Token
//  2. Client sends Token to Server
//  3. Server responds with Server Token (Challenge)
//  4. Client calls Step(Server Token) -> returns Response Token
//  5. Repeat until Complete() returns true.
type SecurityProvider interface {
	// Step processes an input token (challenge) and produces an output token (response).
	// On the first call, inputToken should be nil.
	// Returns:
	// - outputToken: The bytes to send to the server
	// - continueNeeded: True if more steps are expected (GSS_S_CONTINUE_NEEDED)
	// - err: Any error that occurred
	Step(ctx context.Context, inputToken []byte) (outputToken []byte, continueNeeded bool, err error)

	// Complete returns true if the security context has been successfully established.
	Complete() bool

	// Close releases any resources associated with the context (e.g. handles).
	Close() error
}
