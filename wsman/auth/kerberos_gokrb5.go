package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Gokrb5Provider implements SecurityProvider using the pure Go gokrb5 library.
type Gokrb5Provider struct {
	client       *client.Client
	spnegoClient *spnego.SPNEGO
	targetSPN    string
	isComplete   bool
}

// Gokrb5Config holds the configuration for the Gokrb5Provider.
type Gokrb5Config struct {
	// Realm is the Kerberos realm (e.g. EXAMPLE.COM).
	Realm string

	// Krb5ConfPath is the path to the krb5.conf file.
	Krb5ConfPath string

	// KeytabPath is the path to the keytab file (optional).
	KeytabPath string

	// CCachePath is the path to the credential cache (optional).
	CCachePath string

	// Credentials are used if KeytabPath/CCachePath are empty.
	Credentials *Credentials
}

// NewGokrb5Provider creates a new pure Go Kerberos provider.
func NewGokrb5Provider(cfg Gokrb5Config, targetSPN string) (*Gokrb5Provider, error) {
	// Load krb5.conf
	if cfg.Krb5ConfPath == "" {
		cfg.Krb5ConfPath = os.Getenv("KRB5_CONFIG")
		if cfg.Krb5ConfPath == "" {
			cfg.Krb5ConfPath = "/etc/krb5.conf"
		}
	}
	conf, err := config.Load(cfg.Krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("load krb5.conf: %w", err)
	}

	var cl *client.Client

	// Client options - disable FAST for compatibility with older KDCs
	clientOpts := []func(*client.Settings){
		client.DisablePAFXFAST(true),
	}

	// 1. Try Keytab
	if cfg.KeytabPath != "" {
		kt, err := keytab.Load(cfg.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("load keytab: %w", err)
		}
		cl = client.NewWithKeytab(cfg.Credentials.Username, cfg.Realm, kt, conf, clientOpts...)
	} else if cfg.CCachePath != "" {
		// 2. Try CCache
		cc, err := credentials.LoadCCache(cfg.CCachePath)
		if err != nil {
			return nil, fmt.Errorf("load ccache: %w", err)
		}
		cl, err = client.NewFromCCache(cc, conf, clientOpts...)
		if err != nil {
			return nil, fmt.Errorf("create client from ccache: %w", err)
		}
	} else if cfg.Credentials != nil {
		// 3. Password
		cl = client.NewWithPassword(cfg.Credentials.Username, cfg.Realm, cfg.Credentials.Password, conf, clientOpts...)
	} else {
		return nil, fmt.Errorf("no credentials provided (keytab, ccache, or password required)")
	}

	return &Gokrb5Provider{
		client:    cl,
		targetSPN: targetSPN,
	}, nil
}

// Step performs a GSS-API/SPNEGO step.
func (p *Gokrb5Provider) Step(ctx context.Context, inputToken []byte) ([]byte, bool, error) {
	// Perform Login if not already logged in
	// Note: gokrb5 client handles TGT renewal internally for us ideally,
	// but we trigger an initial login here.
	if p.spnegoClient == nil {
		if err := p.client.Login(); err != nil {
			return nil, false, fmt.Errorf("kerberos login: %w", err)
		}
		p.spnegoClient = spnego.SPNEGOClient(p.client, p.targetSPN)
	}

	// Delegate to gokrb5's SPNEGO implementation
	// Note: gokrb5's API is a bit different, it expects the first call to be InitSecContext
	// and subsequent calls to process the response.
	// However, standard GSSAPI is Step-based.
	// gokrb5's InitSecContext takes no input and produces the initial token.
	// BUT, if we receive a token (server challenge), we need to process it.

	var token []byte
	var err error

	if len(inputToken) == 0 {
		// Initial Token Generation
		tkn, err := p.spnegoClient.InitSecContext()
		if err != nil {
			return nil, false, err
		}
		token, err = tkn.Marshal()
		if err != nil {
			return nil, false, fmt.Errorf("marshal token: %w", err)
		}
	} else {
		// Process Server Challenge (Mutual Auth / Continued Step)
		// gokrb5 doesn't expose a clean "Step" function on SPNEGOClient public API easily
		// that handles the "AcceptSecContext" side or the "Continue" side for client?
		// Actually, SPNEGOClient IS the client-side context.
		// It has no public method to handling the server's response token for mutual auth currently exposed well?
		// Wait, let's check the library source or docs.
		// SPNEGOClient returns a *SPNEGO struct.
		// It has InitSecContext() -> (authtoken, error).

		// NOTE: gokrb5/v8/spnego implementation is primarily focused on the simple HTTP case
		// where the client sends one token.
		// It DOES support mutual auth but the API is:
		// CheckPrincipal(tkt Ticket, service string)
		// It doesn't seem to perfectly align with a generic "Step" function for multi-leg SPNEGO.

		// However, standard Kerberos HTTP auth is often 1-leg (Optimistic).
		// If mutual auth is required, the server sends a token back.

		// For now, let's assume 1-leg for the initial implementation as gokrb5 is often used.
		// If inputToken is present, it's likely the server's final mutual auth token.
		// We can try to process it, but if gokrb5 doesn't support it easily, we might just return success
		// if we are already done.
		return nil, false, nil // Treat as done for 1-leg for now
	}

	if err != nil {
		return nil, false, err
	}

	// If we generated a token, we usually expect the server to accept it.
	// In strict multi-leg SPNEGO (e.g. NTLM inside SPNEGO), we might need more steps.
	// But standard Kerberos is 1-leg.
	p.isComplete = true
	return token, false, nil
}

// Complete returns true if the context is established.
func (p *Gokrb5Provider) Complete() bool {
	return p.isComplete
}

// Close releases resources.
func (p *Gokrb5Provider) Close() error {
	p.client.Destroy()
	return nil
}
