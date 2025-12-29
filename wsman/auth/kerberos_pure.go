package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"
)

// PureKerberosProvider implements SecurityProvider using the pure Go gokrb5 library.
type PureKerberosProvider struct {
	client       *client.Client
	spnegoClient *spnego.SPNEGO
	targetSPN    string
	isComplete   bool
}

// PureKerberosConfig holds the configuration for the PureKerberosProvider.
type PureKerberosConfig struct {
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
		cl = client.NewWithKeytab(cfg.Credentials.Username, cfg.Realm, kt, conf, client.DisablePAFXFAST(true))
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

	return &PureKerberosProvider{
		client:    cl,
		targetSPN: targetSPN,
	}, nil
}

// Step performs a GSS-API/SPNEGO step.
func (p *PureKerberosProvider) Step(_ context.Context, inputToken []byte) ([]byte, bool, error) {
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
		//
		// gokrb5's SPNEGO client doesn't expose a clean API for processing
		// the server's mutual auth response token. The InitSecContext() method
		// generates the client token but doesn't have a corresponding method
		// to verify the server's response.
		//
		// For standard Kerberos HTTP auth (which is typically 1-leg), this is
		// acceptable - the server accepts our token and returns 200 OK with
		// an optional mutual auth token. If mutual auth is required, we should
		// validate the server's response, but gokrb5 doesn't expose this API.
		//
		// Safety check: ensure we already sent our token before accepting
		// the server's response. This prevents accepting a server token
		// without ever having authenticated.
		if !p.isComplete {
			return nil, false, fmt.Errorf(
				"received server token before client authentication completed (mutual auth not supported)")
		}

		// Already complete - the server sent a mutual auth token
		// We cannot validate it with gokrb5's current API, so we accept it.
		// TODO: Implement mutual auth validation when gokrb5 supports it.
		return nil, false, nil
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
func (p *PureKerberosProvider) Complete() bool {
	return p.isComplete
}

// Close releases resources.
func (p *PureKerberosProvider) Close() error {
	p.client.Destroy()
	return nil
}
