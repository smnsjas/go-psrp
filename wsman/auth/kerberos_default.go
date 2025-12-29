//go:build !windows

package auth

// NewKerberosProvider creates the appropriate Kerberos provider for the platform.
// On non-Windows, this uses gokrb5 (pure Go) which works reliably with password auth.
// CGO sspi-rs has compatibility issues on macOS (can't access ticket cache, tiny tokens).
func NewKerberosProvider(cfg KerberosProviderConfig) (SecurityProvider, error) {
	// Use gokrb5 (pure Go) - works reliably with password auth
	gokrb5Cfg := PureKerberosConfig{
		Realm:        cfg.Realm,
		Krb5ConfPath: cfg.Krb5ConfPath,
		KeytabPath:   cfg.KeytabPath,
		CCachePath:   cfg.CCachePath,
		Credentials:  cfg.Credentials,
	}
	return NewPureKerberosProvider(gokrb5Cfg, cfg.TargetSPN)
}

// KerberosProviderConfig holds unified config for any Kerberos provider.
type KerberosProviderConfig struct {
	TargetSPN    string
	UseSSO       bool // Not supported on non-Windows
	Realm        string
	Krb5ConfPath string
	KeytabPath   string
	CCachePath   string
	Credentials  *Credentials
}

// SupportsSSO returns true if the platform supports SSO.
func SupportsSSO() bool {
	return false
}
