//go:build !windows

package auth

// NewKerberosProvider creates the appropriate Kerberos provider for the platform.
// On non-Windows, this uses gokrb5 (pure Go).
func NewKerberosProvider(cfg KerberosProviderConfig) (SecurityProvider, error) {
	gokrb5Cfg := Gokrb5Config{
		Realm:        cfg.Realm,
		Krb5ConfPath: cfg.Krb5ConfPath,
		KeytabPath:   cfg.KeytabPath,
		CCachePath:   cfg.CCachePath,
		Credentials:  cfg.Credentials,
	}
	return NewGokrb5Provider(gokrb5Cfg, cfg.TargetSPN)
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
