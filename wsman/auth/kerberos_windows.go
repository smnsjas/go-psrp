//go:build windows

package auth

import "fmt"

// NewKerberosProvider creates the appropriate Kerberos provider for the platform.
// On Windows, this prefers SSPI for SSO support.
func NewKerberosProvider(cfg KerberosProviderConfig) (SecurityProvider, error) {
	if cfg.UseSSO {
		// Windows SSO - use SSPI
		sspiCfg := SSPIConfig{
			UseDefaultCreds: true,
		}
		return NewSSPIProvider(sspiCfg, cfg.TargetSPN)
	}

	// Explicit credentials - can use either SSPI or gokrb5
	// Prefer SSPI on Windows for consistency
	if cfg.Credentials != nil {
		sspiCfg := SSPIConfig{
			UseDefaultCreds: false,
			Username:        cfg.Credentials.Username,
			Password:        cfg.Credentials.Password,
			Domain:          cfg.Credentials.Domain,
		}
		return NewSSPIProvider(sspiCfg, cfg.TargetSPN)
	}

	// Fall back to gokrb5 for keytab/ccache
	gokrb5Cfg := PureKerberosConfig{
		Realm:        cfg.Realm,
		Krb5ConfPath: cfg.Krb5ConfPath,
		KeytabPath:   cfg.KeytabPath,
		CCachePath:   cfg.CCachePath,
		Credentials:  cfg.Credentials,
	}
	return NewPureKerberosProvider(gokrb5Cfg, cfg.TargetSPN)
}

// SupportsSSO returns true if the platform supports SSO.
func SupportsSSO() bool {
	return true
}

func init() {
	// Verify SSPI is available
	_ = fmt.Sprintf("Windows SSPI provider loaded")
}
