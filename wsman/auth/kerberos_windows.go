//go:build windows

package auth

// NewKerberosProvider creates the appropriate Kerberos provider for the platform.
// On Windows, this ALWAYS uses SSPI because:
//   - SSPI handles Kerberos natively via the Negotiate/Kerberos packages
//   - SSPI integrates with Windows credential store (LSA)
//   - pure Go Kerberos (gokrb5) doesn't work on Windows (no krb5.conf, no MSLSA ccache support)
func NewKerberosProvider(cfg KerberosProviderConfig) (SecurityProvider, error) {
	sspiCfg := SSPIConfig{
		// Default to SSO (use current Windows user credentials)
		UseDefaultCreds: true,
		PackageName:     cfg.SSPIPackage,
	}
	if sspiCfg.PackageName == "" {
		sspiCfg.PackageName = SSPIPackageNegotiate
	}

	// If explicit credentials provided, use them instead of SSO
	if cfg.Credentials != nil && cfg.Credentials.Username != "" {
		sspiCfg.UseDefaultCreds = false
		sspiCfg.Username = cfg.Credentials.Username
		sspiCfg.Password = cfg.Credentials.Password
		sspiCfg.Domain = cfg.Credentials.Domain
	}

	return NewSSPIProvider(sspiCfg, cfg.TargetSPN)
}

// SupportsSSO returns true if the platform supports SSO.
func SupportsSSO() bool {
	return true
}
