//go:build !ignore
// +build !ignore

package auth

// KerberosProviderConfig holds unified config for any Kerberos provider.
// This type is shared across all platforms.
type KerberosProviderConfig struct {
	// TargetSPN is the Service Principal Name (e.g., "HTTP/server.domain.com").
	TargetSPN string

	// UseSSO uses the current user's credentials (Windows only).
	// On non-Windows platforms, this field is ignored.
	UseSSO bool

	// Realm is the Kerberos realm (e.g., "DOMAIN.COM").
	// If empty, derived from krb5.conf or SPN.
	Realm string

	// Krb5ConfPath is the path to krb5.conf (default: /etc/krb5.conf).
	Krb5ConfPath string

	// KeytabPath is the path to a keytab file (optional).
	KeytabPath string

	// CCachePath is the path to a credential cache (optional).
	CCachePath string

	// Credentials are username/password credentials (optional).
	Credentials *Credentials
}
