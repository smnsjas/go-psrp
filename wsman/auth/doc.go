// Package auth provides authentication handlers for WSMan connections.
//
// # Supported Authentication Methods
//
//   - Basic: HTTP Basic authentication (use only over TLS)
//   - NTLM: NT LAN Manager authentication (via github.com/Azure/go-ntlmssp)
//   - Kerberos: Via gokrb5 (pure Go) on all platforms, or Windows SSPI
//   - Negotiate: SPNEGO wrapper that prefers Kerberos, falls back to NTLM
//
// # Platform Support
//
// On Windows, Kerberos authentication can use Single Sign-On (SSO) with
// the logged-in user's credentials via the native SSPI API.
//
// On other platforms (macOS, Linux), explicit credentials are required:
// password, keytab file, or credential cache (ccache from kinit).
//
// # Usage
//
// NTLM authentication:
//
//	auth := auth.NewNTLMAuth(auth.Credentials{
//	    Username: "administrator",
//	    Password: "password",
//	    Domain:   "DOMAIN",
//	})
//
// Kerberos authentication:
//
//	provider, _ := auth.NewKerberosProvider(auth.KerberosProviderConfig{
//	    TargetSPN:   "HTTP/server.domain.com",
//	    Realm:       "DOMAIN.COM",
//	    Credentials: &auth.Credentials{Username: "user", Password: "pass"},
//	})
//	auth := auth.NewNegotiateAuth(provider)
//
// Kerberos with credential cache (SSO after kinit):
//
//	provider, _ := auth.NewKerberosProvider(auth.KerberosProviderConfig{
//	    TargetSPN:    "HTTP/server.domain.com",
//	    Realm:        "DOMAIN.COM",
//	    CCachePath:   "/tmp/krb5cc_1000",
//	    Krb5ConfPath: "/etc/krb5.conf",
//	})
//	auth := auth.NewNegotiateAuth(provider)
package auth
