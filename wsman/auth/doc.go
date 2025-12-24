// Package auth provides authentication handlers for WSMan connections.
//
// Supported authentication methods:
//   - Basic: HTTP Basic authentication
//   - NTLM: NT LAN Manager authentication (via github.com/Azure/go-ntlmssp)
//
// # Usage
//
//	auth := auth.NewNTLMAuth(auth.Credentials{
//	    Username: "administrator",
//	    Password: "password",
//	    Domain:   "DOMAIN",
//	})
//	client := wsman.NewClient(endpoint, auth)
package auth
