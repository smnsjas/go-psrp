module github.com/smnsjas/go-psrp

go 1.25.0

require (
	github.com/Azure/go-ntlmssp v0.1.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e
	github.com/go-krb5/krb5 v0.0.0-20251226122733-d0288459fc25
	github.com/smnsjas/go-ntlm-cbt v0.0.0-20260107203125-46149984fac0
	golang.org/x/term v0.38.0
)

require (
	github.com/go-crypt/x v0.4.10 // indirect
	github.com/go-krb5/x v0.3.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/smnsjas/go-psrpcore => ../go-psrpcore
