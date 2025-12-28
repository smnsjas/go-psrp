module github.com/smnsjas/go-psrp

go 1.25

require (
	github.com/Azure/go-ntlmssp v0.1.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/smnsjas/go-psrpcore v0.0.0-20251224034619-517dc56730eb
	golang.org/x/term v0.38.0
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/smnsjas/go-psrpcore => ../go-psrpcore
