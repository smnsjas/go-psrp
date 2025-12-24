module github.com/smnsjas/go-psrp

go 1.25

require (
	github.com/Azure/go-ntlmssp v0.1.0
	github.com/google/uuid v1.6.0
)

require github.com/smnsjas/go-psrpcore v0.0.0-20251224034619-517dc56730eb

replace github.com/smnsjas/go-psrpcore => ../go-psrpcore
