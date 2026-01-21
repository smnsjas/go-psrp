//go:build windows

package auth

import (
	"encoding/binary"
)

const (
	SECBUFFER_CHANNEL_BINDINGS = 14
)

// SEC_CHANNEL_BINDINGS structure
// https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
// Note: This is 32 bytes (8 fields × 4 bytes), NOT 36 bytes
type secChannelBindings struct {
	InitiatorAddrType     uint32 // dwInitiatorAddrType
	InitiatorLength       uint32 // cbInitiatorLength
	InitiatorOffset       uint32 // dwInitiatorOffset
	AcceptorAddrType      uint32 // dwAcceptorAddrType
	AcceptorLength        uint32 // cbAcceptorLength
	AcceptorOffset        uint32 // dwAcceptorOffset
	ApplicationDataLength uint32 // cbApplicationDataLength
	ApplicationDataOffset uint32 // dwApplicationDataOffset
}

// tlsServerEndPointPrefix is the channel binding type prefix per RFC 5929
const tlsServerEndPointPrefix = "tls-server-end-point:"

// makeChannelBindings creates a SEC_CHANNEL_BINDINGS structure with the given certificate hash.
// Per MS docs, the ApplicationData must include the "tls-server-end-point:" prefix.
// Returns a byte slice containing the structure and data.
func makeChannelBindings(certHash []byte) []byte {
	// The application data is "tls-server-end-point:" + certHash
	appData := append([]byte(tlsServerEndPointPrefix), certHash...)

	// Size of header is 8 × 4 bytes = 32 bytes
	const headerSize = 32
	totalSize := headerSize + len(appData)

	buf := make([]byte, totalSize)

	// Write header fields using little-endian
	// Fields 0-5 (addresses) are all zeros
	// Field 6: ApplicationDataLength
	binary.LittleEndian.PutUint32(buf[24:28], uint32(len(appData)))
	// Field 7: ApplicationDataOffset
	binary.LittleEndian.PutUint32(buf[28:32], headerSize)

	// Copy application data after header
	copy(buf[headerSize:], appData)

	return buf
}
