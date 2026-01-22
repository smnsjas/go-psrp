//go:build windows

package auth

import (
	"encoding/binary"
)

const (
	// SECBUFFER_CHANNEL_BINDINGS is the buffer type for channel bindings.
	SECBUFFER_CHANNEL_BINDINGS = 14

	// secChannelBindingsHeaderSize is the size of SEC_CHANNEL_BINDINGS structure.
	// 8 fields × 4 bytes = 32 bytes
	secChannelBindingsHeaderSize = 32

	// tlsServerEndPointPrefix is the channel binding type prefix per RFC 5929.
	tlsServerEndPointPrefix = "tls-server-end-point:"
)

// makeChannelBindings creates a SEC_CHANNEL_BINDINGS structure with the given certificate hash.
// Per MS docs, the ApplicationData must include the "tls-server-end-point:" prefix.
// See: https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
func makeChannelBindings(certHash []byte) []byte {
	// Pre-allocate buffer for header + prefix + hash
	prefixLen := len(tlsServerEndPointPrefix)
	appDataLen := prefixLen + len(certHash)
	totalSize := secChannelBindingsHeaderSize + appDataLen

	buf := make([]byte, totalSize)

	// Write header fields using little-endian
	// Fields 0-5 (addresses) are all zeros - already zero from make()
	// Field 6: ApplicationDataLength (offset 24)
	binary.LittleEndian.PutUint32(buf[24:28], uint32(appDataLen))
	// Field 7: ApplicationDataOffset (offset 28)
	binary.LittleEndian.PutUint32(buf[28:32], secChannelBindingsHeaderSize)

	// Copy prefix and hash directly into buffer (single allocation)
	copy(buf[secChannelBindingsHeaderSize:], tlsServerEndPointPrefix)
	copy(buf[secChannelBindingsHeaderSize+prefixLen:], certHash)

	return buf
}
