package extension

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/pkg/crypto/kem"
)

const (
	// Size of the header part of the extension
	// Bytes 0 and 1: the 2 byte value for a TLS Extension as registered in the IANA
	// Bytes 4 and 5: the length of the key share entries * 2.
	keySharesHeaderSize = 6
)

type KeyShareEntry struct {
	Group   kem.KEM
	Payload []byte
}

type KeyShare struct {
	KeyShareEntries []KeyShareEntry
}

func (s KeyShare) TypeValue() TypeValue {
	return KeyShareTypeValue
}

func (s *KeyShare) Marshal() ([]byte, error) {
	out := make([]byte, keySharesHeaderSize)

	// Get total payload size
	payloadSize := 0
	for _, v := range s.KeyShareEntries {
		payloadSize += 2 + v.Group.PayloadSize()
	}

	// Header
	binary.BigEndian.PutUint16(out, uint16(s.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(2+payloadSize))
	binary.BigEndian.PutUint16(out[4:], uint16(payloadSize))

	// Body
	for _, v := range s.KeyShareEntries {
		// Group
		buffer := make([]byte, 2)
		binary.BigEndian.PutUint16(buffer, uint16(v.Group))

		// Payload
		buffer = append(buffer, v.Payload...)
		out = append(out, buffer...)
	}

	return out, nil
}

func (s *KeyShare) Unmarshal(data []byte) error {
	if len(data) <= keySharesHeaderSize {
		return errBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != s.TypeValue() {
		return errInvalidExtensionType
	}

	currentByte := keySharesHeaderSize
	for currentByte != len(data) {
		group := kem.KEM(binary.BigEndian.Uint16(data[currentByte : currentByte+2]))
		currentByte += 2
		if _, ok := kem.KEMs()[group]; ok {
			s.KeyShareEntries = append(s.KeyShareEntries, KeyShareEntry{
				Group:   group,
				Payload: data[currentByte : currentByte+group.PayloadSize()],
			})
		}
		currentByte += group.PayloadSize()
	}

	return nil
}
