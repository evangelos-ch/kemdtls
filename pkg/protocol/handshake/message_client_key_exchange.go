package handshake

import (
	"encoding/binary"
)

// MessageClientKeyExchange is a DTLS Handshake Message
// With this message, the premaster secret is set, either by direct
// transmission of the RSA-encrypted secret or by the transmission of
// Diffie-Hellman parameters that will allow each side to agree upon
// the same premaster secret.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.7
type MessageClientKeyExchange struct {
	IdentityHint []byte
	PublicKey    []byte
}

// Type returns the Handshake Type
func (m MessageClientKeyExchange) Type() Type {
	return TypeClientKeyExchange
}

// Marshal encodes the Handshake
func (m *MessageClientKeyExchange) Marshal() ([]byte, error) {
	switch {
	case (m.IdentityHint != nil && m.PublicKey != nil) || (m.IdentityHint == nil && m.PublicKey == nil):
		return nil, errInvalidClientKeyExchange
	case m.PublicKey != nil:
		out := append([]byte{0x01, 0x00, 0x00}, m.PublicKey...)
		binary.BigEndian.PutUint16(out[1:], uint16(len(out)-3))
		return out, nil
	default:
		out := append([]byte{0x00, 0x00, 0x00}, m.IdentityHint...)
		binary.BigEndian.PutUint16(out[1:], uint16(len(out)-3))
		return out, nil
	}
}

// Unmarshal populates the message from encoded data
func (m *MessageClientKeyExchange) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errBufferTooSmall
	}

	if int(data[0]) == 0 {
		// If parsed as PSK return early and only populate PSK Identity Hint
		if pskLength := binary.BigEndian.Uint16(data[1:3]); len(data) == int(pskLength+3) {
			m.IdentityHint = append([]byte{}, data[3:]...)
			return nil
		}
	} else {
		if publicKeyLength := binary.BigEndian.Uint16(data[1:3]); len(data) != int(publicKeyLength+3) {
			return errBufferTooSmall
		}

		m.PublicKey = append([]byte{}, data[3:]...)
		return nil
	}
	return nil
}
