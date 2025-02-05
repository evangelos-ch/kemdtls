package handshake

import (
	"encoding/binary"

	// "github.com/pion/dtls/v2/pkg/crypto/elliptic"
	// "github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/kem"
	// "github.com/pion/dtls/v2/pkg/crypto/signature"
)

// MessageServerKeyExchange supports ECDH and PSK
type MessageServerKeyExchange struct {
	IdentityHint []byte

	SelectedKEM kem.KEM
	PublicKey   []byte
	Ciphertext  []byte
}

// Type returns the Handshake Type
func (m MessageServerKeyExchange) Type() Type {
	return TypeServerKeyExchange
}

// Marshal encodes the Handshake
func (m *MessageServerKeyExchange) Marshal() ([]byte, error) {
	if m.IdentityHint != nil {
		out := append([]byte{0x00, 0x00}, m.IdentityHint...)
		binary.BigEndian.PutUint16(out, uint16(len(out)-2))
		return out, nil
	}

	// out := []byte{byte(m.EllipticCurveType), 0x00, 0x00}
	// binary.BigEndian.PutUint16(out[1:], uint16(m.NamedCurve))

	out := []byte{0x0, 0x0}
	binary.BigEndian.PutUint16(out, uint16(m.SelectedKEM))

	out = append(out, []byte{0x0, 0x0}...)
	binary.BigEndian.PutUint16(out[2:], uint16(len(m.PublicKey)))
	out = append(out, m.PublicKey...)

	buff := []byte{0x0, 0x0}
	binary.BigEndian.PutUint16(buff, uint16(len(m.Ciphertext)))
	buff = append(buff, m.Ciphertext...)
	out = append(out, buff...)

	// if m.HashAlgorithm == hash.None && m.SignatureAlgorithm == signature.Anonymous && len(m.Signature) == 0 {
	// 	return out, nil
	// }

	// out = append(out, []byte{byte(m.HashAlgorithm), byte(m.SignatureAlgorithm), 0x00, 0x00}...)
	// binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(m.Signature)))
	// out = append(out, m.Signature...)

	return out, nil
}

// Unmarshal populates the message from encoded data
func (m *MessageServerKeyExchange) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errBufferTooSmall
	}

	// If parsed as PSK return early and only populate PSK Identity Hint
	if pskLength := binary.BigEndian.Uint16(data); len(data) == int(pskLength+2) {
		m.IdentityHint = append([]byte{}, data[2:]...)
		return nil
	}

	serverKem := kem.KEM(binary.BigEndian.Uint16(data[:2]))
	if _, ok := kem.KEMs()[serverKem]; ok {
		m.SelectedKEM = serverKem
	} else {
		return errInvalidEllipticKEM
	}

	// if _, ok := elliptic.CurveTypes()[elliptic.CurveType(data[0])]; ok {
	// 	m.EllipticCurveType = elliptic.CurveType(data[0])
	// } else {
	// 	return errInvalidEllipticCurveType
	// }

	// if len(data[1:]) < 2 {
	// 	return errBufferTooSmall
	// }
	// m.NamedCurve = elliptic.Curve(binary.BigEndian.Uint16(data[1:3]))
	// if _, ok := elliptic.Curves()[m.NamedCurve]; !ok {
	// 	return errInvalidNamedCurve
	// }
	// if len(data) < 4 {
	// 	return errBufferTooSmall
	// }

	publicKeyLength := binary.BigEndian.Uint16(data[2:4])
	offset := 4 + publicKeyLength
	if uint16(len(data)) < offset {
		return errBufferTooSmall
	}
	m.PublicKey = append([]byte{}, data[4:offset]...)

	ciphertextLength := binary.BigEndian.Uint16(data[offset : offset+2])
	originalOffset := offset + 2
	offset += ciphertextLength + 2
	if uint16(len(data)) < offset {
		return errBufferTooSmall
	}
	m.Ciphertext = append([]byte{}, data[originalOffset:offset]...)

	// Anon connection doesn't contains hashAlgorithm, signatureAlgorithm, signature
	if uint16(len(data)) == offset {
		return nil
	} else if uint16(len(data)) <= offset {
		return errBufferTooSmall
	}

	// m.HashAlgorithm = hash.Algorithm(data[offset])
	// if _, ok := hash.Algorithms()[m.HashAlgorithm]; !ok {
	// 	return errInvalidHashAlgorithm
	// }
	// offset++
	// if len(data) <= offset {
	// 	return errBufferTooSmall
	// }
	// m.SignatureAlgorithm = signature.Algorithm(data[offset])
	// if _, ok := signature.Algorithms()[m.SignatureAlgorithm]; !ok {
	// 	return errInvalidSignatureAlgorithm
	// }
	// offset++
	// if len(data) < offset+2 {
	// 	return errBufferTooSmall
	// }
	// signatureLength := int(binary.BigEndian.Uint16(data[offset:]))
	// offset += 2
	// if len(data) < offset+signatureLength {
	// 	return errBufferTooSmall
	// }
	// m.Signature = append([]byte{}, data[offset:offset+signatureLength]...)
	return nil
}
