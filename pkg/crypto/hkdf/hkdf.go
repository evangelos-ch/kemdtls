package hkdf

import (
	"encoding/binary"
	"hash"
	"io"

	HKDF "golang.org/x/crypto/hkdf"
)

func Extract(hash func() hash.Hash, secret []byte, salt []byte) []byte {
	return HKDF.Extract(hash, secret, salt)
}

func Expand(hash func() hash.Hash, secret []byte, label string, handshakeHash []byte) io.Reader {
	labelPrefix := []byte("dtls13 ")
	labelPrefixLength := len(labelPrefix)

	labelBytes := []byte(label)
	labelLength := len(labelBytes)
	totalLabelLength := labelPrefixLength + labelLength

	outputSize := 3 + totalLabelLength + len(handshakeHash)

	// Marshal
	buffer := make([]byte, outputSize)
	binary.BigEndian.PutUint16(buffer, uint16(outputSize))
	buffer[2] = uint8(totalLabelLength)
	buffer = append(buffer, labelPrefix...)
	buffer = append(buffer, labelBytes...)
	buffer = append(buffer, uint8(len(handshakeHash)))
	buffer = append(buffer, handshakeHash...)

	return HKDF.Expand(hash, secret, buffer)
}
