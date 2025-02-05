package dtls

import (
	"github.com/pion/dtls/v2/pkg/crypto/kem"
	"github.com/pion/dtls/v2/pkg/protocol/extension"
)

func findMatchingSRTPProfile(a, b []SRTPProtectionProfile) (SRTPProtectionProfile, bool) {
	for _, aProfile := range a {
		for _, bProfile := range b {
			if aProfile == bProfile {
				return aProfile, true
			}
		}
	}
	return 0, false
}

func findMatchingCipherSuite(a, b []CipherSuite) (CipherSuite, bool) { //nolint
	for _, aSuite := range a {
		for _, bSuite := range b {
			if aSuite.ID() == bSuite.ID() {
				return aSuite, true
			}
		}
	}
	return nil, false
}

func findMatchingKEM(a []extension.KeyShareEntry, b []kem.KEM) (extension.KeyShareEntry, bool) {
	for _, aKem := range a {
		for _, bKem := range b {
			if aKem.Group == bKem {
				return aKem, true
			}
		}
	}
	return extension.KeyShareEntry{}, false
}

func splitBytes(bytes []byte, splitLen int) [][]byte {
	splitBytes := make([][]byte, 0)
	numBytes := len(bytes)
	for i := 0; i < numBytes; i += splitLen {
		j := i + splitLen
		if j > numBytes {
			j = numBytes
		}

		splitBytes = append(splitBytes, bytes[i:j])
	}

	return splitBytes
}
