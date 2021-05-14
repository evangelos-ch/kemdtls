package ciphersuite

import "github.com/pion/dtls/v2/pkg/crypto/kem"

// TLSMcElieceSphincsWithAes256CbcSha implements the TLS_SABER_WITH_AES_128_GCM_SHA256 CipherSuite
type TLSSABERWithAes128GcmSha256 struct {
	TLSEcdheEcdsaWithAes128GcmSha256
}

// ID returns the ID of the CipherSuite
func (c *TLSSABERWithAes128GcmSha256) ID() ID {
	return TLS_SABER_WITH_AES_128_GCM_SHA256
}

func (c *TLSSABERWithAes128GcmSha256) String() string {
	return "TLS_SABER_WITH_AES_128_GCM_SHA256"
}

func (c *TLSSABERWithAes128GcmSha256) KEM() kem.KEM {
	return kem.SABER_FIRESABER
}
