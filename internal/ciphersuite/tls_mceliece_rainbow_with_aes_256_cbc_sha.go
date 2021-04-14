package ciphersuite

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

// TLSMcElieceSphincsWithAes256CbcSha implements the TLS_MCELIECE_Sphincs_WITH_AES_256_CBC_SHA CipherSuite
type TLSMcElieceSphincsWithAes256CbcSha struct {
	TLSEcdheEcdsaWithAes256CbcSha
}

// CertificateType returns what type of certificate this CipherSuite exchanges
func (c *TLSMcElieceSphincsWithAes256CbcSha) CertificateType() clientcertificate.Type {
	return clientcertificate.SPHINCSSign
}

// ID returns the ID of the CipherSuite
func (c *TLSMcElieceSphincsWithAes256CbcSha) ID() ID {
	return TLS_MCELIECE_SPHINCS_WITH_AES_256_CBC_SHA
}

func (c *TLSMcElieceSphincsWithAes256CbcSha) String() string {
	return "TLS_MCELIECE_SPHINCS_WITH_AES_256_CBC_SHA"
}
