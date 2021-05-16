package kem

import (
	"errors"
	"fmt"

	"github.com/pion/dtls/v2/pkg/crypto/kem/oqs"
)

type KEM uint16

// KEM enums
const (
	CLASSIC_MCELIECE_348864  KEM = 0x001e
	CLASSIC_MCELIECE_348864f KEM = 0x001f
	SABER_FIRESABER          KEM = 0x0020
	NTRU_HPS_2048_509        KEM = 0x0021
	NTRU_HPS_2048_677        KEM = 0x0022
	NTRU_HPS_4096_821        KEM = 0x0023
	NTRU_HRSS_701            KEM = 0x0024
	KYBER_512                KEM = 0x0025
	KYBER_768                KEM = 0x0026
	KYBER_1024               KEM = 0x0027
	SIKE_p434                KEM = 0x0028
	SIKE_p503                KEM = 0x0029
	SIKE_p610                KEM = 0x002A
	SIKE_p751                KEM = 0x002B
	SIKE_p434_compressed     KEM = 0x002C
	SIKE_p503_compressed     KEM = 0x002D
	SIKE_p610_compressed     KEM = 0x002E
	SIKE_p751_compressed     KEM = 0x002F
)

func (k KEM) String() string {
	switch k {
	case CLASSIC_MCELIECE_348864:
		return "Classic-McEliece-348864"
	case CLASSIC_MCELIECE_348864f:
		return "Classic-McEliece-348864f"
	case SABER_FIRESABER:
		return "FireSaber-KEM"
	case NTRU_HPS_2048_509:
		return "NTRU-HPS-2048-509"
	case NTRU_HPS_2048_677:
		return "NTRU-HPS-2048-677"
	case NTRU_HPS_4096_821:
		return "NTRU-HPS-4096-821"
	case NTRU_HRSS_701:
		return "NTRU-HRSS-701"
	case KYBER_512:
		return "Kyber512"
	case KYBER_768:
		return "Kyber768"
	case KYBER_1024:
		return "Kyber1024"
	case SIKE_p434:
		return "SIKE-p434"
	case SIKE_p434_compressed:
		return "SIKE-p434-compressed"
	case SIKE_p503:
		return "SIKE-p503"
	case SIKE_p503_compressed:
		return "SIKE-p503-compressed"
	case SIKE_p610:
		return "SIKE-p610"
	case SIKE_p610_compressed:
		return "SIKE-p610-compressed"
	case SIKE_p751:
		return "SIKE-p751"
	case SIKE_p751_compressed:
		return "SIKE-p751-compressed"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(k))
	}
}

// The payload size of the KEM for the KeyShare in bytes
func (k KEM) PayloadSize() int {
	switch k {
	case CLASSIC_MCELIECE_348864:
		return 4
	case CLASSIC_MCELIECE_348864f:
		// TODO FIX THIS TO BE CORRECT
		return 5
	case SABER_FIRESABER:
		return 1312
	case NTRU_HPS_2048_509:
		return 699
	case NTRU_HPS_2048_677:
		return 930
	case NTRU_HPS_4096_821:
		return 1230
	case NTRU_HRSS_701:
		return 1138
	case KYBER_512:
		return 800
	case KYBER_768:
		return 1184
	case KYBER_1024:
		return 1568
	case SIKE_p434:
		return 330
	case SIKE_p434_compressed:
		return 197
	case SIKE_p503:
		return 378
	case SIKE_p503_compressed:
		return 378
	case SIKE_p610:
		return 462
	case SIKE_p610_compressed:
		return 274
	case SIKE_p751_compressed:
		return 335
	default:
		return -1
	}
}

// KEMs returns all KEMs we implement
func KEMs() map[KEM]bool {
	return map[KEM]bool{
		CLASSIC_MCELIECE_348864:  false,
		CLASSIC_MCELIECE_348864f: false,
		SABER_FIRESABER:          true,
		NTRU_HPS_2048_509:        true,
		NTRU_HPS_2048_677:        true,
		NTRU_HPS_4096_821:        true,
		NTRU_HRSS_701:            true,
		KYBER_512:                true,
		KYBER_768:                true,
		KYBER_1024:               true,
	}
}

func DefaultKEMs() []KEM {
	return []KEM{
		NTRU_HPS_2048_509,
		NTRU_HPS_2048_677,
		NTRU_HPS_4096_821,
		NTRU_HRSS_701,
	}
}

func IsLibOQS(k KEM) bool {
	liboqs_kems := []KEM{CLASSIC_MCELIECE_348864, CLASSIC_MCELIECE_348864f, SABER_FIRESABER}
	for _, kem := range liboqs_kems {
		if kem == k {
			return true
		}
	}
	return false
}

type Keypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateKey(k KEM) (Keypair, error) {
	if IsLibOQS(k) {
		publicKey, privateKey, err := oqs.GetKeypair(k.String())
		if err != nil {
			return Keypair{nil, nil}, err
		}
		return Keypair{PublicKey: publicKey, PrivateKey: privateKey}, nil
	} else {
		return Keypair{nil, nil}, errors.New("KEM not implemented.")
	}
}

func Encapsulate(k KEM, publicKey []byte) ([]byte, []byte, error) {
	if IsLibOQS(k) {
		ciphertext, sharedSecret, err := oqs.Encapsulate(k.String(), publicKey)
		if err != nil {
			return nil, nil, err
		}
		return ciphertext, sharedSecret, nil
	} else {
		return nil, nil, errors.New("KEM not implemented.")
	}
}

func Decapsulate(k KEM, localKeypair Keypair, ciphertext []byte) ([]byte, error) {
	if IsLibOQS(k) {
		sharedSecret, err := oqs.Decapsulate(k.String(), localKeypair.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	} else {
		return nil, errors.New("KEM not implemented.")
	}
}
