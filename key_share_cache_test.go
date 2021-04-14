package dtls

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/kem"
)

func TestKeyShare(t *testing.T) {
	cache := newKeyShareCache()
	key1 := []byte{0x1, 0x2, 0x3, 0x4}
	key1p := []byte{0x1, 0x2, 0x3, 0x3}
	key2 := []byte{0x1, 0x2, 0x3, 0x4, 0x5}
	key2p := []byte{0x1, 0x2, 0x3, 0x4, 0x3}
	cache.push(kem.CLASSIC_MCELIECE_348864, &kem.Keypair{PublicKey: key1, PrivateKey: key1p})
	cache.push(kem.CLASSIC_MCELIECE_348864f, &kem.Keypair{PublicKey: key2, PrivateKey: key2p})
	if !reflect.DeepEqual(cache.pull(kem.CLASSIC_MCELIECE_348864), &kem.Keypair{PublicKey: key1, PrivateKey: key1p}) {
		t.Errorf("Got back the wrong key from the cache, expected %#v got %#v", cache.pull(kem.CLASSIC_MCELIECE_348864), key1)
	}
	if !reflect.DeepEqual(cache.pull(kem.CLASSIC_MCELIECE_348864f), &kem.Keypair{PublicKey: key2, PrivateKey: key2p}) {
		t.Errorf("Got back the wrong key from the cache, expected %#v got %#v", cache.pull(kem.CLASSIC_MCELIECE_348864f), key2)
	}
	if cache.pull(65534) != nil {
		t.Error("Result of non-existent KEM isn't nil.")
	}
}
