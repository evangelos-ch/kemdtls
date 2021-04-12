package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/kem"
)

func TestExtensionKeyShare(t *testing.T) {
	// TODO ADJUST FOR REAL KEY
	rawExtensionKeyShare := []byte{
		0x00, 0x33,
		0x00, 0x0f,
		0x00, 0x0d,
		0x00, 0x1e, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x1f, 0x01, 0x02, 0x03, 0x04, 0x05,
	}
	parsedExtensionKeyShare := &KeyShare{
		KeyShareEntries: []KeyShareEntry{
			{kem.CLASSIC_MCELIECE_348864, []byte{0x01, 0x02, 0x03, 0x04}},
			{kem.CLASSIC_MCELIECE_348864f, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		},
	}

	// Marshal
	raw, err := parsedExtensionKeyShare.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawExtensionKeyShare) {
		t.Errorf("extensionKeyShare marshal: got %#v\n want %#v", raw, rawExtensionKeyShare)
	}

	// Umarashal
	keyShare := &KeyShare{
		KeyShareEntries: make([]KeyShareEntry, 0),
	}
	unmarshalErr := keyShare.Unmarshal(rawExtensionKeyShare)
	if err != nil {
		t.Error(unmarshalErr)
	} else if !reflect.DeepEqual(keyShare, parsedExtensionKeyShare) {
		t.Errorf("extensionKeyShare unmarshal: got %#v, want %#v", keyShare, parsedExtensionKeyShare)
	}
}
