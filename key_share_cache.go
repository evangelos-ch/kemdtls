package dtls

import (
	"sync"

	"github.com/pion/dtls/v2/pkg/crypto/kem"
)

type keyShareCache struct {
	cache map[kem.KEM]*kem.Keypair
	mu    sync.Mutex
}

func newKeyShareCache() *keyShareCache {
	return &keyShareCache{
		cache: make(map[kem.KEM]*kem.Keypair),
	}
}

func (c *keyShareCache) push(k kem.KEM, keypair *kem.Keypair) bool { //nolint
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[k] = keypair
	return true
}

func (c *keyShareCache) pull(k kem.KEM) *kem.Keypair {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache[k]
}
