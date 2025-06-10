package cryptoutils

import (
	"crypto/rand"
)

func GenerateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}
