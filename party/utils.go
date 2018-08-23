package party

import (
	"crypto/rand"
	"math/big"
)

// generates a new random number < max
func CryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}

	return rand
}
