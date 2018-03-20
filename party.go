package secstat

import (
	"crypto/rand"
	"log"
	"math/big"
	"paillier"
	"sync"
)

// precomputed random shares
var randomShares []*paillier.Ciphertext
var partyShareMutex sync.Mutex
var partyShareIndex = 0

type Party struct {
	Sk *paillier.ThresholdPrivateKey
	Pk *paillier.PublicKey
}

type PartialDecrypt struct {
	Csks        []*paillier.Ciphertext
	Gsk         *paillier.Ciphertext
	Degree      int
	ScaleFactor int
}

type PartialDecryptElement struct {
	Csk *paillier.Ciphertext
	Gsk *paillier.Ciphertext
}

func (party *Party) precomputeRandomShares(n int) {

	var wg sync.WaitGroup
	randomShares = make([]*paillier.Ciphertext, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			randomShares[i] = party.GetRandomShare(false)
		}(i)
	}

	wg.Wait()

}

func (party *Party) GetRandomMultShare(c *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	r := newCryptoRandom(party.Pk.N)
	enc := party.Pk.EncryptInt(r)
	cMult := party.Pk.ECMult(c, r)
	return enc, cMult
}

func (party *Party) GetRandomShare(precomputed bool) *paillier.Ciphertext {

	// try to get a precomputed random share if possible
	if precomputed {
		partyShareMutex.Lock()
		if randomShares != nil && partyShareIndex > len(randomShares) {
			var share *paillier.Ciphertext
			share = randomShares[partyShareIndex]
			partyShareIndex++
			partyShareMutex.Unlock()
			return share
		}
		partyShareMutex.Unlock()
	}

	r := newCryptoRandom(party.Pk.N)
	enc := party.Pk.EncryptInt(r)
	return enc
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

func (party *Party) PartialDecrypt(ciphertext *paillier.Ciphertext) *paillier.PartialDecryption {
	return party.Sk.Decrypt(ciphertext.C)
}
