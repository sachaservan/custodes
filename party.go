package hypocert

import (
	"crypto/rand"
	"log"
	"math/big"
	"paillier"
	"sync"
	"time"
)

const networkLatency = 0

// precomputed random shares
var randomShares []*paillier.Ciphertext
var partyShareMutex sync.Mutex
var partyShareIndex = 0
var precomputed = false

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
			randomShares[i] = party.GetRandomShare(party.Pk.N)
		}(i)
	}

	wg.Wait()

}

func (party *Party) GetRandomMultShare(c *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	r := newCryptoRandom(party.Pk.N)
	enc := party.Pk.EncryptInt(r)
	cMult := party.Pk.ECMult(c, r)

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	return enc, cMult
}

func (party *Party) GetRandomShare(bound *big.Int) *paillier.Ciphertext {

	if bound.BitLen() < party.Pk.S {
		bound = party.Pk.N
	}

	r := newCryptoRandom(bound)
	enc := party.Pk.EncryptInt(r)

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	return enc
}

func (party *Party) PartialDecrypt(ciphertext *paillier.Ciphertext) *paillier.PartialDecryption {

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	partial := party.Sk.Decrypt(ciphertext.C)
	return partial
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}
