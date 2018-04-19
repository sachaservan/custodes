package hypocert

import (
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

	r := random(party.Pk.N)
	enc := party.Pk.Encrypt(r)
	cMult := party.Pk.ECMult(c, r)

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	return enc, cMult
}

func (party *Party) GetRandomShare(bound *big.Int) *paillier.Ciphertext {

	r := random(bound)
	enc := party.Pk.Encrypt(r)

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	return enc
}

func (party *Party) GetRandomBitVector(l int) []*paillier.Ciphertext {

	v := make([]*paillier.Ciphertext, l)
	for i := 0; i < l; i++ {
		b := random(big2)
		v[i] = party.Pk.Encrypt(b)
	}

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	return v
}

func (party *Party) PartialDecrypt(ciphertext *paillier.Ciphertext) *paillier.PartialDecryption {

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	partial := party.Sk.Decrypt(ciphertext.C)
	return partial
}

func (party *Party) PartialDecryptAndProof(ciphertext *paillier.Ciphertext) *paillier.PartialDecryptionZKP {

	// simulate network latency
	time.Sleep(networkLatency * time.Millisecond)

	zkp, _ := party.Sk.DecryptAndProduceZKP(ciphertext.C)
	return zkp
}
