package node

import (
	"math/big"
	"time"

	"github.com/sachaservan/paillier"
)

func (party *Party) GetRandomMultEnc(c *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {
	time.Sleep(party.DebugLatency)

	r := paillier.CryptoRandom(party.P)
	enc := party.Pk.Encrypt(r)
	cMult := party.Pk.ECMult(c, r)

	return enc, cMult
}

func (party *Party) GetRandomEncAndShare(id int, bound *big.Int) (*paillier.Ciphertext, *Share) {
	time.Sleep(party.DebugLatency)

	r := paillier.CryptoRandom(bound)
	enc := party.Pk.Encrypt(r)
	shares, values, _ := party.CreateShares(r, id)
	party.DistributeRandShares(shares, values)

	return enc, shares[party.ID]
}

func (party *Party) GetRandomEncBitVector(m int) []*paillier.Ciphertext {
	time.Sleep(party.DebugLatency)

	vec := make([]*paillier.Ciphertext, m)
	for i := 0; i < m; i++ {
		bit := paillier.CryptoRandom(big.NewInt(2))
		vec[i] = party.Pk.Encrypt(bit)
	}

	return vec
}

func (party *Party) GetRandomEnc(bound *big.Int) *paillier.Ciphertext {
	time.Sleep(party.DebugLatency)

	r := paillier.CryptoRandom(bound)
	enc := party.Pk.Encrypt(r)
	return enc
}

func (party *Party) PartialDecrypt(ciphertext *paillier.Ciphertext) *paillier.PartialDecryption {
	time.Sleep(party.DebugLatency)

	partial := party.Sk.Decrypt(ciphertext.C)
	return partial
}

func (party *Party) PartialDecryptAndProof(ciphertext *paillier.Ciphertext) *paillier.PartialDecryptionZKP {
	time.Sleep(party.DebugLatency)

	zkp, _ := party.Sk.DecryptAndProduceZKP(ciphertext.C)

	return zkp
}
