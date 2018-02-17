package sbst

import (
	"bgn"
	"crypto/rand"
	"log"
	"math/big"

	"github.com/Nik-U/pbc"
)

type Party struct {
	SkShare *big.Int
	Pk      *bgn.PublicKey
}

type PartialDecrypt struct {
	Csks        []*pbc.Element
	Gsk         *pbc.Element
	Degree      int
	ScaleFactor int
}

type PartialDecryptElement struct {
	Csk *pbc.Element
	Gsk *pbc.Element
}

func (party *Party) getRandomShare() *pbc.Element {
	r := newCryptoRandom(party.Pk.N)
	enc := party.Pk.EncryptElement(r)
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

func (party *Party) PartialDecrypt(ct *bgn.Ciphertext, pk *bgn.PublicKey) *PartialDecrypt {

	if ct.L2 {
		return party.partialDecryptL2(ct, pk)
	}

	csks := make([]*pbc.Element, ct.Degree)

	gsk := pk.G1.NewFieldElement()
	gsk = gsk.PowBig(party.Pk.P, party.SkShare)

	for i, coeff := range ct.Coefficients {
		csk := pk.G1.NewFieldElement()
		csks[i] = csk.PowBig(coeff, party.SkShare)
	}

	return &PartialDecrypt{csks, gsk, ct.Degree, ct.ScaleFactor}
}

func (party *Party) partialDecryptL2(ct *bgn.Ciphertext, pk *bgn.PublicKey) *PartialDecrypt {

	csks := make([]*pbc.Element, ct.Degree)

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk = gsk.PowBig(gsk, party.SkShare)

	for i, coeff := range ct.Coefficients {
		csk := pk.Pairing.NewGT().NewFieldElement()
		csks[i] = csk.PowBig(coeff, party.SkShare)
	}

	return &PartialDecrypt{csks, gsk, ct.Degree, ct.ScaleFactor}
}

func (party *Party) PartialDecryptElement(el *pbc.Element) *PartialDecryptElement {

	gsk := party.Pk.G1.NewFieldElement()
	gsk = gsk.PowBig(party.Pk.P, party.SkShare)

	csk := party.Pk.G1.NewFieldElement()
	csk.PowBig(el, party.SkShare)

	return &PartialDecryptElement{csk, gsk}
}

func (party *Party) PartialDecryptElementL2(el *pbc.Element) *PartialDecryptElement {

	gsk := party.Pk.Pairing.NewGT().Pair(party.Pk.P, party.Pk.P)
	gsk.PowBig(gsk, party.SkShare)

	csk := el.NewFieldElement()
	csk.PowBig(el, party.SkShare)

	return &PartialDecryptElement{csk, gsk}
}
