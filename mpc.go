package sbst

import (
	"bgn"
	"math/big"

	"github.com/Nik-U/pbc"
)

type MPC struct {
	Parties []*Party
	Pk      *bgn.PublicKey
	Sk      *bgn.SecretKey
}

type MPCRequest struct {
	Ct *bgn.Ciphertext
}

type MPCResponse struct {
	PartialCt   *bgn.Ciphertext
	PartialRand *bgn.Ciphertext
}

type MPCReceptacle struct {
	Ct   *bgn.Ciphertext
	Rand *bgn.Ciphertext
}

// ReEncryptElementMPC is a wrapper function that converts an element to a ciphertext
// and executes the re-encryption protocol
func (mpc *MPC) ReEncryptElementMPC(el *pbc.Element) *pbc.Element {
	ct := bgn.NewCiphertext([]*pbc.Element{el}, 1, 0, true)
	return mpc.ReEncryptMPC(ct).Coefficients[0]
}

func (mpc *MPC) ReEncryptMPC(ct *bgn.Ciphertext) *bgn.Ciphertext {

	var result *MPCReceptacle

	for i := 0; i < len(mpc.Parties); i++ {
		res := mpc.requestMPCReEncryption(ct)

		if result == nil {
			result = &MPCReceptacle{Ct: res.PartialCt, Rand: res.PartialRand}
		} else {
			mpc.Pk.EAdd(result.Ct, res.PartialCt)

			for k := 0; k < len(res.PartialRand.Coefficients); k++ {
				result.Rand.Coefficients[k] = mpc.Pk.EAddElements(result.Rand.Coefficients[k],
					res.PartialRand.Coefficients[k])
			}
		}
	}

	plaintext := mpc.DecryptMPC(result.Ct)
	reEncrypt := mpc.Pk.Encrypt(plaintext)

	return mpc.Pk.EAdd(reEncrypt, mpc.Pk.AInv(result.Rand))
}

func (mpc *MPC) requestMPCReEncryption(ct *bgn.Ciphertext) *MPCResponse {

	randCt := ct.Copy()
	rand := &bgn.Ciphertext{make([]*pbc.Element, randCt.Degree), randCt.Degree, randCt.ScaleFactor, false}

	for i := 0; i < len(randCt.Coefficients); i++ {
		randVal := mpc.Pk.EncryptElement(newCryptoRandom(mpc.Pk.N))
		randCt.Coefficients[i] = mpc.Pk.EAddL2Elements(randCt.Coefficients[i], mpc.Pk.ToDeterministicL2Element(randVal))
		rand.Coefficients[i] = randVal
	}

	return &MPCResponse{randCt, rand}
}

func (mpc *MPC) DecryptMPC(ct *bgn.Ciphertext) *bgn.Plaintext {

	partialDecryptions := make([]*PartialDecrypt, len(mpc.Parties))

	for index, party := range mpc.Parties {
		partialDecryptions[index] = party.PartialDecrypt(ct, mpc.Pk)
	}

	result := mpc.combineShares(ct, partialDecryptions, mpc.Pk)
	return result
}

func (mpc *MPC) DecryptElementMPC(ct *pbc.Element, l2 bool) *big.Int {

	var res *PartialDecryptElement

	if l2 {
		res = mpc.Parties[0].PartialDecryptElementL2(ct)

	} else {
		res = mpc.Parties[0].PartialDecryptElement(ct)

	}

	partial := res

	for index, party := range mpc.Parties {

		if index == 0 {
			continue
		}

		if l2 {
			res = party.PartialDecryptElementL2(ct)

		} else {
			res = party.PartialDecryptElement(ct)
		}

		partial.Csk.Mul(partial.Csk, res.Csk)
		partial.Gsk = partial.Gsk.Mul(partial.Gsk, res.Gsk)
	}

	result, err := mpc.Pk.RecoverMessageWithDL(partial.Gsk, partial.Csk, l2)
	if err != nil {
		panic("unable to decrypt ciphertext")
	}
	return result
}

func (mpc *MPC) combineShares(ct *bgn.Ciphertext, shares []*PartialDecrypt, pk *bgn.PublicKey) *bgn.Plaintext {

	if len(shares) < 1 {
		panic("Number of shares to combine must be >= 1")
	}

	size := shares[0].Degree // assume all partial decrypts will have same number of coeffs (they should)
	csks := make([]*pbc.Element, size)

	for i := 0; i < size; i++ {
		csks[i] = shares[0].Csks[i].NewFieldElement()
		csks[i].Set(shares[0].Csks[i])
	}

	gsk := shares[0].Gsk.NewFieldElement()
	gsk.Set(shares[0].Gsk)

	for index, share := range shares {

		if index == 0 {
			continue
		}

		for i := 0; i < size; i++ {
			csks[i].Mul(csks[i], share.Csks[i])
		}

		gsk.Mul(gsk, share.Gsk)
	}

	plaintextCoeffs := make([]int64, size)

	for i := 0; i < size; i++ {

		pt, err := mpc.Pk.RecoverMessageWithDL(gsk, csks[i], true)
		if err != nil {
			panic(err)
		}

		plaintextCoeffs[i] = pk.DecodeSign(pt).Int64()

	}

	return &bgn.Plaintext{
		Coefficients: plaintextCoeffs,
		Degree:       size,
		Base:         pk.PolyBase,
		ScaleFactor:  shares[0].ScaleFactor}

}

// NewMPCKeyGen generates a new public key and n shares of a secret key
func NewMPCKeyGen(numShares int, keyBits int, polyBase int, deterministic bool) (*bgn.PublicKey, *bgn.SecretKey, []*Party, error) {

	// generate standard key pair
	var sk *bgn.SecretKey
	//15010109923
	pk, sk, err := bgn.NewKeyGen(keyBits, big.NewInt(1021), polyBase, deterministic)

	if err != nil {
		return nil, nil, nil, err
	}

	// secret key shares (i.e. parties)
	var parties []*Party

	// TODO: Redo this correctly, totally wrong right now.
	// max value of each share (no bigger than sk/n)
	max := big.NewInt(0).Div(sk.Key, big.NewInt(int64(numShares)))

	// sum of all the shares
	sum := big.NewInt(0)

	// compute shares
	for i := 0; i < numShares-1; i++ {
		// create new random share
		next := newCryptoRandom(max)
		parties = append(parties, &Party{next, pk})
		sum.Add(sum, next)
	}

	// last share should be computed so as to
	// have all shares add up to sk
	last := sum.Sub(sk.Key, sum)
	parties = append(parties, &Party{last, pk})

	return pk, sk, parties, err
}
