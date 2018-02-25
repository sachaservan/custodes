package secstat

import (
	"bgn"
	"fmt"
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
	share := mpc.RandomShare()
	res := mpc.Pk.EAddL2Elements(mpc.Pk.ToDeterministicL2Element(share), el)
	enc := mpc.Pk.EncryptDeterministic(mpc.DecryptElementMPC(res, true, false))
	return mpc.Pk.ESubElements(enc, share)
}

func (mpc *MPC) ReEncryptMPC(ct *bgn.Ciphertext) *bgn.Ciphertext {

	degree := len(ct.Coefficients)
	result := make([]*pbc.Element, degree)

	c := make(chan int, degree)

	for i, coeff := range ct.Coefficients {

		go func(i int, coeff *pbc.Element) {
			result[i] = mpc.ReEncryptElementMPC(coeff)
			c <- i
		}(i, coeff)
	}

	// wait for goroutines to finish
	for i := 0; i < degree; i++ {
		<-c
	}

	ctL1 := ct.Copy()
	ctL1.L2 = false
	ctL1.Coefficients = result
	return ctL1
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

// EModInvertElement computes the modular inverse of a (mod pk.T)
func (mpc *MPC) EModInvertElement(a *pbc.Element) *pbc.Element {

	for {
		b := mpc.RandomShare()
		c := mpc.DecryptElementMPC(mpc.Pk.EMultElements(a, b), true, false)

		if c.Int64() != 0 {
			cInv := big.NewInt(0).ModInverse(c, mpc.Pk.T)
			return mpc.Pk.EMultCElement(b, cInv)
		}
	}
}

func (mpc *MPC) IntegerDivisionMPC(a, b *pbc.Element) *pbc.Element {

	// convert a and b into bits
	numeratorBits := mpc.EIntegerToEBits(a)
	denomBits := mpc.EIntegerToEBits(b)

	fmt.Print("a_2 = ")
	for i := 0; i < len(numeratorBits); i++ {
		d := mpc.DecryptElementMPC(numeratorBits[len(numeratorBits)-i-1], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	fmt.Print("b_2 = ")
	for i := 0; i < len(denomBits); i++ {
		d := mpc.DecryptElementMPC(denomBits[len(denomBits)-i-1], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	// get the prefix or of the bits to get the encrypted bitlen (in binary)
	numeratorPreOR := mpc.EBitsPrefixOR(mpc.ReverseBits(numeratorBits))
	denomPreOr := mpc.EBitsPrefixOR(mpc.ReverseBits(denomBits))

	// get the bit length as an interger in Zn

	// sum the prefix-or results
	numeratorBitLen := mpc.Pk.EncryptDeterministic(big.NewInt(0))
	denomBitLen := mpc.Pk.EncryptDeterministic(big.NewInt(0))
	for i := 0; i < len(numeratorPreOR); i++ {
		numeratorBitLen = mpc.Pk.EAddElements(numeratorBitLen, numeratorPreOR[i])
		denomBitLen = mpc.Pk.EAddElements(denomBitLen, denomPreOr[i])
	}

	diffBits := mpc.EIntegerToEBits(mpc.Pk.ESubElements(numeratorBitLen, denomBitLen))

	// get the result of 2^diffBits
	quotientBitLen := mpc.EBitsExp(diffBits)

	fmt.Printf("[DEBUG]: Q is on the order of %d bits\n", mpc.DecryptElementMPC(quotientBitLen, false, false).Int64())

	// inverse of two mod T
	twoInverse := big.NewInt(0).ModInverse(big.NewInt(2), mpc.Pk.T)

	// add one to the bitlength
	upperBound := mpc.Pk.EMultCElement(quotientBitLen, big.NewInt(2))
	// subtract one from the bitlength
	lowerBound := mpc.Pk.EMultCElement(quotientBitLen, twoInverse)

	// current guess such that Q = (lowerBound + guess)
	guess := mpc.Pk.EncryptDeterministic(big.NewInt(0))

	// bits rep of lower bound to track overflow mod T
	resBitsLower := mpc.EBitsZero()

	// constant to avoid re-encrypting every time
	one := mpc.Pk.EncryptDeterministic(big.NewInt(1))
	two := mpc.Pk.EncryptDeterministic(big.NewInt(2))

	// can't divide by 2 when guess < 4 since
	// 3/2 not integer
	threshold := mpc.EBitsBigEndian(big.NewInt(4), mpc.Pk.T.BitLen())

	round := 0

	for {

		fmt.Printf("[DEBUG]: Round#: %d\n", round)
		fmt.Printf("[DEBUG]:Upper bound %d\n", mpc.DecryptElementMPC(upperBound, round > 0, false))
		fmt.Printf("[DEBUG]:Lower bound %d\n", mpc.DecryptElementMPC(lowerBound, round > 0, false))
		fmt.Printf("[DEBUG]: Guess %d\n", mpc.DecryptElementMPC(guess, round > 0, false))

		if round > mpc.Pk.T.BitLen() {
			return lowerBound
		}

		if round > 0 {
			// still level-1 ciphertexts at the first iteration
			upperBound = mpc.ReEncryptElementMPC(upperBound)
			lowerBound = mpc.ReEncryptElementMPC(lowerBound)
			guess = mpc.ReEncryptElementMPC(guess)
		}

		q := mpc.Pk.EAddElements(lowerBound, guess)

		result := mpc.Pk.EMultElements(b, q)
		resultBits := mpc.EIntegerToEBits(mpc.ReEncryptElementMPC(result))

		t1 := mpc.EBitsLessThan(resultBits, numeratorBits) // Q*b (mod T) < a (mod T)
		t2 := mpc.EBitsLessThan(resBitsLower, resultBits)  // Qb_0 (mod T) > Qb_i (mod T)

		if round == 0 {
			resBitsLower = resultBits
		}

		// take the AND of t1 and t2
		isLess := mpc.ReEncryptElementMPC(mpc.Pk.EMultElements(mpc.ReEncryptElementMPC(t1), mpc.ReEncryptElementMPC(t2)))
		notLess := mpc.Pk.ESubElements(one, isLess) // take NOT of isLess

		fmt.Printf("[DEBUG]: t1 bit: %d  t2 bit: %d\n", mpc.DecryptElementMPC(t1, true, true).Int64(), mpc.DecryptElementMPC(t2, true, true).Int64())

		// update the lower bound
		lowerBound = mpc.Pk.EAddL2Elements(mpc.Pk.EMultElements(lowerBound, notLess), mpc.Pk.EMultElements(q, isLess))

		// update the upper bound
		upperBound = mpc.Pk.EAddL2Elements(mpc.Pk.EMultElements(upperBound, isLess), mpc.Pk.EMultElements(q, notLess))

		// update the guess to be (upper - lower) / 2
		guess = mpc.Pk.ESubL2Elements(upperBound, lowerBound)
		guess = mpc.ReEncryptElementMPC(guess)

		// check if guess below threshold
		cmp := mpc.EBitsLessThan(mpc.EIntegerToEBits(guess), threshold)
		cmp = mpc.ReEncryptElementMPC(cmp)

		fmt.Printf("[DEBUG]: guess < threshold: %d\n", mpc.DecryptElementMPC(cmp, false, true).Int64())

		// condition 1: guess = (upperBound - lowerBound)/2
		guess1 := mpc.Pk.EMultCElement(guess, twoInverse)
		guess1 = mpc.Pk.EMultElements(guess1, mpc.Pk.ESubElements(one, cmp))

		// condition 2: guess = 2 since we want ceil(3/2)
		guess2 := mpc.Pk.EMultElements(two, cmp)

		// pick the correct guess
		guess = mpc.Pk.EAddL2Elements(guess1, guess2)

		if round+2 >= mpc.Pk.T.BitLen() {
			// on the next to last round, guess is 1 since we want ceil(1/2)
			guess = mpc.Pk.ToDeterministicL2Element(mpc.Pk.EncryptDeterministic(big.NewInt(1)))
		} else if round+1 >= mpc.Pk.T.BitLen() {
			// on the last round, guess is 0
			guess = mpc.Pk.ToDeterministicL2Element(mpc.Pk.EncryptDeterministic(big.NewInt(0)))
		}

		// keep chugging
		round++
	}
}

func (mpc *MPC) DecryptMPC(ct *bgn.Ciphertext) *bgn.Plaintext {

	partialDecryptions := make([]*PartialDecrypt, len(mpc.Parties))

	for index, party := range mpc.Parties {
		partialDecryptions[index] = party.PartialDecrypt(ct, mpc.Pk)
	}

	result := mpc.combineShares(ct, partialDecryptions, mpc.Pk)
	return result
}

func (mpc *MPC) DecryptElementMPC(ct *pbc.Element, l2 bool, bit bool) *big.Int {

	var csk, gsk *pbc.Element

	if l2 {
		csk, gsk = mpc.Parties[0].PartialDecryptElementL2(ct)

	} else {
		csk, gsk = mpc.Parties[0].PartialDecryptElement(ct)
	}

	n := len(mpc.Parties)
	partialCsks := make(chan *pbc.Element, n)
	partialGsks := make(chan *pbc.Element, n)

	for index, party := range mpc.Parties {

		if index == 0 {
			continue
		}

		go func(i int, party *Party) {

			if i > 0 {

				var csk, gsk *pbc.Element
				if l2 {
					csk, gsk = party.PartialDecryptElementL2(ct)

				} else {
					csk, gsk = party.PartialDecryptElement(ct)
				}

				partialCsks <- csk
				partialGsks <- gsk
			}

		}(index, party)
	}

	// wait for goroutines to finish
	for i := 1; i < n; i++ {
		cski := <-partialCsks
		gski := <-partialGsks

		csk.Mul(csk, cski)
		gsk.Mul(gsk, gski)
	}

	// if decrypting a bit, avoid DL alg
	if bit {
		zero := ct.NewFieldElement()
		if csk.Equals(zero) {
			return big.NewInt(0)
		}
		return big.NewInt(1)
	}

	result, err := mpc.Pk.RecoverMessageWithDL(gsk, csk, l2)
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
		Pk:           mpc.Pk,
		Coefficients: plaintextCoeffs,
		Degree:       size,
		ScaleFactor:  shares[0].ScaleFactor}

}

// NewMPCKeyGen generates a new public key and n shares of a secret key
func NewMPCKeyGen(numShares int, keyBits int, messageSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64, deterministic bool) (*bgn.PublicKey, *bgn.SecretKey, []*Party, error) {

	// generate standard key pair
	var sk *bgn.SecretKey

	pk, sk, err := bgn.NewKeyGen(keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, deterministic)

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
