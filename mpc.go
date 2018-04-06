package hypocert

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"paillier"
)

// Constants

var big2Inv *big.Int
var big2 *big.Int
var big1 *big.Int

type MPC struct {
	Parties []*Party
	Pk      *paillier.PublicKey
}

type MPCKeyGenParams struct {
	NumParties       int
	Threshold        int // decryption threshold
	KeyBits          int // at least 512 for Paillier
	MessageSpaceBits int // used for binary decomposition
	SecurityBits     int // at least 40 bits
	FPPrecisionBits  int
}

// PrecomputeData generates values needed ahead of time
// to speed up the online phase
func (mpc *MPC) PrecomputeData() {

	bitLen := mpc.Pk.T.BitLen()

	// TODO: calculate this value for better estimates of precomputation needs
	// arbitrary guess at the moment
	expectedNumRounds := 30 * int(math.Pow(float64(bitLen), 2))

	// compute the lagrange poly coeffs ahead of time
	mpc.computeBinaryFunctionCache(bitLen)

	fmt.Println("[DEBUG]: Finished computing Lagrange polynomials.")

	fmt.Println("[DEBUG]: Finished computing solved bits.")

	// precompute random shares for later use
	for _, party := range mpc.Parties {
		party.precomputeRandomShares(expectedNumRounds)
	}

	fmt.Println("[DEBUG]: Finished computing random shares.")

}

func (mpc *MPC) EMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	mask, val := mpc.RandomMultShare(a)

	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res.FPScaleFactor = a.FPScaleFactor + b.FPScaleFactor
	res = mpc.Pk.ESub(res, val)

	return res

}

func (mpc *MPC) IntegerDivisionRevealMPC(a, b *paillier.Ciphertext) *big.Int {

	// convert a and b into bits
	numeratorBits := mpc.EIntegerToEBits(a)
	denomBits := mpc.EIntegerToEBits(b)

	fmt.Print("a_2 = ")
	for i := 0; i < len(numeratorBits); i++ {
		d := mpc.Reveal(numeratorBits[len(numeratorBits)-i-1]).Value
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	fmt.Print("b_2 = ")
	for i := 0; i < len(denomBits); i++ {
		d := mpc.Reveal(denomBits[len(denomBits)-i-1]).Value
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	// get the prefix or of the bits to get the encrypted bitlen (in binary)
	numeratorPreOR := mpc.EBitsPrefixOR(mpc.ReverseBits(numeratorBits))
	denomPreOr := mpc.EBitsPrefixOR(mpc.ReverseBits(denomBits))

	// get the bit length as an interger in Zn

	// sum the prefix-or results
	numeratorBitLen := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))
	denomBitLen := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))
	for i := 0; i < len(numeratorPreOR); i++ {
		numeratorBitLen = mpc.Pk.EAdd(numeratorBitLen, numeratorPreOR[i])
		denomBitLen = mpc.Pk.EAdd(denomBitLen, denomPreOr[i])
	}

	diffBits := mpc.Pk.ESub(numeratorBitLen, denomBitLen)
	bitLen := mpc.Reveal(diffBits).Value

	precision := big.NewInt(4)
	scaleBack := big.NewInt(1)
	if bitLen.Cmp(precision) > 0 {
		scaleBack = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Sub(bitLen, precision), nil)
		mpc.Pk.ECMult(b, scaleBack)
		bitLen = precision
	}

	//fmt.Printf("[DEBUG]: Q is on the order of %d bits\n", mpc.Reveal(quotientBitLen, false, false).Int64())

	// add one to the bitlength
	upperBound := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Add(bitLen, big.NewInt(2)), nil)
	// subtract one from the bitlength
	lowerBound := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Sub(bitLen, big.NewInt(2)), nil)

	// current guess such that Q = (lowerBound + guess)
	guess := big.NewInt(0)
	guess.Sub(upperBound, lowerBound)
	guess.Div(guess.Add(guess, big.NewInt(1)), big.NewInt(2))

	// bits rep of lower bound to track overflow mod T
	//resBitsLower := mpc.EBitsZero()

	round := 0

	for {

		fmt.Printf("[DEBUG]: Round#: %d\n", round)
		fmt.Printf("[DEBUG]: Upper bound: %d\n", upperBound)
		fmt.Printf("[DEBUG]: Lower bound: %d\n", lowerBound)
		fmt.Printf("[DEBUG]: Current guess: %d\n", guess)

		if int64(round) > bitLen.Int64()+1 {
			return lowerBound.Mul(lowerBound, scaleBack)
		}

		q := big.NewInt(0).Add(lowerBound, guess)
		resultBits := mpc.EBitsMult(denomBits, mpc.EBitsBigEndian(q, len(denomBits)))

		t1 := mpc.EBitsLT(resultBits, numeratorBits) // Q*b (mod T) < a (mod T)
		// t2 := mpc.EBitsLT(resBitsLower, resultBits)  // Qb_0 (mod T) > Qb_i (mod T)

		// if round == 0 {
		// 	resBitsLower = resultBits
		// }

		// take the AND of t1 and t2
		isLess := mpc.Reveal(t1).Value.Int64()

		// update the lower bound
		if isLess == 1 {
			lowerBound.Add(lowerBound, guess)
		} else {
			// update the upper bound
			upperBound.Add(lowerBound, guess)
		}
		// update the guess to be (upper - lower) / 2
		guess.Sub(upperBound, lowerBound)
		guess.Div(guess.Add(guess, big.NewInt(1)), big.NewInt(2))

		// keep chugging
		round++
	}
}

func (mpc *MPC) IntegerDivisionMPC(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	// convert a and b into bits
	numeratorBits := mpc.EIntegerToEBits(a)
	denomBits := mpc.EIntegerToEBits(b)

	fmt.Print("a_2 = ")
	for i := 0; i < len(numeratorBits); i++ {
		d := mpc.Reveal(numeratorBits[len(numeratorBits)-i-1]).Value
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	fmt.Print("b_2 = ")
	for i := 0; i < len(denomBits); i++ {
		d := mpc.Reveal(denomBits[len(denomBits)-i-1]).Value
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	// get the prefix or of the bits to get the encrypted bitlen (in binary)
	numeratorPreOR := mpc.EBitsPrefixOR(mpc.ReverseBits(numeratorBits))
	denomPreOr := mpc.EBitsPrefixOR(mpc.ReverseBits(denomBits))

	// get the bit length as an interger in Zn

	// sum the prefix-or results
	numeratorBitLen := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))
	denomBitLen := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))
	for i := 0; i < len(numeratorPreOR); i++ {
		numeratorBitLen = mpc.Pk.EAdd(numeratorBitLen, numeratorPreOR[i])
		denomBitLen = mpc.Pk.EAdd(denomBitLen, denomPreOr[i])
	}

	diffBits := mpc.EIntegerToEBits(mpc.Pk.ESub(numeratorBitLen, denomBitLen))

	// get the result of 2^diffBits
	quotientBitLen := mpc.EBitsExp(diffBits)

	// inverse of two mod T
	twoInverse := big.NewInt(0).ModInverse(big.NewInt(2), mpc.Pk.N)

	// add one to the bitlength
	upperBound := mpc.Pk.ECMult(quotientBitLen, big.NewInt(2))
	// subtract one from the bitlength
	lowerBound := mpc.Pk.ECMult(quotientBitLen, twoInverse)

	// current guess such that Q = (lowerBound + guess)
	guess := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))

	// bits rep of lower bound to track overflow mod T
	resBitsLower := mpc.EBitsZero()

	// constant to avoid re-encrypting every time
	one := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(1.0)))
	two := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(2.0)))

	// can't divide by 2 when guess < 4 since
	// 3/2 not integer
	threshold := mpc.EBitsBigEndian(big.NewInt(4), mpc.Pk.N.BitLen())

	round := 0

	for {

		fmt.Printf("[DEBUG]: Round#: %d\n", round)
		fmt.Printf("[DEBUG]: Upper bound: %d\n", mpc.Reveal(upperBound).Value)
		fmt.Printf("[DEBUG]: Lower bound: %d\n", mpc.Reveal(lowerBound).Value)
		fmt.Printf("[DEBUG]: Current guess: %d\n", mpc.Reveal(guess).Value)

		if round > 7 {
			return lowerBound
		}

		q := mpc.Pk.EAdd(lowerBound, guess)

		result := mpc.EMult(b, q)
		resultBits := mpc.EIntegerToEBits(result)

		t1 := mpc.EBitsLT(resultBits, numeratorBits) // Q*b (mod T) < a (mod T)
		t2 := mpc.EBitsLT(resBitsLower, resultBits)  // Qb_0 (mod T) > Qb_i (mod T)

		if round == 0 {
			resBitsLower = resultBits
		}

		// take the AND of t1 and t2
		isLess := mpc.EMult(t1, t2)
		notLess := mpc.Pk.ESub(one, isLess) // take NOT of isLess

		//fmt.Printf("[DEBUG]: t1 bit: %d  t2 bit: %d\n", mpc.Reveal(t1, true, true).Int64(), mpc.Reveal(t2, true, true).Int64())

		// update the lower bound
		lowerBound = mpc.Pk.EAdd(mpc.EMult(lowerBound, notLess), mpc.EMult(q, isLess))

		// update the upper bound
		upperBound = mpc.Pk.EAdd(mpc.EMult(upperBound, isLess), mpc.EMult(q, notLess))

		// update the guess to be (upper - lower) / 2
		guess = mpc.Pk.ESub(upperBound, lowerBound)

		// check if guess below threshold
		cmp := mpc.EBitsLT(mpc.EIntegerToEBits(guess), threshold)

		//fmt.Printf("[DEBUG]: guess < threshold: %d\n", mpc.Reveal(cmp, false, true).Int64())

		// condition 1: guess = (upperBound - lowerBound)/2
		guess1 := mpc.Pk.ECMult(guess, twoInverse)
		guess1 = mpc.EMult(guess1, mpc.Pk.ESub(one, cmp))

		// condition 2: guess = 2 since we want ceil(3/2)
		guess2 := mpc.EMult(two, cmp)

		// pick the correct guess
		guess = mpc.Pk.EAdd(guess1, guess2)

		if round+2 >= mpc.Pk.T.BitLen() {
			// on the next to last round, guess is 1 since we want ceil(1/2)
			guess = mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(1.0)))

		} else if round+1 >= mpc.Pk.T.BitLen() {
			// on the last round, guess is 0
			guess = mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))
		}

		// keep chugging
		round++
	}
}

func (mpc *MPC) RevealInt(ciphertext *paillier.Ciphertext) *big.Int {

	partialDecrypts := make([]*paillier.PartialDecryption, len(mpc.Parties))
	for i := 0; i < len(mpc.Parties); i++ {
		partialDecrypts[i] = mpc.Parties[i].PartialDecrypt(ciphertext)
	}

	val, err := mpc.Parties[0].Sk.CombinePartialDecryptions(partialDecrypts)
	if err != nil {
		panic(err)
	}

	return val.Value
}

func (mpc *MPC) Reveal(ciphertext *paillier.Ciphertext) *paillier.Plaintext {

	partialDecrypts := make([]*paillier.PartialDecryption, len(mpc.Parties))
	for i := 0; i < len(mpc.Parties); i++ {
		partialDecrypts[i] = mpc.Parties[i].PartialDecrypt(ciphertext)
	}

	val, err := mpc.Parties[0].Sk.CombinePartialDecryptions(partialDecrypts)
	if err != nil {
		panic(err)
	}

	val.ScaleFactor = mpc.Pk.FPPrecBits
	return val
}

func NewMPCKeyGen(params *MPCKeyGenParams) *MPC {

	nu := big.NewInt(0).Binomial(int64(params.NumParties), int64(params.Threshold)).Int64()
	if int64(params.MessageSpaceBits+params.SecurityBits+params.FPPrecisionBits)+nu >= int64(params.KeyBits*2) {
		panic("modulus not big enough for given parameters")
	}

	if params.MessageSpaceBits <= params.FPPrecisionBits {
		panic("message space is smaller than the precision")
	}

	tkh := paillier.GetThresholdKeyGenerator(params.KeyBits, params.NumParties, params.Threshold, rand.Reader)
	tpks, err := tkh.Generate()
	pk := &tpks[0].PublicKey
	pk.T = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(params.MessageSpaceBits)), nil)
	pk.S = params.SecurityBits
	pk.K = params.MessageSpaceBits
	pk.FPPrecBits = params.FPPrecisionBits

	if err != nil {
		panic(err)
	}

	parties := make([]*Party, len(tpks))
	for i := 0; i < len(tpks); i++ {
		parties[i] = &Party{tpks[i], pk}
	}

	mpc := &MPC{parties, pk}

	// init constants

	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2Inv = big.NewInt(0).ModInverse(big2, pk.N)

	return mpc
}
