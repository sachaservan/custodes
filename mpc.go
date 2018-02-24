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

	var result []*pbc.Element
	degree := len(ct.Coefficients)
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

func (mpc *MPC) IntegerDivisionMPC(a, b *pbc.Element) *big.Int {

	da := mpc.EBits(a)
	db := mpc.EBits(b)

	daprefix := mpc.EBitsPrefixOR(mpc.ReverseBits(da))
	dbprefix := mpc.EBitsPrefixOR(mpc.ReverseBits(db))

	fmt.Print("a_2 = ")
	for i := 0; i < len(da); i++ {
		d := mpc.DecryptElementMPC(da[len(da)-i-1], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	fmt.Print("b_2 = ")
	for i := 0; i < len(da); i++ {
		d := mpc.DecryptElementMPC(db[len(da)-i-1], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println("_2")

	bitlena := mpc.Pk.EncryptElement(big.NewInt(0))
	bitlenb := mpc.Pk.EncryptElement(big.NewInt(0))

	fmt.Print("PREORa_2 = ")
	for i := 0; i < len(daprefix); i++ {
		d := mpc.DecryptElementMPC(daprefix[i], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	fmt.Print("PREORb_2 = ")
	for i := 0; i < len(dbprefix); i++ {
		d := mpc.DecryptElementMPC(dbprefix[i], false, false)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	// sum the prefix
	for i := 0; i < len(daprefix); i++ {
		bitlena = mpc.Pk.EAddElements(bitlena, daprefix[i])
		bitlenb = mpc.Pk.EAddElements(bitlenb, dbprefix[i])
	}

	diff := mpc.Pk.ESubElements(bitlena, bitlenb)
	qBits := mpc.DecryptElementMPC(diff, false, false)
	fmt.Printf("[DEBUG]: Q is on the order of %d bits\n", qBits)

	upper := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Add(qBits, big.NewInt(1)), nil)
	lower := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Sub(qBits, big.NewInt(1)), nil)
	guess := big.NewInt(0)

	round := 0

	resBitsLower := mpc.EBitsZero()

	for {

		fmt.Printf("Round#: %d\n", round)

		fmt.Println("Upper bound " + upper.String())
		fmt.Println("Lower bound " + lower.String())
		fmt.Println("Guess " + guess.String())

		if round > mpc.Pk.T.BitLen() {
			res := big.NewInt(0).Add(upper, lower)
			return res.Div(res, big.NewInt(2))
		}

		res := mpc.Pk.EMultCElement(b, big.NewInt(0).Add(lower, guess))
		resBits := mpc.EBits(res)
		fmt.Printf("RES%d (15*%d)= ", round, big.NewInt(0).Add(lower, guess))
		for i := 0; i < len(resBits); i++ {
			d := mpc.DecryptElementMPC(resBits[len(resBits)-i-1], false, false)
			fmt.Printf("%d", d)
		}
		fmt.Println("_2")

		la := mpc.EBitsLessThan(resBits, da)           // Qb (mod T) < a (mod T)
		gb := mpc.EBitsLessThan(resBitsLower, resBits) // Qb_0 (mod T) > Qb_i (mod T)

		if round == 0 {
			resBitsLower = resBits
		}

		bitLess := mpc.Pk.EMultElements(mpc.ReEncryptElementMPC(la), mpc.ReEncryptElementMPC(gb))
		isLess := mpc.DecryptElementMPC(bitLess, true, true).Int64()

		fmt.Printf("la bit: %d  gb bit: %d\n", mpc.DecryptElementMPC(la, true, true).Int64(), mpc.DecryptElementMPC(gb, true, true).Int64())

		if isLess == 1 {
			lower = big.NewInt(0).Add(lower, guess)
			resBitsLower = resBits

		} else {
			upper = big.NewInt(0).Add(lower, guess)
		}

		guess = big.NewInt(0).Sub(upper, lower)
		guess.Div(guess, big.NewInt(2))

		round++

		est := big.NewInt(0).Sub(upper, lower)
		est.Div(est, big.NewInt(2))
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
		Coefficients: plaintextCoeffs,
		Degree:       size,
		Base:         pk.PolyBase,
		ScaleFactor:  shares[0].ScaleFactor}

}

// NewMPCKeyGen generates a new public key and n shares of a secret key
func NewMPCKeyGen(numShares int, keyBits int, polyBase int, deterministic bool) (*bgn.PublicKey, *bgn.SecretKey, []*Party, error) {

	// generate standard key pair
	var sk *bgn.SecretKey

	// some primes:
	// 269 --- 8 bits
	// 1021 --- not square!
	// 15551 --- not square!
	// 100043 --- not square!
	// 16427 --- 15 bits
	// 32797 --- 16 bits
	// 16777633 ---25 bits

	pk, sk, err := bgn.NewKeyGen(keyBits, big.NewInt(15551), polyBase, deterministic)

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
