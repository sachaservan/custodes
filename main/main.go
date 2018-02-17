package main

import (
	"bgn"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sbst"

	"github.com/Nik-U/pbc"
)

func main() {
	printWelcome()

	keyBits := 35 // length of q1 and q2
	polyBase := 3
	fpPrecision := 2

	exampleMultiParty(2, keyBits, polyBase, fpPrecision)
	// examplePearsonsTestSimulation(2, keyBits, polyBase, fpPrecision, true)
	// exampleTTestSimulation(2, keyBits, polyBase, fpPrecision, true)
}

func exampleMultiParty(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, parties, _ := sbst.NewMPCKeyGen(numParties, keyBits, polyBase, true)
	mpc := &sbst.MPC{parties, pk, sk}

	// comp
	m1 := bgn.NewPlaintext(big.NewFloat(3.0), pk.PolyBase)
	m2 := bgn.NewPlaintext(big.NewFloat(3.0), pk.PolyBase)
	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMult(c1, c2)

	resultAdd := mpc.DecryptMPC(c3)
	resultMult := mpc.DecryptMPC(c4)
	c5 := mpc.ReEncryptMPC(c4)
	c5 = pk.EMult(c5, c5)
	c5 = pk.EMultC(c5, big.NewFloat(-1.0))
	resultMult2 := mpc.DecryptMPC(c5)
	c6 := mpc.ReEncryptMPC(c5)
	resultMult3 := mpc.DecryptMPC(pk.EMult(c6, c6))

	// one := pk.EncryptElement(big.NewInt(1))
	// zero := pk.EncryptElement(big.NewInt(0))

	// bitsa := []*pbc.Element{zero, zero, one, one, zero, zero, zero, zero, zero, one}
	// bitsb := []*pbc.Element{one, zero, zero, one, zero, zero, one, one, one, one}

	// bitsLT := mpc.EBitsLessThan(bitsa, bitsb)
	// d := mpc.DecryptElementMPC(bitsLT, true)
	// fmt.Printf("BitsLessThan: %d\n", d)

	// bs := mpc.EBitsOR(bitsb)
	// d = mpc.DecryptElementMPC(bs, false)
	// fmt.Printf("BitsOR %d\n", d)

	// fmt.Println("Bit prefix product:")
	// bits := mpc.EFanInMult(bitsb)
	// for i := 0; i < len(bits); i++ {
	// 	d = mpc.DecryptElementMPC(bits[i], false)
	// 	fmt.Printf("%d", d)
	// }

	// fmt.Println()

	// bitsSum := mpc.EBitsSum(bitsa, bitsb)
	// fmt.Println("Bits SUM:")

	// for i := 0; i < len(bitsSum); i++ {
	// 	d := mpc.DecryptElementMPC(bitsSum[i], false)
	// 	fmt.Printf("%d", d)
	// }
	// fmt.Println()

	// for {
	// 	fmt.Println("Bits Decompose:")
	// 	zn := big.NewInt(newCryptoRandom(pk.T).Int64())
	// 	decomposed := mpc.EBits(pk.EncryptElement(zn))
	// 	fmt.Print(zn.String() + "_2 = ")
	// 	for i := 0; i < len(decomposed); i++ {
	// 		d := mpc.DecryptElementMPC(decomposed[i], false)
	// 		fmt.Printf("%d", d)
	// 	}
	// 	fmt.Println()
	// }

	a := big.NewInt(1019)
	b := big.NewInt(99)
	Q := big.NewInt(0).Div(a, b)
	result := divbabydiv(mpc, pk.EncryptElement(a), pk.EncryptElement(b))
	fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + result.String())
	fmt.Println("Actual: " + a.String() + "/" + b.String() + " = " + Q.String())

	// print results
	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultAdd.String())
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultMult.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s*(-1)) = E(%s)\n\n", resultMult.String(), resultMult.String(), resultMult2.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s) = E(%s)\n\n", resultMult2.String(), resultMult2.String(), resultMult3.String())
}

func divbabydiv(mpc *sbst.MPC, a, b *pbc.Element) *big.Int {

	da := mpc.EBits(a)
	db := mpc.EBits(b)

	// 	fmt.Print(zn.String() + "_2 = ")
	// 	for i := 0; i < len(decomposed); i++ {
	// 		d := mpc.DecryptElementMPC(decomposed[i], false)
	// 		fmt.Printf("%d", d)
	// 	}
	// 	fmt.Println()

	daprefix := mpc.EBitsPreOR(mpc.ReverseBits(da))
	dbprefix := mpc.EBitsPreOR(mpc.ReverseBits(db))

	fmt.Print("a_2 = ")
	for i := 0; i < len(da); i++ {
		d := mpc.DecryptElementMPC(da[i], false, true)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	fmt.Print("b_2 = ")
	for i := 0; i < len(da); i++ {
		d := mpc.DecryptElementMPC(db[i], false, true)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	bitlena := mpc.Pk.EncryptElement(big.NewInt(0))
	bitlenb := mpc.Pk.EncryptElement(big.NewInt(0))

	fmt.Print("PREORa_2 = ")
	for i := 0; i < len(daprefix); i++ {
		d := mpc.DecryptElementMPC(daprefix[i], false, true)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	fmt.Print("PREORb_2 = ")
	for i := 0; i < len(dbprefix); i++ {
		d := mpc.DecryptElementMPC(dbprefix[i], false, true)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	// sum the prefix
	for i := 0; i < len(daprefix); i++ {
		bitlena = mpc.Pk.EAddElements(bitlena, daprefix[i])
		bitlenb = mpc.Pk.EAddElements(bitlenb, dbprefix[i])
	}

	diff := mpc.Pk.ESubElements(bitlena, bitlenb)
	d := mpc.DecryptElementMPC(diff, false, false)
	fmt.Printf("[DEBUG]: Q is on the order of %d bits\n", d)

	upper := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Add(d, big.NewInt(1)), nil)
	lower := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Sub(d, big.NewInt(1)), nil)
	guess := big.NewInt(0).Sub(upper, lower)
	guess.Div(guess, big.NewInt(2))
	round := int64(0)

	res := mpc.Pk.EMultCElement(b, big.NewInt(0).Add(lower, guess))
	resBits := mpc.EBits(res)
	resBitsPrev := mpc.EBitsZero()

	for {

		fmt.Printf("Round#: %d\n", round)

		fmt.Println("Upper bound " + upper.String())
		fmt.Println("Lower bound " + lower.String())
		fmt.Println("Guess " + guess.String())

		if round == d.Int64()+1 || upper.Cmp(lower) < 0 {
			res := big.NewInt(0).Add(upper, lower)
			return res.Div(res, big.NewInt(2))
		}

		res = mpc.Pk.EMultCElement(b, big.NewInt(0).Add(lower, guess))
		resBits = mpc.EBits(res)
		la := mpc.EBitsLessThan(resBits, da) // Qb < a (mod T)
		gb := mpc.EBitsLessThan(resBitsPrev, resBits)
		bitLess := mpc.Pk.EMultElements(mpc.ReEncryptElementMPC(la), mpc.ReEncryptElementMPC(gb))
		isLess := mpc.DecryptElementMPC(bitLess, true, true).Int64()
		resBitsPrev = resBits

		fmt.Printf("bit %d current res is %d\n", isLess, mpc.DecryptElementMPC(res, false, false))
		if isLess == 1 {
			lower = big.NewInt(0).Add(lower, guess)
			lower.Sub(lower, big.NewInt(1))
		} else {
			upper = big.NewInt(0).Add(lower, guess)
			upper.Add(upper, big.NewInt(1))
		}

		guess = big.NewInt(0).Sub(upper, lower)
		guess.Div(guess, big.NewInt(2))

		round++

		est := big.NewInt(0).Sub(upper, lower)
		est.Div(est, big.NewInt(2))
		fmt.Println("Current estimate: Q=" + est.String())
	}

	return nil
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

func printWelcome() {
	fmt.Println("=====================================")
	fmt.Println("	  _____ ____   _____ _______")
	fmt.Println("	 / ____|  _ \\ / ____|__   __|")
	fmt.Println("	 | (___| |_) | (___    | |")
	fmt.Println("	 \\___ \\|  _ < \\___ \\   | |")
	fmt.Println("	 ____) | |_) |____) |  | |")
	fmt.Println("	|_____/|____/|_____/   |_|")
	fmt.Println("Secure Blockchain Statistical Testing")
	fmt.Println("=====================================")

}
