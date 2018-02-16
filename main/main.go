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

	exampleMultiParty(5, keyBits, polyBase, fpPrecision)
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

	// bitsa := []*pbc.Element{one, zero, one, one, zero, zero, zero}
	// bitsb := []*pbc.Element{one, zero, zero, one, zero, zero, zero}

	// bitsLT := mpc.EBitsLessThan(bitsa, bitsb)
	// d := mpc.DecryptElementMPC(bitsLT, true)
	// fmt.Printf("BitsLessThan: %d\n", d)

	// bs := mpc.EBitsOR(bitsb)
	// d := mpc.DecryptElementMPC(bs, false)
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

	// fmt.Println("Bits Decompose:")
	// zn := big.NewInt(1020)
	// decomposed := mpc.EBitsDecompose(pk.EncryptElement(zn), 10, pk.T)
	// fmt.Print(zn.String() + "_2 = ")
	// for i := 0; i < len(decomposed); i++ {
	// 	d := mpc.DecryptElementMPC(decomposed[i], false)
	// 	fmt.Printf("%d", d)
	// }
	// fmt.Println()

	a := big.NewInt(500)
	b := big.NewInt(100)
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

	n := 10

	da := mpc.EBitsDecompose(a, n, mpc.Pk.T)
	db := mpc.EBitsDecompose(b, n, mpc.Pk.T)
	daprefix := mpc.EBitsPrefixOR(mpc.ReverseBits(da))
	dbprefix := mpc.EBitsPrefixOR(mpc.ReverseBits(db))

	// fmt.Println("prefixor a")
	// for i := 0; i < len(daprefix); i++ {
	// 	d := mpc.DecryptElementMPC(daprefix[i], false)
	// 	fmt.Printf("%d", d)
	// }
	// fmt.Println()

	// fmt.Println("prefixor b")
	// for i := 0; i < len(dbprefix); i++ {
	// 	d := mpc.DecryptElementMPC(dbprefix[i], false)
	// 	fmt.Printf("%d", d)
	// }
	// fmt.Println()

	bitlena := mpc.Pk.EncryptElement(big.NewInt(0))
	bitlenb := mpc.Pk.EncryptElement(big.NewInt(0))

	// sum the prefix
	for i := 0; i < len(daprefix); i++ {
		bitlena = mpc.Pk.EAddElements(bitlena, daprefix[i])
		bitlenb = mpc.Pk.EAddElements(bitlenb, dbprefix[i])
	}

	diff := mpc.Pk.ESubElements(bitlena, bitlenb)
	d := mpc.DecryptElementMPC(diff, false)
	fmt.Printf("Q is on the order of %d bits\n", d)

	upper := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Add(d, big.NewInt(1)), nil)
	lower := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(0).Sub(d, big.NewInt(1)), nil)
	guess := big.NewInt(0).Add(upper, lower)
	guess.Div(guess, big.NewInt(2))
	round := int64(0)

	for {

		if round == d.Int64() || upper.Cmp(lower) < 0 {
			res := big.NewInt(0).Add(upper, lower)
			return res.Div(res, big.NewInt(2))
		}

		res := mpc.Pk.ESubElements(a, mpc.Pk.EMultCElement(b, guess, true))
		resBits := mpc.EBitsDecompose(res, n, mpc.Pk.T)
		bitLess := mpc.EBitsLessThan(resBits, da)
		isLess := mpc.DecryptElementMPC(bitLess, true).Int64()

		if isLess == 1 {
			lower.Add(lower, guess).Sub(lower, big.NewInt(1))
		} else {
			upper.Add(lower, guess).Add(upper, big.NewInt(1))
		}

		guess = big.NewInt(0).Add(upper, lower)
		guess.Div(guess, big.NewInt(2))

		round++

		est := big.NewInt(0).Add(upper, lower)
		est.Div(est, big.NewInt(2))
		fmt.Printf("Round#: %d\n", round)
		fmt.Println("Current estimate: Q=" + est.String())

		fmt.Println("Upper bound " + upper.String())
		fmt.Println("Lower bound " + lower.String())

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
