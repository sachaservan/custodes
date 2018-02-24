package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"runtime"
	"secstat"

	"github.com/Nik-U/pbc"
)

func main() {
	printWelcome()

	keyBits := 35 // length of q1 and q2
	polyBase := 3
	fpPrecision := 2

	// examplePearsonsTestSimulation(2, keyBits, polyBase, fpPrecision, true)
	//exampleTTestSimulation(2, keyBits, polyBase, fpPrecision, true)
	exampleMultiParty(2, keyBits, polyBase, fpPrecision)

}

func exampleMultiParty(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, parties, _ := secstat.NewMPCKeyGen(numParties, keyBits, polyBase, true)
	mpc := &secstat.MPC{parties, pk, sk}

	// // comp
	// m1 := bgn.NewPlaintext(big.NewFloat(3.0), pk.PolyBase)
	// m2 := bgn.NewPlaintext(big.NewFloat(3.0), pk.PolyBase)
	// c1 := pk.Encrypt(m1)
	// c2 := pk.Encrypt(m2)
	// c3 := pk.EAdd(c1, c2)
	// c4 := pk.EMult(c1, c2)

	// resultAdd := mpc.DecryptMPC(c3)
	// resultMult := mpc.DecryptMPC(c4)
	// c5 := mpc.ReEncryptMPC(c4)
	// c5 = pk.EMult(c5, c5)
	// c5 = pk.EMultC(c5, big.NewFloat(-1.0))
	// resultMult2 := mpc.DecryptMPC(c5)
	// c6 := mpc.ReEncryptMPC(c5)
	// resultMult3 := mpc.DecryptMPC(pk.EMult(c6, c6))

	one := pk.EncryptElement(big.NewInt(1))
	zero := pk.EncryptElement(big.NewInt(0))
	//two := pk.EncryptElement(big.NewInt(6))
	//bits2 := []*pbc.Element{two, two, two, two, two, two, two, two, two, two}

	//bitsa := []*pbc.Element{one, one, one, one, zero, one, zero, zero, zero, one}
	bitsb := []*pbc.Element{one, one, zero, zero, zero, zero, zero, zero, one}

	// bitsLT := mpc.EBitsLessThan(bitsa, bitsb)
	// d := mpc.DecryptElementMPC(bitsLT, true)
	// fmt.Printf("BitsLessThan: %d\n", d)

	mpc.ComputeLangragePolynomialCache(len(bitsb))
	runtime.GOMAXPROCS(100)

	// for {

	// 	// for i := range bitsb {
	// 	// 	j := newCryptoRandom(big.NewInt(int64(i + 1))).Int64()
	// 	// 	bitsb[i], bitsb[j] = bitsb[j], bitsb[i]
	// 	// }

	// 	// for i := 0; i < len(bitsb); i++ {
	// 	// 	d := mpc.DecryptElementMPC(bitsb[i], false, false)
	// 	// 	fmt.Printf("%d", d)
	// 	// }
	// 	// fmt.Println()

	// 	// bits := mpc.EBitsPrefixOR(bitsb)
	// 	// for i := 0; i < len(bits); i++ {
	// 	// 	d := mpc.DecryptElementMPC(bits[i], false, false)
	// 	// 	fmt.Printf("%d", d)
	// 	// }
	// 	// fmt.Println("\n")

	// 	r := newCryptoRandom(pk.T)
	// 	bits := mpc.EBits(mpc.Pk.EncryptDeterministic(r))

	// 	acc := big.NewInt(0)
	// 	pow := big.NewInt(2)
	// 	for i := 0; i < len(bits); i++ {
	// 		d := mpc.DecryptElementMPC(bits[len(bits)-i-1], false, false)
	// 		fmt.Printf("%d", d)

	// 		acc.Mul(acc, pow)
	// 		acc.Add(acc, d)
	// 	}
	// 	fmt.Printf("_2 = %d >> %d\n", r, acc)

	// 	if r.Cmp(acc) != 0 {
	// 		panic("bit decomposition failed!")
	// 	}

	// }

	a := big.NewInt(4004) // mod 15551
	b := big.NewInt(15)
	Q := big.NewInt(0).Div(a, b)
	result := mpc.IntegerDivisionMPC(pk.EncryptElement(a), pk.EncryptElement(b))
	fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + result.String())
	fmt.Println("Actual: " + a.String() + "/" + b.String() + " = " + Q.String())

	// print results
	// fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultAdd.String())
	// fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultMult.String())
	// fmt.Printf("MPCEMULT E(%s) ⊠ E(%s*(-1)) = E(%s)\n\n", resultMult.String(), resultMult.String(), resultMult2.String())
	// fmt.Printf("MPCEMULT E(%s) ⊠ E(%s) = E(%s)\n\n", resultMult2.String(), resultMult2.String(), resultMult3.String())
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
	fmt.Println(" _    _                    _____          _  ")
	fmt.Println("| |  | |                  / ____|        | |  ")
	fmt.Println("| |__| |_   _ _ __   ___ | |     ___ _ __| |_ ")
	fmt.Println("|  __  | | | | '_ \\ / _ \\| |    / _ \\ '__| __|")
	fmt.Println("| |  | | |_| | |_) | (_) | |___|  __/ |  | |_ ")
	fmt.Println("|_|  |_|\\__, | .__/ \\___/ \\_____\\___|_|   \\__|")
	fmt.Println("	 __/ | |                              ")
	fmt.Println("	|___/|_|                           ")
	fmt.Println("Secure Statistical Testing")
	fmt.Println("=====================================")

}
