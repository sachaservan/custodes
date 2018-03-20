package main

import (
	"crypto/rand"
	"fmt"
	"hypocert"
	"log"
	"math/big"
	"runtime"
	"time"
)

func main() {
	printWelcome()

	// Some primes for message space:
	// 269 					---  8 bits
	// 1021 				--- 10 bits
	// 15551 				--- 14 bits
	// 16427 				--- 15 bits
	// 32797 				--- 16 bits
	// 100043 				--- 17 bits
	// 16777633 			--- 25 bits
	// 1073741833 			--- 30 bits
	// 1099511628323 		--- 40 bits

	numParties := 2
	keyBits := 128 // length of q1 and q2
	messageSpace, err := rand.Prime(rand.Reader, 64)
	if err != nil {
		panic("unable to generate message space prime!")
	}

	polyBase := 3
	fpScaleBase := 3
	fpPrecision := 0.0001

	runtime.GOMAXPROCS(10000)

	//examplePearsonsTestSimulation(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	exampleTTestSimulation(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	//exampleMultiParty(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision)

}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

func exampleMultiParty(numParties int, keyBits int, messageSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64) {

	mpc := hypocert.NewMPCKeyGen(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision)
	pk := mpc.Pk

	//bitsa := mpc.EBitsBigEndian(big.NewInt(11), pk.T.BitLen())
	// bitsb := mpc.EBitsBigEndian(big.NewInt(10), pk.T.BitLen())

	// for {

	// 	ints := big.NewInt(101)

	// 	bitsa := mpc.EIntegerToEBits(pk.EncryptInt(ints))
	// 	fmt.Print("bitsa: ")
	// 	for i := len(bitsa) - 1; i >= 0; i-- {
	// 		fmt.Print(mpc.DecryptMPC(bitsa[i]).String())
	// 	}
	// 	fmt.Println("_2 = " + ints.String())

	// }

	startTime := time.Now()
	a := big.NewInt(121124)
	b := big.NewInt(12)
	Q := big.NewInt(0).Div(a, b)
	result := mpc.IntegerDivisionMPC(pk.EncryptInt(a), pk.EncryptInt(b))
	endTime := time.Now()
	fmt.Printf("T bits %d, runtime = %s\n", mpc.Pk.T.BitLen(), endTime.Sub(startTime).String())
	log.Println("Runtime: " + endTime.Sub(startTime).String())
	//fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + mpc.DecryptElementMPC(result, true, false).String())
	fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + mpc.DecryptMPC(result).String())
	fmt.Println("Actual: " + a.String() + "/" + b.String() + " = " + Q.String())

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
	fmt.Println("Secure Hypothesis Testing")
	fmt.Println("=====================================")

}
