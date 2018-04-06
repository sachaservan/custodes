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

	runtime.GOMAXPROCS(10000)

	keyGenParams := &hypocert.MPCKeyGenParams{
		NumParties:       2,
		Threshold:        2,
		KeyBits:          512,
		MessageSpaceBits: 32,
		SecurityBits:     40,
		FPPrecisionBits:  10,
	}

	//examplePearsonsTestSimulation(numParties, keyBits, messageSpaceBits, securityBits, polyBase, fpScaleBase, fpPrecision, true)
	//exampleTTestSimulation(numParties, keyBits, messageSpaceBits, polyBase, securityBits, fpScaleBase, fpPrecision, true)
	exampleMultiParty(keyGenParams)
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

func exampleMultiParty(keyGenParams *hypocert.MPCKeyGenParams) {

	mpc := hypocert.NewMPCKeyGen(keyGenParams)

	fmt.Println("Generated keys")

	d := big.NewFloat(9.0)
	c := mpc.Pk.EncryptInt(mpc.Pk.EncodeFixedPoint(d, mpc.Pk.FPPrecBits))

	startTime := time.Now()
	v := mpc.EFPReciprocal(c)

	endTime := time.Now()
	log.Println("Runtime: " + endTime.Sub(startTime).String())
	fmt.Println("Using div protocol: " + mpc.Reveal(v).String())
	fmt.Println("Actual: " + big.NewFloat(0).Quo(big.NewFloat(1.0), d).String())

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
