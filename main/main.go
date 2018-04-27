package main

import (
	"fmt"
	"hypocert"
	"log"
	"math/big"
	"runtime"
	"time"
)

func main() {
	// printWelcome()

	runtime.GOMAXPROCS(10000)

	//runBenchmark(2, false, false)
	// runBenchmark(2, true, false)
	// runBenchmark(4, false, false)
	// runBenchmark(4, true, false)
	// runBenchmark(8, false, false)
	// runBenchmark(8, true, false)

	// runBenchmark(8)
	// runBenchmark(16)
	// runBenchmark(32)

	keyGenParams := &hypocert.MPCKeyGenParams{
		NumParties:      3,
		Threshold:       2,
		KeyBits:         32,
		MessageBits:     10,
		SecurityBits:    0,
		FPPrecisionBits: 10,
	}

	exampleMultiParty(keyGenParams)
}

func runBenchmark(numParties int, zkp bool, debug bool) {

	keyGenParams := &hypocert.MPCKeyGenParams{
		NumParties:      numParties,
		Threshold:       numParties,
		Verify:          zkp,
		KeyBits:         128,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
	}

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	ttest, runtimeTtest := exampleTTestSimulation(keyGenParams, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("T-Test p-value:              " + ttest.String())
	fmt.Printf("Number of parties:        %d\n", numParties)
	fmt.Printf("Zero-Knowledge Proofs:    %t\n", zkp)
	fmt.Printf("T-Test runtime (s): 	  %f\n", runtimeTtest.Seconds())
	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	ptest, runtimePtest := examplePearsonsTestSimulation(keyGenParams, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("Pearson's p-value:            " + ptest.String())
	fmt.Printf("Number of parties:          %d\n", numParties)
	fmt.Printf("Zero-Knowledge Proofs:      %t\n", zkp)
	fmt.Printf("Pearson's Test runtime (s): %f\n", runtimePtest.Seconds())
	fmt.Println("************************************************")

}

func exampleMultiParty(keyGenParams *hypocert.MPCKeyGenParams) {

	mpc := hypocert.NewMPCKeyGen(keyGenParams)
	fmt.Println("Generated keys")

	shares, id := mpc.CreateShares(big.NewInt(4))
	startTime := time.Now()

	mpc.DistributeShares(shares)

	newId := mpc.MultShares(id, id)

	s := mpc.RevealShare(newId)
	log.Println("Runtime: " + time.Now().Sub(startTime).String())

	fmt.Println("re: " + s.String())

	// a := big.NewFloat(1000)
	// b := big.NewFloat(65532)

	// encoa := mpc.Pk.EncodeFixedPoint(a, mpc.Pk.FPPrecBits)
	// encob := mpc.Pk.EncodeFixedPoint(b, mpc.Pk.FPPrecBits)

	// ea := mpc.Pk.Encrypt(encoa)
	// eb := mpc.Pk.Encrypt(encob)

	// startTime := time.Now()

	// rcpr := mpc.EFPDivision(ea, eb)

	// endTime := time.Now()
	// log.Println("Runtime: " + endTime.Sub(startTime).String())
	// fmt.Println("Using div protocol: " + mpc.RevealFP(rcpr, mpc.Pk.FPPrecBits).String())
	// fmt.Println("Actual: " + big.NewFloat(0).Quo(a, b).String())
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
