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

	runBenchmark(2, 0*time.Millisecond, false, false)
	// runBenchmark(2, true, false)
	// runBenchmark(4, false, false)
	// runBenchmark(4, true, false)
	// runBenchmark(8, false, false)
	// runBenchmark(8, true, false)

	// runBenchmark(8)
	// runBenchmark(16)
	// runBenchmark(32)

	// params := &hypocert.MPCKeyGenParams{
	// 	NumParties:      4,
	// 	Threshold:       2,
	// 	KeyBits:         128,
	// 	MessageBits:     64,
	// 	SecurityBits:    40,
	// 	FPPrecisionBits: 20,
	// }

	//exampleMultiParty(params)
}

func runBenchmark(threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         128,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	ttest, runtimeTtest := exampleTTestSimulation(params, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("T-Test p-value:              " + ttest.String())
	fmt.Printf("Number of parties:        %d\n", 2*threshold)
	fmt.Printf("Zero-Knowledge Proofs:    %t\n", zkp)
	fmt.Printf("T-Test runtime (s): 	  %f\n", runtimeTtest.Seconds())
	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	ptest, runtimePtest := examplePearsonsTestSimulation(params, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("Pearson's p-value:            " + ptest.String())
	fmt.Printf("Number of parties:          %d\n", 2*threshold)
	fmt.Printf("Zero-Knowledge Proofs:      %t\n", zkp)
	fmt.Printf("Pearson's Test runtime (s): %f\n", runtimePtest.Seconds())
	fmt.Println("************************************************")

}

func exampleMultiParty(keyGenParams *hypocert.MPCKeyGenParams) {

	mpc := hypocert.NewMPCKeyGen(keyGenParams)

	ct := mpc.Pk.Encrypt(big.NewInt(13))

	share := mpc.PaillierToShare(ct)

	fmt.Println("Converted share: " + mpc.RevealShare(share).String())

	share0 := mpc.CreateShares(big.NewInt(10))
	share1 := mpc.CreateShares(big.NewInt(5))
	share2 := mpc.CreateShares(big.NewInt(1))
	share3 := mpc.CreateShares(big.NewInt(0))

	startTime := time.Now()

	fmt.Println("share0: " + mpc.RevealShare(share0).String())
	fmt.Println("share1: " + mpc.RevealShare(share1).String())
	fmt.Println("share2: " + mpc.RevealShare(share2).String())
	fmt.Println("share3: " + mpc.RevealShare(share3).String())

	// res := mpc.Add(share0, share1)
	a := mpc.Mult(share0, share1)

	fmt.Println("a: " + mpc.RevealShare(a).String())

	fmt.Println("share0: " + mpc.RevealShare(share0).String())
	fmt.Println("share1: " + mpc.RevealShare(share1).String())

	// b := mpc.Mult(a, share1)

	// fmt.Println("a: " + mpc.RevealShare(b).String())

	r4 := mpc.TruncPR(share1, mpc.Pk.K, 3)
	fmt.Println("r: " + mpc.RevealShare(r4).String())

	for {
		v := mpc.FPDivision(share0, share1)
		fmt.Println("v: " + mpc.RevealShareFP(v, mpc.Pk.FPPrecBits).String())

		// bits := mpc.EBitsDec(share1, mpc.Pk.K)

		// for i := len(bits) - 1; i >= 0; i-- {
		// 	s := mpc.RevealShare(bits[i])
		// 	fmt.Print(s.String())
		// }

		// fmt.Println()
	}

	fmt.Println()
	log.Println("Runtime: " + time.Now().Sub(startTime).String())

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
