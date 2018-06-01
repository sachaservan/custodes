package main

import (
	"fmt"
	"hypocert"
	"math/big"
	"runtime"
	"time"
)

func main() {
	printWelcome()

	// TODO: change accordingly
	filename := "/home/azuka/Desktop/age_sex.csv"

	runtime.GOMAXPROCS(10000)

	runBenchmark(filename, 2, 0*time.Millisecond, false, true)
	runBenchmark(filename, 4, 0*time.Millisecond, false, false)
	runBenchmark(filename, 8, 0*time.Millisecond, false, false)
	runBenchmark(filename, 16, 0*time.Millisecond, false, false)

	// FOR QUICK TESTS
	// params := &hypocert.MPCKeyGenParams{
	// 	NumParties:      3,
	// 	Threshold:       2,
	// 	Verify:          false,
	// 	KeyBits:         512,
	// 	MessageBits:     64,
	// 	SecurityBits:    40,
	// 	FPPrecisionBits: 20,
	// 	NetworkLatency:  0}

	// mpc := hypocert.NewMPCKeyGen(params)

	// share0 := mpc.CreateShares(big.NewInt(1095941025))
	// share1 := mpc.CreateShares(big.NewInt(1173973248))
	// div := mpc.FPDivision(share0, share1)
	// fmt.Println("Div: " + mpc.RevealShareFP(div, mpc.Pk.FPPrecBits).String())

}

func runBenchmark(filename string, threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 40,
		NetworkLatency:  latency}

	mpc := hypocert.NewMPCKeyGen(params)

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Chi^2 Test...")
	fmt.Println("------------------------------------------------")

	hypocert.MultCountPaillier = 0
	hypocert.MultCountShares = 0
	chi2test, numCategories, totalTime, paillierTime, divTime, numSharesCreated := exampleChiSquaredSimulation(mpc, filename, debug)

	fmt.Println("************************************************")
	fmt.Println("Chi^2 p-value:                    " + chi2test.String())
	fmt.Printf("Dataset size:                    N/A")
	fmt.Printf("Number of categories:            %d\n", numCategories)
	fmt.Printf("Number of parties:               %d\n", 2*threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("Chi^2 Test runtime (s):     %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):  %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):     %f\n", divTime.Seconds())

	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	hypocert.MultCountPaillier = 0
	hypocert.MultCountShares = 0
	ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated := exampleTTestSimulation(mpc, filename, debug)

	fmt.Println("************************************************")
	fmt.Println("T-Test p-value:                   " + ttest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", 2*threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:      	 %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("T-Test runtime (s): 	         %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	hypocert.MultCountPaillier = 0
	hypocert.MultCountShares = 0
	ptest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated := examplePearsonsTestSimulation(mpc, filename, debug)

	fmt.Println("************************************************")
	fmt.Println("Pearson's p-value:                " + ptest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", 2*threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("Pearson's Test runtime (s):      %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())

	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Benchmarking Multiplication times...")
	fmt.Println("------------------------------------------------")

	a := mpc.Pk.Encrypt(big.NewInt(1))
	b := mpc.Pk.Encrypt(big.NewInt(1))
	ashare := mpc.CreateShares(big.NewInt(1))
	bshare := mpc.CreateShares(big.NewInt(1))

	multTimePaillier := time.Duration(0)
	multTimeShares := time.Duration(0)

	for i := 0; i < 1000; i++ {
		stime := time.Now()
		mpc.EMult(a, b)
		endTime := time.Now()
		multTimePaillier += endTime.Sub(stime)
	}

	for i := 0; i < 1000; i++ {
		stime := time.Now()
		mpc.Mult(ashare, bshare)
		endTime := time.Now()
		multTimeShares += endTime.Sub(stime)
	}

	fmt.Printf("Paillier MULT time: %f\n", +float64(multTimePaillier.Nanoseconds())/(1000000.0*1000.0))
	fmt.Printf("Shares MULT time:   %f\n", +float64(multTimeShares.Nanoseconds())/(1000000.0*1000.0))

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
