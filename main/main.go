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

	runtime.GOMAXPROCS(10000)

	// TO RUN BENCHMARKS:

	// 1) CHANGE THE ROOT DIR
	ROOTDIR := "/home/azuka/go/src/hypocert"

	// 2) SET THE NUMBER OF PARTIES (2, 4, 8)
	NUMPARTIES := 2 //x2

	// 3) NETWORK LATENCY
	NETWORKLATENCY := time.Duration(0) //ms

	/* 1000 row dataset */
	filename1000 := ROOTDIR + "/benchmark/benchmark_1000.csv"

	/* 1000 row dataset, 10 categories */
	filenameChiSq1000_10 := ROOTDIR + "/benchmark/benchmark_chisq_1000_10.csv"

	/* 1000 row dataset, 25 categories */
	filenameChiSq1000_25 := ROOTDIR + "/benchmark/benchmark_chisq_1000_25.csv"

	/* 1000 row dataset, 50 categories */
	filenameChiSq1000_50 := ROOTDIR + "/benchmark/benchmark_chisq_1000_50.csv"

	/************************************************************************/

	/* 5000 row dataset */
	filename5000 := ROOTDIR + "/benchmark/benchmark_5000.csv"

	/* 5000 row dataset, 10 categories */
	filenameChiSq5000_10 := ROOTDIR + "/benchmark/benchmark_chisq_5000_10.csv"

	/* 5000 row dataset, 25 categories */
	filenameChiSq5000_25 := ROOTDIR + "/benchmark/benchmark_chisq_5000_25.csv"

	/* 5000 row dataset, 50 categories */
	filenameChiSq5000_50 := ROOTDIR + "/benchmark/benchmark_chisq_5000_50.csv"

	/************************************************************************/

	/* 10000 row dataset */
	filename10000 := ROOTDIR + "/benchmark/benchmark_10000.csv"

	/* 10000 row dataset, 10 categories */
	filenameChiSq10000_10 := ROOTDIR + "/benchmark/benchmark_chisq_10000_10.csv"

	/* 10000 row dataset, 25 categories */
	filenameChiSq10000_25 := ROOTDIR + "/benchmark/benchmark_chisq_10000_25.csv"

	/* 10000 row dataset, 50 categories */
	filenameChiSq10000_50 := ROOTDIR + "/benchmark/benchmark_chisq_10000_50.csv"

	/************************************************************************/

	runTTestBechmarks(filename1000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runTTestBechmarks(filename5000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runTTestBechmarks(filename10000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)

	runPearsonsBechmarks(filename1000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runPearsonsBechmarks(filename5000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runPearsonsBechmarks(filename10000, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)

	runChiSqBechmarks(filenameChiSq1000_10, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq1000_25, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq1000_50, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq5000_10, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq5000_25, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq5000_50, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq10000_10, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq10000_25, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)
	runChiSqBechmarks(filenameChiSq10000_50, NUMPARTIES, NETWORKLATENCY*time.Millisecond, false, false)

	runMultBenchmark(NUMPARTIES, 0*time.Millisecond, false, false)

}

func runChiSqBechmarks(filename string, threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	mpc := hypocert.NewMPCKeyGen(params)

	//**************************************************************************************
	//**************************************************************************************
	// Chi-Squared Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Chi^2 Test...")
	fmt.Println("------------------------------------------------")

	hypocert.MultCountPaillier = 0
	hypocert.MultCountShares = 0
	chi2test, numRows, numCategories, totalTime, paillierTime, divTime, numSharesCreated := exampleChiSquaredSimulation(mpc, filename, debug)

	fmt.Println("************************************************")
	fmt.Println("Chi^2 p-value:                    " + chi2test.String())
	fmt.Printf("Dataset size:                    %d\n", numRows)
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
}

func runTTestBechmarks(filename string, threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	mpc := hypocert.NewMPCKeyGen(params)

	//**************************************************************************************
	//**************************************************************************************
	// T Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

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

}

func runPearsonsBechmarks(filename string, threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	mpc := hypocert.NewMPCKeyGen(params)

	//**************************************************************************************
	//**************************************************************************************
	// Pearson's Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

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

}

func runMultBenchmark(threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * threshold,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	mpc := hypocert.NewMPCKeyGen(params)

	//**************************************************************************************
	//**************************************************************************************
	// Multiplication Benchmark
	//**************************************************************************************
	//**************************************************************************************

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
