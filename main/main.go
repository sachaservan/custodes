package main

import (
	"fmt"
	"hypocert"
	"runtime"
	"time"
)

func main() {
	printWelcome()

	runtime.GOMAXPROCS(10000)

	runBenchmark(2, 0*time.Millisecond, false, false)
	runBenchmark(4, 0*time.Millisecond, false, false)
	runBenchmark(8, 0*time.Millisecond, false, false)
	runBenchmark(16, 0*time.Millisecond, false, false)
	//runBenchmark(8, 0*time.Millisecond, true, false)

	// runBenchmark(8)
	// runBenchmark(16)
	// runBenchmark(32)

	// params := &hypocert.MPCKeyGenParams{
	// 	NumParties:      3,
	// 	Threshold:       2,
	// 	KeyBits:         512,
	// 	MessageBits:     84,
	// 	SecurityBits:    40,
	// 	FPPrecisionBits: 20,
	// }

	// exampleMultiParty(params)
}

func runBenchmark(threshold int, latency time.Duration, zkp bool, debug bool) {

	params := &hypocert.MPCKeyGenParams{
		NumParties:      2*threshold - 1,
		Threshold:       threshold,
		Verify:          zkp,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  latency}

	// fmt.Println("------------------------------------------------")
	// fmt.Println("Running Chi^2 Test...")
	// fmt.Println("------------------------------------------------")

	// chi2test, datasetSize, totalTime, paillierTime, divTime, numSharesCreated := exampleChiSquaredSimulation(params, "/home/azuka/Desktop/age_sex.csv", debug)

	// fmt.Println("************************************************")
	// fmt.Println("Chi^2 p-value:                " + chi2test.String())
	// fmt.Printf("Dataset size:                %d\n", datasetSize)
	// fmt.Printf("Number of parties:          %d\n", 2*threshold)
	// fmt.Printf("Zero-Knowledge Proofs:      %t\n", zkp)
	// fmt.Printf("Total number of shares:     %d\n", numSharesCreated)
	// fmt.Printf("Pearson's Test runtime (s): %f\n", totalTime.Seconds())
	// fmt.Printf("  Computation runtime (s):  %f\n", paillierTime.Seconds())
	// fmt.Printf("  Division runtime (s):     %f\n", divTime.Seconds())

	// fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated := exampleTTestSimulation(params, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("T-Test p-value:              " + ttest.String())
	fmt.Printf("Dataset size:                %d\n", datasetSize)
	fmt.Printf("Number of parties:           %d\n", 2*threshold)
	fmt.Printf("Zero-Knowledge Proofs:       %t\n", zkp)
	fmt.Printf("Total number of shares:      %d\n", numSharesCreated)
	fmt.Printf("T-Test runtime (s): 	     %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):   %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):      %f\n", divTime.Seconds())
	fmt.Println("************************************************")

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	ptest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated := examplePearsonsTestSimulation(params, "/home/azuka/Desktop/age_sex.csv", debug)

	fmt.Println("************************************************")
	fmt.Println("Pearson's p-value:             " + ptest.String())
	fmt.Printf("Dataset size:                 %d\n", datasetSize)
	fmt.Printf("Number of parties:            %d\n", 2*threshold)
	fmt.Printf("Zero-Knowledge Proofs:        %t\n", zkp)
	fmt.Printf("Total number of shares:       %d\n", numSharesCreated)
	fmt.Printf("Pearson's Test runtime (s):   %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):    %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):       %f\n", divTime.Seconds())

	fmt.Println("************************************************")

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
