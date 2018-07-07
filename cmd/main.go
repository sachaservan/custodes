package main

import (
	"flag"
	"fmt"
	"hypocert"
	"math/big"
	"runtime"
	"time"
)

func main() {
	printWelcome()

	// Command line arguments
	rootDirCmd := flag.String("rootdir", "", "full path to project dir.")
	numPartiesCmd := flag.Int("parties", 3, "integer number of parties >= 3.")
	thresholdCmd := flag.Int("threshold", 2, "integer number of parties >= 2.")
	networkLatencyCmd := flag.Int("netlat", 0, "average network latency for party communication.")
	debugCmd := flag.Bool("debug", false, "print debug statements during computation.")
	useSharesCmd := flag.Bool("lss", false, "use only linear secret sharing for computations.")

	flag.Parse()

	// extract the passed in arguments
	rootDir := *rootDirCmd
	numParties := *numPartiesCmd
	threshold := *thresholdCmd
	networkLatency := time.Duration(*networkLatencyCmd)
	debug := *debugCmd
	useShares := *useSharesCmd

	// ensure threshsold is ok
	if numParties < 2*threshold-1 {
		panic("Threshold is too high compared to the number of parties!")
	}

	// number of cores
	runtime.GOMAXPROCS(2 * numParties)

	// system parameters
	params := &hypocert.MPCKeyGenParams{
		NumParties:      numParties,
		Threshold:       threshold,
		Verify:          false,
		KeyBits:         512,
		MessageBits:     100,
		SecurityBits:    40,
		FPPrecisionBits: 50,
		NetworkLatency:  networkLatency * time.Millisecond}

	fmt.Print("System setup in progress...")
	mpc := hypocert.NewMPCKeyGen(params)
	fmt.Println("done.")

	// filenames to use for the statistical test computations
	filename1000 := rootDir + "/cmd/files/benchmark_1000.csv"
	filenameChiSq1000_5 := rootDir + "/cmd/files/benchmark_chisq_1000_5.csv"
	filenameChiSq1000_10 := rootDir + "/cmd/files/benchmark_chisq_1000_10.csv"
	filenameChiSq1000_20 := rootDir + "/cmd/files/benchmark_chisq_1000_20.csv"

	/* Student's t-test */
	runTTestBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, useShares, debug)

	/* Pearson's correlation test */
	runPearsonsBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, useShares, debug)

	/* Chi-squared test */
	runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, false, useShares, debug)
	runChiSqBechmarks(mpc, filenameChiSq1000_10, numParties, networkLatency*time.Millisecond, false, useShares, debug)
	runChiSqBechmarks(mpc, filenameChiSq1000_20, numParties, networkLatency*time.Millisecond, false, useShares, debug)
}

func runChiSqBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool) {

	//**************************************************************************************
	//**************************************************************************************
	// Chi-Squared Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Chi^2 Test...")
	fmt.Println("------------------------------------------------")

	var chi2test *big.Float
	var datasetSize int
	var numCategories int
	var dealerSetupTime time.Duration
	var totalTime time.Duration
	var paillierTime time.Duration
	var divTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		chi2test, datasetSize, numCategories, dealerSetupTime, totalTime, paillierTime, divTime, numSharesCreated = exampleChiSquaredSimulationWithSecretSharing(mpc, filename, debug)
	} else {
		chi2test, datasetSize, numCategories, totalTime, paillierTime, divTime, numSharesCreated = exampleChiSquaredSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("Chi^2 statistic:                    " + chi2test.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of categories:            %d\n", numCategories)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Dealer setup time (s): 	         %f\n", dealerSetupTime.Seconds())
	fmt.Printf("Chi^2 Test runtime (s):          %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")
}

func runTTestBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool) {

	//**************************************************************************************
	//**************************************************************************************
	// T Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	var ttest *big.Float
	var datasetSize int
	var dealerSetupTime time.Duration
	var totalTime time.Duration
	var paillierTime time.Duration
	var divTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		ttest, datasetSize, dealerSetupTime, totalTime, paillierTime, divTime, numSharesCreated = exampleTTestSimulationWithSecretSharing(mpc, filename, debug)
	} else {
		ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated = exampleTTestSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("T-Test statistic:                   " + ttest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	fmt.Printf("Total number of shares:      	 %d\n", numSharesCreated)
	fmt.Printf("Dealer setup time (s): 	         %f\n", dealerSetupTime.Seconds())
	fmt.Printf("T-Test runtime (s): 	         %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")

}

func runPearsonsBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool) {

	//**************************************************************************************
	//**************************************************************************************
	// Pearson's Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	var ptest *big.Float
	var datasetSize int
	var dealerSetupTime time.Duration
	var totalTime time.Duration
	var computeTime time.Duration
	var divTime time.Duration
	var cmpTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		ptest, datasetSize, dealerSetupTime, totalTime, computeTime, cmpTime, divTime, numSharesCreated = examplePearsonsTestSimulationWihSecretSharing(mpc, filename, debug)
	} else {
		ptest, datasetSize, totalTime, computeTime, cmpTime, divTime, numSharesCreated = examplePearsonsTestSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("Pearson's statistic:                " + ptest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Dealer setup time (s): 	         %f\n", dealerSetupTime.Seconds())
	fmt.Printf("Pearson's Test runtime (s):      %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", computeTime.Seconds())
	fmt.Printf("  Comparison runtime (s):        %f\n", cmpTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
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
	fmt.Println()
	fmt.Println("Certified Hypothesis Testing")
	fmt.Println("=====================================")
	fmt.Println("DISCLAIMER: this software if intended for simulation and proof-of-concept purposes only.")
	fmt.Println("=====================================")

}
