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
	example := flag.Bool("example", false, "run an examples of all three statistical tests.")
	rootDirCmd := flag.String("rootdir", "", "full path to project dir where datasets are located.")
	numPartiesCmd := flag.Int("parties", 3, "integer number of parties >= 3.")
	thresholdCmd := flag.Int("threshold", 2, "integer number of threshold >= 2.")
	networkLatencyCmd := flag.Int("netlat", 0, "average network latency for party communication.")
	debug := flag.Bool("debug", false, "print debug statements during computation.")
	sharesOnly := flag.Bool("shares", false, "use only linear secret sharing for ALL computations.")
	ttest := flag.Bool("ttest", false, "run Student's T-test simulation")
	corrtest := flag.Bool("pearsontest", false, "run Pearson's Correlation test simulation")
	chisqtest := flag.Bool("chisqtest", false, "run Chi^2 test simulation")

	flag.Parse()

	// extract the passed in arguments
	rootDir := *rootDirCmd
	numParties := *numPartiesCmd
	threshold := *thresholdCmd
	networkLatency := time.Duration(*networkLatencyCmd)
	allTests := !(*ttest || *corrtest || *chisqtest)

	// ensure threshsold is ok for the given number of parties
	if numParties < 2*threshold-1 {
		panic("Threshold is too high compared to the number of parties!")
	}

	// number of cores
	runtime.GOMAXPROCS(2 * numParties)

	// system parameters
	var params *hypocert.MPCKeyGenParams

	if !*example {
		params = &hypocert.MPCKeyGenParams{
			NumParties:      numParties,
			Threshold:       threshold,
			KeyBits:         128,
			MessageBits:     100,
			SecurityBits:    40,
			FPPrecisionBits: 30,
			NetworkLatency:  networkLatency * time.Millisecond}
	} else {
		params = &hypocert.MPCKeyGenParams{
			NumParties:      3,
			Threshold:       2,
			KeyBits:         512,
			MessageBits:     100,
			SecurityBits:    0,
			FPPrecisionBits: 20,
			NetworkLatency:  0}
	}

	fmt.Print("System setup in progress...")
	mpc, err := hypocert.NewMPCKeyGen(params)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")

	// filenames to use for the statistical test computations
	filename1000 := rootDir + "/cmd/files/benchmark_1000.csv"
	filenameChiSq1000_5 := rootDir + "/cmd/files/benchmark_chisq_1000_5.csv"
	filenameChiSq1000_10 := rootDir + "/cmd/files/benchmark_chisq_1000_10.csv"
	filenameChiSq1000_20 := rootDir + "/cmd/files/benchmark_chisq_1000_20.csv"

	if *ttest || allTests {
		/* Student's t-test */
		runTTestBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)
	}

	if *corrtest || allTests {

		/* Pearson's correlation test */
		runPearsonsBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)

	}

	if *chisqtest || allTests {

		if *example {
			runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)

		} else {
			/* Chi-squared test */
			runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)
			runChiSqBechmarks(mpc, filenameChiSq1000_10, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)
			runChiSqBechmarks(mpc, filenameChiSq1000_20, numParties, networkLatency*time.Millisecond, *sharesOnly, *debug, *example)
		}
	}
}

func runChiSqBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, onlyUseShares bool, debug bool, example bool) {

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
		chi2test, datasetSize, numCategories, totalTime, paillierTime, divTime, numSharesCreated = ChiSquaredTestSimulation(mpc, filename, debug, example)
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
	fmt.Printf("---Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("---Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")
}

func runTTestBechmarks(
	mpc *hypocert.MPC,
	filename string,
	numParties int,
	latency time.Duration,
	onlyUseShares bool,
	debug bool,
	example bool) {

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
		ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated = TTestSimulation(mpc, filename, debug, example)
	}

	fmt.Println("************************************************")
	fmt.Println("T-Test statistic:                   " + ttest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	fmt.Printf("Total number of shares:      	 %d\n", numSharesCreated)
	fmt.Printf("Dealer setup time (s): 	         %f\n", dealerSetupTime.Seconds())
	fmt.Printf("T-Test runtime (s): 	         %f\n", totalTime.Seconds())
	fmt.Printf("---Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("---Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")

}

func runPearsonsBechmarks(
	mpc *hypocert.MPC,
	filename string,
	numParties int,
	latency time.Duration,
	onlyUseShares bool,
	debug bool,
	example bool) {

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
	var numSharesCreated int

	if onlyUseShares {
		ptest, datasetSize, dealerSetupTime, totalTime, computeTime, divTime, numSharesCreated = examplePearsonsTestSimulationWihSecretSharing(mpc, filename, debug)
	} else {
		ptest, datasetSize, totalTime, computeTime, divTime, numSharesCreated = PearsonsTestSimulation(mpc, filename, debug, example)
	}

	fmt.Println("************************************************")
	fmt.Println("Pearson's statistic:                " + ptest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Dealer setup time (s): 	         %f\n", dealerSetupTime.Seconds())
	fmt.Printf("Pearson's Test runtime (s):      %f\n", totalTime.Seconds())
	fmt.Printf("---Computation runtime (s):       %f\n", computeTime.Seconds())
	fmt.Printf("---Division runtime (s):          %f\n", divTime.Seconds())
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
	fmt.Println("Certified Hypothesis Testing (System Simulation)")
	fmt.Println("=====================================")
	fmt.Println("DISCLAIMER: this software if intended for simulation and proof-of-concept purposes only.")
	fmt.Println("=====================================")

}
