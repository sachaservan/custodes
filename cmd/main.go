package main

import (
	"flag"
	"fmt"
	"hypocert"
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
	runId := flag.Int("runId", 0, "unique id of the test/benchmark run")
	writeToFile := flag.Bool("save", false, "save tests results to a json file")
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
			KeyBits:         512,
			MessageBits:     100,
			SecurityBits:    40,
			FPPrecisionBits: 30,
			NetworkLatency:  networkLatency * time.Millisecond}
	} else {
		// params for example purposes
		params = &hypocert.MPCKeyGenParams{
			NumParties:      3,
			Threshold:       2,
			KeyBits:         512,
			MessageBits:     100,
			SecurityBits:    40,
			FPPrecisionBits: 30,
			NetworkLatency:  0}
	}

	fmt.Print("System setup in progress...")
	mpc, err := hypocert.NewMPCKeyGen(params)
	if err != nil {
		panic(err)
	}
	fmt.Println("done.")

	// filenames to use for the statistical test computations
	filename1000 := rootDir + "/cmd/datasets/benchmark_1000.csv"
	filenameChiSq1000_5 := rootDir + "/cmd/datasets/benchmark_chisq_1000_5.csv"
	filenameChiSq1000_10 := rootDir + "/cmd/datasets/benchmark_chisq_1000_10.csv"
	filenameChiSq1000_20 := rootDir + "/cmd/datasets/benchmark_chisq_1000_20.csv"

	if *ttest || allTests {
		/* Student's t-test */
		runTTestBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)
	}

	if *corrtest || allTests {

		/* Pearson's correlation test */
		runPearsonsBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)

	}

	if *chisqtest || allTests {

		if *example {
			runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)

		} else {
			/* Chi-squared test */
			runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)
			runChiSqBechmarks(mpc, filenameChiSq1000_10, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)
			runChiSqBechmarks(mpc, filenameChiSq1000_20, numParties, networkLatency*time.Millisecond, *debug, *writeToFile, *runId, *example)
		}
	}
}

func printWelcome() {
	fmt.Println("+=======================================================================+")
	fmt.Println("		 _    _                    _____          _  ")
	fmt.Println("		| |  | |                  / ____|        | |  ")
	fmt.Println("		| |__| |_   _ _ __   ___ | |     ___ _ __| |_ ")
	fmt.Println("		|  __  | | | | '_ \\ / _ \\| |    / _ \\ '__| __|")
	fmt.Println("		| |  | | |_| | |_) | (_) | |___|  __/ |  | |_ ")
	fmt.Println("		|_|  |_|\\__, | .__/ \\___/ \\_____\\___|_|   \\__|")
	fmt.Println("			 __/ | |                              ")
	fmt.Println("			|___/|_|                           ")
	fmt.Println()
	fmt.Println("			Certified Hypothesis Testing")
	fmt.Println("+========================================================================+")
	fmt.Println("| DISCLAIMER: this software is intended for simulation                   |")
	fmt.Println("|             and nd proof-of-concept purposes only.                     |")
	fmt.Println("+========================================================================+")
	fmt.Println()
}
