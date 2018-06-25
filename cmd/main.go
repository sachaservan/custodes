package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hypocert"
	"io/ioutil"
	"math/big"
	"runtime"
	"strconv"
	"time"
)

type Report struct {
	TestType            string
	UseShares           bool
	PValue              float64
	DatasetSize         int
	NumberOfCategories  int
	NumberOfParties     int
	TotalNumberOfShares int
	TotalTime           float64
	ComputationTime     float64
	ComparisonTime      float64
	DivisionTime        float64
	Latency             float64
}

func main() {
	printWelcome()

	// Command line arguments
	rootDirCmd := flag.String("rootdir", "", "full path to project dir.")
	numPartiesCmd := flag.Int("parties", 3, "integer number of parties >= 3.")
	runIdCmd := flag.Int("runid", 0, "integer number for keeping track of the current run.")
	thresholdCmd := flag.Int("threshold", 2, "integer number of parties >= 2.")
	networkLatencyCmd := flag.Int("netlat", 0, "average network latency for party communication.")
	debugCmd := flag.Bool("debug", false, "print debug statements during computation.")
	useSharesCmd := flag.Bool("shares", false, "use only secret sharing for computations.")

	flag.Parse()

	rootDir := *rootDirCmd
	numParties := *numPartiesCmd
	threshold := *thresholdCmd
	networkLatency := time.Duration(*networkLatencyCmd)
	debug := *debugCmd
	useShares := *useSharesCmd

	fmt.Println("dummy " + rootDir + " " + strconv.FormatBool(useShares) + " " + strconv.Itoa(*runIdCmd))
	fmt.Println("num parties " + strconv.Itoa(numParties))

	if numParties < 2*threshold-1 {
		panic("Threshold is too high compared to the number of parties!")
	}

	runtime.GOMAXPROCS(2 * numParties)

	fmt.Print("Generating keys...")
	params := &hypocert.MPCKeyGenParams{
		NumParties:      numParties,
		Threshold:       threshold,
		Verify:          false,
		KeyBits:         512,
		MessageBits:     100,
		SecurityBits:    40,
		FPPrecisionBits: 30,
		NetworkLatency:  networkLatency * time.Millisecond}

	mpc := hypocert.NewMPCKeyGen(params)

	fmt.Println("done.")

	// filename1000 := rootDir + "/benchmark/benchmark_1000.csv"
	// filenameChiSq1000_5 := rootDir + "/benchmark/benchmark_chisq_1000_5.csv"
	// filenameChiSq1000_10 := rootDir + "/benchmark/benchmark_chisq_1000_10.csv"
	// filenameChiSq1000_20 := rootDir + "/benchmark/benchmark_chisq_1000_20.csv"

	// filename5000 := rootDir + "/benchmark/benchmark_5000.csv"
	// filenameChiSq5000_5 := rootDir + "/benchmark/benchmark_chisq_5000_5.csv"
	// filenameChiSq5000_10 := rootDir + "/benchmark/benchmark_chisq_5000_10.csv"
	// filenameChiSq5000_20 := rootDir + "/benchmark/benchmark_chisq_5000_20.csv"

	// filename10000 := rootDir + "/benchmark/benchmark_10000.csv"
	// filenameChiSq10000_5 := rootDir + "/benchmark/benchmark_chisq_10000_5.csv"
	// filenameChiSq10000_10 := rootDir + "/benchmark/benchmark_chisq_10000_10.csv"
	// filenameChiSq10000_20 := rootDir + "/benchmark/benchmark_chisq_10000_20.csv"

	// runTTestBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runTTestBechmarks(mpc, filename5000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runTTestBechmarks(mpc, filename10000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)

	// runPearsonsBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runPearsonsBechmarks(mpc, filename5000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runPearsonsBechmarks(mpc, filename10000, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)

	// runChiSqBechmarks(mpc, filenameChiSq1000_5, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq1000_10, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq1000_20, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq5000_5, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq5000_10, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq5000_20, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq10000_5, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq10000_10, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)
	// runChiSqBechmarks(mpc, filenameChiSq10000_20, numParties, networkLatency*time.Millisecond, false, useShares, debug, *runIdCmd)

	runMultBenchmark(mpc, numParties, networkLatency*time.Millisecond, false, debug)

}

func runChiSqBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool, runId int) {

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
	var totalTime time.Duration
	var paillierTime time.Duration
	var divTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		chi2test, datasetSize, numCategories, totalTime, paillierTime, divTime, numSharesCreated = exampleChiSquaredSimulationWithSecretSharing(mpc, filename, debug)
	} else {
		chi2test, datasetSize, numCategories, totalTime, paillierTime, divTime, numSharesCreated = exampleChiSquaredSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("Chi^2 p-value:                    " + chi2test.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of categories:            %d\n", numCategories)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Chi^2 Test runtime (s):          %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")

	pvalue, _ := chi2test.Float64()

	r := Report{
		TestType:            "CHI2",
		UseShares:           onlyUseShares,
		PValue:              pvalue,
		DatasetSize:         datasetSize,
		NumberOfCategories:  numCategories,
		NumberOfParties:     numParties,
		TotalNumberOfShares: numSharesCreated,
		TotalTime:           totalTime.Seconds(),
		ComputationTime:     paillierTime.Seconds(),
		DivisionTime:        divTime.Seconds(),
		Latency:             latency.Seconds()}

	reportJson, _ := json.MarshalIndent(r, "", "\t")
	err := ioutil.WriteFile("../benchmark/res/"+strconv.Itoa(runId)+"_"+strconv.FormatBool(onlyUseShares)+"_"+r.TestType+"_"+strconv.Itoa(datasetSize)+"_"+strconv.Itoa(numParties)+"_"+strconv.Itoa(numCategories)+".json", reportJson, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}

func runTTestBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool, runId int) {

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
	var totalTime time.Duration
	var paillierTime time.Duration
	var divTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated = exampleTTestSimulationWithSecretSharing(mpc, filename, debug)
	} else {
		ttest, datasetSize, totalTime, paillierTime, divTime, numSharesCreated = exampleTTestSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("T-Test p-value:                   " + ttest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:      	 %d\n", numSharesCreated)
	fmt.Printf("T-Test runtime (s): 	         %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")

	pvalue, _ := ttest.Float64()

	r := Report{
		TestType:            "TTEST",
		UseShares:           onlyUseShares,
		PValue:              pvalue,
		DatasetSize:         datasetSize,
		NumberOfCategories:  0,
		NumberOfParties:     numParties,
		TotalNumberOfShares: numSharesCreated,
		TotalTime:           totalTime.Seconds(),
		ComputationTime:     paillierTime.Seconds(),
		DivisionTime:        divTime.Seconds(),
		Latency:             latency.Seconds()}

	numCategories := 0
	reportJson, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile("../benchmark/res/"+strconv.Itoa(runId)+"_"+strconv.FormatBool(onlyUseShares)+"_"+r.TestType+"_"+strconv.Itoa(datasetSize)+"_"+strconv.Itoa(numParties)+"_"+strconv.Itoa(numCategories)+".json", reportJson, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}

func runPearsonsBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, onlyUseShares bool, debug bool, runId int) {

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
	var totalTime time.Duration
	var computeTime time.Duration
	var divTime time.Duration
	var cmpTime time.Duration
	var numSharesCreated int

	if onlyUseShares {
		ptest, datasetSize, totalTime, computeTime, cmpTime, divTime, numSharesCreated = examplePearsonsTestSimulationWihSecretSharing(mpc, filename, debug)
	} else {
		ptest, datasetSize, totalTime, computeTime, cmpTime, divTime, numSharesCreated = examplePearsonsTestSimulation(mpc, filename, debug)
	}

	fmt.Println("************************************************")
	fmt.Println("Pearson's p-value:                " + ptest.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of parties:               %d\n", numParties)
	fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Pearson's Test runtime (s):      %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", computeTime.Seconds())
	fmt.Printf("  Comparison runtime (s):        %f\n", cmpTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")

	pvalue, _ := ptest.Float64()

	r := Report{
		TestType:            "PEARSON",
		UseShares:           onlyUseShares,
		PValue:              pvalue,
		DatasetSize:         datasetSize,
		NumberOfCategories:  0,
		NumberOfParties:     numParties,
		TotalNumberOfShares: numSharesCreated,
		TotalTime:           totalTime.Seconds(),
		ComputationTime:     computeTime.Seconds(),
		ComparisonTime:      cmpTime.Seconds(),
		DivisionTime:        divTime.Seconds(),
		Latency:             latency.Seconds()}

	numCategories := 0
	reportJson, _ := json.MarshalIndent(r, "", "\t")
	err := ioutil.WriteFile("../benchmark/res/"+strconv.Itoa(runId)+"_"+strconv.FormatBool(onlyUseShares)+"_"+r.TestType+"_"+strconv.Itoa(datasetSize)+"_"+strconv.Itoa(numParties)+"_"+strconv.Itoa(numCategories)+".json", reportJson, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}

func runMultBenchmark(mpc *hypocert.MPC, threshold int, latency time.Duration, zkp bool, debug bool) {

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

	for i := 0; i < 100; i++ {
		stime := time.Now()
		mpc.EMult(a, b)
		endTime := time.Now()
		multTimePaillier += endTime.Sub(stime)
	}

	for i := 0; i < 100; i++ {
		stime := time.Now()
		mpc.Mult(ashare, bshare)
		endTime := time.Now()
		multTimeShares += endTime.Sub(stime)
	}

	fmt.Printf("Paillier MULT time:   %f\n", +float64(multTimePaillier.Nanoseconds())/(1000000.0*100.0))
	fmt.Printf("Shares MULT time:     %f\n", +float64(multTimeShares.Nanoseconds())/(1000000.0*100.0))
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
	fmt.Println("Certified Hypothesis Testing")
	fmt.Println("=====================================")

}
