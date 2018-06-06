package main

import (
	"flag"
	"fmt"
	"hypocert"
	"math/big"
	"runtime"
	"time"
    "encoding/json"
    "io/ioutil"
    "strconv"
)

type Report struct {
    TestType string
    PValue float64 
    DatasetSize int 
    NumberOfCategories int 
    NumberOfParties int 
    TotalNumberOfShares int 
    TotalNumberOfPaillierMults int 
    TotalNumberOfShareMults int 
    TotalTime float64
    ComputationTime float64 
    DivisionTime float64
    Latency float64
}

func main() {
	printWelcome()

	runtime.GOMAXPROCS(10000)

	// Command line arguments
	rootDirCmd := flag.String("rootdir", "", "full path to project dir.")
	numPartiesCmd := flag.Int("parties", 3, "integer number of parties >= 3.")
	thresholdCmd := flag.Int("threshold", 2, "integer number of parties >= 2.")
	networkLatencyCmd := flag.Int("netlat", 0, "average network latency for party communication.")
	debugCmd := flag.Bool("debug", false, "print debug statements during computation.")

	flag.Parse()

	rootDir := *rootDirCmd
	numParties := *numPartiesCmd
	threshold := *thresholdCmd
	networkLatency := time.Duration(*networkLatencyCmd)
	debug := *debugCmd

	if numParties < 2*threshold-1 {
		panic("Threshold is too high compared to the number of parties!")
	}

	fmt.Print("Generating keys...")
	params := &hypocert.MPCKeyGenParams{
		NumParties:      2 * numParties,
		Threshold:       threshold,
		Verify:          false,
		KeyBits:         512,
		MessageBits:     84,
		SecurityBits:    40,
		FPPrecisionBits: 20,
		NetworkLatency:  networkLatency}

	mpc := hypocert.NewMPCKeyGen(params)

	fmt.Println("done.")

	/* 1000 row dataset */
	filename1000 := rootDir + "/benchmark/benchmark_1000.csv"

	/* 1000 row dataset, 10 categories */
	filenameChiSq1000_10 := rootDir + "/benchmark/benchmark_chisq_1000_10.csv"

	/* 1000 row dataset, 25 categories */
	filenameChiSq1000_25 := rootDir + "/benchmark/benchmark_chisq_1000_25.csv"

	/* 1000 row dataset, 50 categories */
	filenameChiSq1000_50 := rootDir + "/benchmark/benchmark_chisq_1000_50.csv"

	/************************************************************************/

	/* 5000 row dataset */
	filename5000 := rootDir + "/benchmark/benchmark_5000.csv"

	/* 5000 row dataset, 10 categories */
	filenameChiSq5000_10 := rootDir + "/benchmark/benchmark_chisq_5000_10.csv"

	/* 5000 row dataset, 25 categories */
	filenameChiSq5000_25 := rootDir + "/benchmark/benchmark_chisq_5000_25.csv"

	/* 5000 row dataset, 50 categories */
	filenameChiSq5000_50 := rootDir + "/benchmark/benchmark_chisq_5000_50.csv"

	/************************************************************************/

	/* 10000 row dataset */
	filename10000 := rootDir + "/benchmark/benchmark_10000.csv"

	/* 10000 row dataset, 10 categories */
	filenameChiSq10000_10 := rootDir + "/benchmark/benchmark_chisq_10000_10.csv"

	/* 10000 row dataset, 25 categories */
	filenameChiSq10000_25 := rootDir + "/benchmark/benchmark_chisq_10000_25.csv"

	/* 10000 row dataset, 50 categories */
	filenameChiSq10000_50 := rootDir + "/benchmark/benchmark_chisq_10000_50.csv"

	/************************************************************************/

	runTTestBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, debug)
	runTTestBechmarks(mpc, filename5000, numParties, networkLatency*time.Millisecond, false, debug)
	runTTestBechmarks(mpc, filename10000, numParties, networkLatency*time.Millisecond, false, debug)

	runPearsonsBechmarks(mpc, filename1000, numParties, networkLatency*time.Millisecond, false, debug)
	runPearsonsBechmarks(mpc, filename5000, numParties, networkLatency*time.Millisecond, false, debug)
	runPearsonsBechmarks(mpc, filename10000, numParties, networkLatency*time.Millisecond, false, debug)

	runChiSqBechmarks(mpc, filenameChiSq1000_10, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq1000_25, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq1000_50, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq5000_10, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq5000_25, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq5000_50, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq10000_10, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq10000_25, numParties, networkLatency*time.Millisecond, false, debug)
	runChiSqBechmarks(mpc, filenameChiSq10000_50, numParties, networkLatency*time.Millisecond, false, debug)

	runMultBenchmark(mpc, numParties, networkLatency*time.Millisecond, false, debug)

}

func runChiSqBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, debug bool) {

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
	chi2test, datasetSize, numCategories, totalTime, paillierTime, divTime, numSharesCreated := exampleChiSquaredSimulation(mpc, filename, debug)

	fmt.Println("************************************************")
	fmt.Println("Chi^2 p-value:                    " + chi2test.String())
	fmt.Printf("Dataset size:                    %d\n", datasetSize)
	fmt.Printf("Number of categories:            %d\n", numCategories)
	fmt.Printf("Number of parties:               %d\n", numParties)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("Chi^2 Test runtime (s):          %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")
    
    pvalue, _ := chi2test.Float64()
    
    r := Report{
        TestType: "CHI2",
        PValue: pvalue,
        DatasetSize: datasetSize,
        NumberOfCategories: numCategories,
        NumberOfParties: numParties,
        TotalNumberOfShares: numSharesCreated,
        TotalNumberOfPaillierMults:  hypocert.MultCountPaillier,
        TotalNumberOfShareMults: hypocert.MultCountShares,
        TotalTime: totalTime.Seconds(),
        ComputationTime: paillierTime.Seconds(),
        DivisionTime: divTime.Seconds(),
        Latency: latency.Seconds()}
        
    reportJson, _ := json.MarshalIndent(r, "", "\t")
    err := ioutil.WriteFile(r.TestType + "_" + strconv.Itoa(datasetSize) + "_" + strconv.Itoa(numParties) + "_" + strconv.Itoa(numCategories) + ".json", reportJson, 0644)        
    
    if err != nil {
        fmt.Println(err)
        return
    }
}

func runTTestBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, debug bool) {

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
	fmt.Printf("Number of parties:               %d\n", numParties)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:      	 %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("T-Test runtime (s): 	         %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")
    
    pvalue, _ := ttest.Float64()
    
    r := Report{
        TestType: "TTEST",
        PValue: pvalue,
        DatasetSize: datasetSize,
        NumberOfCategories: 0,
        NumberOfParties: numParties,
        TotalNumberOfShares: numSharesCreated,
        TotalNumberOfPaillierMults:  hypocert.MultCountPaillier,
        TotalNumberOfShareMults: hypocert.MultCountShares,
        TotalTime: totalTime.Seconds(),
        ComputationTime: paillierTime.Seconds(),
        DivisionTime: divTime.Seconds(),
        Latency: latency.Seconds()}
    
    numCategories := 0
    reportJson, err := json.MarshalIndent(r, "", "\t")
    if err != nil {
        fmt.Println(err)
        return
    }
    
    err = ioutil.WriteFile(r.TestType + "_" + strconv.Itoa(datasetSize) + "_" + strconv.Itoa(numParties) + "_" + strconv.Itoa(numCategories) + ".json", reportJson, 0644)        
    
    if err != nil {
        fmt.Println(err)
        return
    }
}

func runPearsonsBechmarks(mpc *hypocert.MPC, filename string, numParties int, latency time.Duration, zkp bool, debug bool) {

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
	fmt.Printf("Number of parties:               %d\n", numParties)
	//fmt.Printf("Zero-Knowledge Proofs:           %t\n", zkp)
	fmt.Printf("Total number of shares:          %d\n", numSharesCreated)
	fmt.Printf("Total number of Paillier Mults:  %d\n", hypocert.MultCountPaillier)
	fmt.Printf("Total number of Share Mults:     %d\n", hypocert.MultCountShares)
	fmt.Printf("Pearson's Test runtime (s):      %f\n", totalTime.Seconds())
	fmt.Printf("  Computation runtime (s):       %f\n", paillierTime.Seconds())
	fmt.Printf("  Division runtime (s):          %f\n", divTime.Seconds())
	fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
	fmt.Println("************************************************")
    
    pvalue, _ := ptest.Float64()
    
    r := Report{
        TestType: "PEARSON",
        PValue: pvalue,
        DatasetSize: datasetSize,
        NumberOfCategories: 0,
        NumberOfParties: numParties,
        TotalNumberOfShares: numSharesCreated,
        TotalNumberOfPaillierMults:  hypocert.MultCountPaillier,
        TotalNumberOfShareMults: hypocert.MultCountShares,
        TotalTime: totalTime.Seconds(),
        ComputationTime: paillierTime.Seconds(),
        DivisionTime: divTime.Seconds(),
        Latency: latency.Seconds()}
        
    numCategories := 0    
    reportJson, _ := json.MarshalIndent(r, "", "\t")
    err := ioutil.WriteFile(r.TestType + "_" + strconv.Itoa(datasetSize) + "_" + strconv.Itoa(numParties) + "_" + strconv.Itoa(numCategories) + ".json", reportJson, 0644)        
    
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

	fmt.Printf("Paillier MULT time:   %f\n", +float64(multTimePaillier.Nanoseconds())/(1000000.0*1000.0))
	fmt.Printf("Shares MULT time:     %f\n", +float64(multTimeShares.Nanoseconds())/(1000000.0*1000.0))
	fmt.Printf("Network latency (s):  %d\n", latency.Seconds())

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
