package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hypocert"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/sachaservan/paillier"
)

type ProtocolType int

const (
	TruncPR ProtocolType = iota
	Mult
	FPMult
	ECMultFP
	Reveal
	RandInt
	Division
)

type MPCTranscriptEntry struct {
	Protocol ProtocolType           // type of protocol
	CtIn     *[]paillier.Ciphertext // inputs to the protocol
	CtOut    *paillier.Ciphertext   // ciphertext output
	PtOut    *big.Int               // plaintext output
}

type MPCTranscript struct {
	Entries []*MPCTranscriptEntry
	next    int
}

func newMPCTranscript(size int) *MPCTranscript {
	return &MPCTranscript{make([]*MPCTranscriptEntry, size), 0}
}

func (trans *MPCTranscript) addEntry(entry *MPCTranscriptEntry) {
	trans.Entries[trans.next] = entry
}

type TestResult struct {
	Test             string
	Value            *big.Float
	NumRows          int
	NumColumns       int
	TotalRuntime     time.Duration
	ComputeRuntime   time.Duration
	DivRuntime       time.Duration
	SetupTime        time.Duration
	NumSharesCreated int
	Transcript       []*MPCTranscriptEntry // transcript of all MPC protocols
}

func runChiSqBechmarks(
	mpc *hypocert.MPC,
	filename string,
	numParties int,
	latency time.Duration,
	debug bool,
	writeToFile bool,
	runId int,
	example bool) {

	//**************************************************************************************
	//**************************************************************************************
	// Chi-Squared Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Chi^2 Test...")
	fmt.Println("------------------------------------------------")

	var testResult *TestResult
	testResult = ChiSquaredTestSimulation(mpc, filename, debug, example)

	if writeToFile {
		writeTestResultsToFile(testResult, runId, numParties)
	} else {
		fmt.Println("************************************************")
		fmt.Println("Chi^2 statistic:                 " + testResult.Value.String())
		fmt.Printf("Dataset size:                    %d\n", testResult.NumRows)
		fmt.Printf("Number of categories:            %d\n", testResult.NumColumns)
		fmt.Printf("Number of parties:               %d\n", numParties)
		fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:          %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	         %f\n", testResult.SetupTime.Seconds())
		fmt.Printf("Chi^2 Test runtime (s):          %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):      %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Division runtime (s):         %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
		fmt.Println("************************************************")
	}
}

func runTTestBechmarks(
	mpc *hypocert.MPC,
	filename string,
	numParties int,
	latency time.Duration,
	debug bool,
	writeToFile bool,
	runId int,
	example bool) {

	//**************************************************************************************
	//**************************************************************************************
	// T Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running T-Test...")
	fmt.Println("------------------------------------------------")

	var testResult *TestResult
	testResult = TTestSimulation(mpc, filename, debug, example)

	if writeToFile {
		writeTestResultsToFile(testResult, runId, numParties)
	} else {
		fmt.Println("************************************************")
		fmt.Println("T-Test statistic:                " + testResult.Value.String())
		fmt.Printf("Dataset size:                    %d\n", testResult.NumRows)
		fmt.Printf("Number of parties:               %d\n", numParties)
		fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:      	 %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	         %f\n", testResult.SetupTime.Seconds())
		fmt.Printf("T-Test runtime (s): 	         %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):      %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Division runtime (s):         %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
		fmt.Println("************************************************")
	}
}

func runPearsonsBechmarks(
	mpc *hypocert.MPC,
	filename string,
	numParties int,
	latency time.Duration,
	debug bool,
	writeToFile bool,
	runId int,
	example bool) {

	//**************************************************************************************
	//**************************************************************************************
	// Pearson's Test Benchmark
	//**************************************************************************************
	//**************************************************************************************

	fmt.Println("------------------------------------------------")
	fmt.Println("Running Pearson's Coorelation Test...")
	fmt.Println("------------------------------------------------")

	var testResult *TestResult
	testResult = PearsonsTestSimulation(mpc, filename, debug, example)

	if writeToFile {
		writeTestResultsToFile(testResult, runId, numParties)
	} else {
		fmt.Println("************************************************")
		fmt.Println("Pearson's statistic:             " + testResult.Value.String())
		fmt.Printf("Dataset size:                    %d\n", testResult.NumRows)
		fmt.Printf("Number of parties:               %d\n", numParties)
		fmt.Printf("Threshold:                       %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:          %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	         %f\n", testResult.SetupTime.Seconds())
		fmt.Printf("Pearson's Test runtime (s):      %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):      %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Division runtime (s):         %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):             %f\n", latency.Seconds())
		fmt.Println("************************************************")
	}
}

func parseCategoricalDataset(file string) ([][]int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	csvr := csv.NewReader(f)
	data := make([][]int64, 0)

	for {
		row, err := csvr.Read()

		if err != nil {
			if err == io.EOF {
				err = nil
			}

			return data, err
		}

		values := make([]int64, len(row))
		for i := 0; i < len(row); i++ {
			var val int64
			if val, err = strconv.ParseInt(row[i], 10, 64); err != nil {
				panic("could not parse dataset")
			}

			values[i] = val
		}

		data = append(data, values)
	}

}

func parseDataset(file string) ([]float64, []float64, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	defer f.Close()

	csvr := csv.NewReader(f)

	data1 := make([]float64, 0)
	data2 := make([]float64, 0)

	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				err = nil
			}

			return data1, data2, err
		}

		var val1 float64
		var val2 float64

		if val1, err = strconv.ParseFloat(row[0], 64); err != nil {
			continue
		}
		if val2, err = strconv.ParseFloat(row[1], 64); err != nil {
			continue
		}

		data1 = append(data1, val1)
		data2 = append(data2, val2)

	}

}

func writeTestResultsToFile(r *TestResult, runId int, numParties int) {
	filename := "./" + strconv.Itoa(runId) + "_" +
		r.Test + "_" + strconv.Itoa(r.NumRows) + "_" +
		strconv.Itoa(r.NumColumns) + "_" +
		strconv.Itoa(numParties) + "_" + ".json"

	reportJson, _ := json.MarshalIndent(r, "", "\t")
	err := ioutil.WriteFile(
		filename,
		reportJson, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}
