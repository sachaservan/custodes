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
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

type ProtocolType int

// simulates records stored on the blockchain
const (
	ETruncPR ProtocolType = iota
	EMult
	Decrypt
)

type MPCTranscriptEntry struct {
	Protocol ProtocolType           // type of protocol
	CtIn     []*paillier.Ciphertext // inputs to the protocol
	CtOut    []*paillier.Ciphertext // ciphertext output
	PtOut    *big.Int               // plaintext output
}

type MPCTranscript struct {
	Entries []*MPCTranscriptEntry
	Next    int
}

type EncryptedDataset struct {
	Data    [][]*paillier.Ciphertext
	NumRows int
	NumCols int
}

type TestResult struct {
	Test                  string
	Value                 *big.Float
	TotalRuntime          time.Duration
	ComputeRuntime        time.Duration
	SignExtractionRuntime time.Duration
	DivRuntime            time.Duration
	NumSharesCreated      int
	Transcript            *MPCTranscript // transcript of all MPC protocols
}

type TestReport struct {
	Test                  string
	Value                 *big.Float
	TotalRuntime          float64
	SetupTime             float64
	ComputeRuntime        float64
	SignExtractionRuntime float64
	DivRuntime            float64
	AuditRuntime          float64
	NumParties            int
	NumRows               int
	NumCols               int
	NumSharesCreated      int
	RunId                 int
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

	encD, setupTime := encryptCategoricalDataset(mpc, filename, example)
	testResult := ChiSquaredTestSimulation(mpc, encD, debug)

	if writeToFile {
		r := &TestReport{
			Test:             "Chi-Squared",
			Value:            testResult.Value,
			TotalRuntime:     testResult.TotalRuntime.Seconds(),
			SetupTime:        setupTime.Seconds(),
			ComputeRuntime:   testResult.ComputeRuntime.Seconds(),
			DivRuntime:       testResult.DivRuntime.Seconds(),
			NumParties:       numParties,
			NumRows:          encD.NumRows,
			NumCols:          encD.NumCols,
			NumSharesCreated: testResult.NumSharesCreated,
			RunId:            runId,
		}
		writeTestResultsToFile(r)
	} else {
		fmt.Println("************************************************")
		fmt.Println("Chi^2 statistic:             " + testResult.Value.String())
		fmt.Printf("Dataset size:                %d\n", encD.NumRows)
		fmt.Printf("Number of categories:        %d\n", encD.NumCols)
		fmt.Printf("Number of parties:           %d\n", numParties)
		fmt.Printf("Threshold:                   %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:      %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	     %f\n", setupTime.Seconds())
		fmt.Printf("Chi^2 Test runtime (s):      %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):  %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Division runtime (s):     %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):         %f\n", latency.Seconds())
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

	encD, setupTime := encryptDataset(mpc, filename, example)

	if debug {
		fmt.Println("[DEBUG] Finished encrypting dataset")
	}

	testResult := TTestSimulation(mpc, encD, debug)

	if writeToFile {
		r := &TestReport{
			Test:                  "T-Test",
			Value:                 testResult.Value,
			TotalRuntime:          testResult.TotalRuntime.Seconds(),
			SetupTime:             setupTime.Seconds(),
			ComputeRuntime:        testResult.ComputeRuntime.Seconds(),
			SignExtractionRuntime: testResult.SignExtractionRuntime.Seconds(),
			DivRuntime:            testResult.DivRuntime.Seconds(),
			NumParties:            numParties,
			NumRows:               encD.NumRows,
			NumCols:               encD.NumCols,
			NumSharesCreated:      testResult.NumSharesCreated,
			RunId:                 runId,
		}
		writeTestResultsToFile(r)
	} else {
		fmt.Println("************************************************")
		fmt.Println("T-Test statistic:            " + testResult.Value.String())
		fmt.Printf("Dataset size:                %d\n", encD.NumRows)
		fmt.Printf("Number of parties:           %d\n", numParties)
		fmt.Printf("Threshold:                   %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:      %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	     %f\n", setupTime.Seconds())
		fmt.Printf("T-Test runtime (s): 	     %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):  %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Sign Bit runtime (s):     %f\n", testResult.SignExtractionRuntime.Seconds())
		fmt.Printf("---Division runtime (s):     %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):         %f\n", latency.Seconds())
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

	encD, setupTime := encryptDataset(mpc, filename, example)

	if debug {
		fmt.Println("[DEBUG] Finished encrypting dataset")
	}

	testResult := PearsonsTestSimulation(mpc, encD, debug)

	if writeToFile {
		r := &TestReport{
			Test:                  "Pearson",
			Value:                 testResult.Value,
			TotalRuntime:          testResult.TotalRuntime.Seconds(),
			SetupTime:             setupTime.Seconds(),
			ComputeRuntime:        testResult.ComputeRuntime.Seconds(),
			SignExtractionRuntime: testResult.SignExtractionRuntime.Seconds(),
			DivRuntime:            testResult.DivRuntime.Seconds(),
			NumParties:            numParties,
			NumRows:               encD.NumRows,
			NumCols:               encD.NumCols,
			NumSharesCreated:      testResult.NumSharesCreated,
			RunId:                 runId,
		}
		writeTestResultsToFile(r)
	} else {
		fmt.Println("************************************************")
		fmt.Println("Pearson's statistic:         " + testResult.Value.String())
		fmt.Printf("Dataset size:                %d\n", encD.NumRows)
		fmt.Printf("Number of parties:           %d\n", numParties)
		fmt.Printf("Threshold:                   %d\n", mpc.Threshold)
		fmt.Printf("Total number of shares:      %d\n", testResult.NumSharesCreated)
		fmt.Printf("Dealer setup time (s): 	     %f\n", setupTime.Seconds())
		fmt.Printf("Pearson's Test runtime (s):  %f\n", testResult.TotalRuntime.Seconds())
		fmt.Printf("---Computation runtime (s):  %f\n", testResult.ComputeRuntime.Seconds())
		fmt.Printf("---Sign Bit runtime (s):     %f\n", testResult.SignExtractionRuntime.Seconds())
		fmt.Printf("---Division runtime (s):     %f\n", testResult.DivRuntime.Seconds())
		fmt.Printf("Network latency (s):         %f\n", latency.Seconds())
		fmt.Println("************************************************")
	}
}

func newMPCTranscript(size int) *MPCTranscript {
	return &MPCTranscript{make([]*MPCTranscriptEntry, size), 0}
}

func (trans *MPCTranscript) setEntryAtIndex(entry *MPCTranscriptEntry, i int) {
	trans.Entries[i] = entry
}

func (trans *MPCTranscript) addEntry(entry *MPCTranscriptEntry) {
	trans.Entries[trans.Next] = entry
	trans.Next++
}

func encryptCategoricalDataset(
	mpc *hypocert.MPC,
	filepath string,
	example bool) (*EncryptedDataset, time.Duration) {
	dealerSetupStart := time.Now()

	var x [][]int64
	var err error

	if !example {
		x, err = parseCategoricalDataset(filepath)
		if err != nil {
			panic(err)
		}
	} else {
		// Test dataset (result should be 0.666...)
		x = [][]int64{
			{1, 0}, {1, 0}, {0, 1},
			{0, 1}, {0, 1}, {0, 1},
		}

		fmt.Println("Example dataset: ")
		fmt.Println("   ------------------------------------------------")
		fmt.Print("X: |")
		for i := 0; i < len(x); i++ {
			fmt.Print("(" + strconv.Itoa(int(x[i][0])) + ", " + strconv.Itoa(int(x[i][1])) + ")")
			if i+1 < len(x) {
				fmt.Print(", ")
			} else {
				fmt.Println("|")
			}
		}
		fmt.Println("   ------------------------------------------------")
		fmt.Println()
	}

	numCategories := len(x[0])
	numRows := len(x)

	var eX [][]*paillier.Ciphertext
	eX = make([][]*paillier.Ciphertext, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eX[i] = make([]*paillier.Ciphertext, numCategories)
			for j := 0; j < numCategories; j++ {
				pt := mpc.Pk.EncodeFixedPoint(
					big.NewFloat(float64(x[i][j])), mpc.FPPrecBits)
				eX[i][j] = mpc.Pk.Encrypt(pt)
			}
		}(i)
	}

	wg.Wait()

	return &EncryptedDataset{
			Data:    eX,
			NumRows: numRows,
			NumCols: numCategories,
		},
		time.Now().Sub(dealerSetupStart)
}

func encryptDataset(
	mpc *hypocert.MPC,
	filepath string,
	example bool) (*EncryptedDataset, time.Duration) {

	dealerSetupStart := time.Now()

	var x []float64
	var y []float64

	var err error
	if !example {
		x, y, err = parseDataset(filepath)
		if err != nil {
			panic(err)
		}
	} else {
		// Test dataset (result should be 1.99 for t-test, 0.29... for pearson)
		x = []float64{105, 119, 100, 97, 96, 101, 94, 95, 98}
		y = []float64{96, 99, 94, 89, 96, 93, 88, 105, 88}

		fmt.Println("Example dataset: ")
		fmt.Println("   ----------------------------------------")
		fmt.Print("X: |")
		for i := 0; i < len(x); i++ {
			fmt.Print(strconv.Itoa(int(x[i])))
			if i+1 < len(x) {
				fmt.Print(", ")
			} else {
				fmt.Print("|")
			}
		}
		fmt.Print("\nY: |")
		for i := 0; i < len(y); i++ {
			fmt.Print(strconv.Itoa(int(y[i])))
			if i+1 < len(y) {
				fmt.Print(", ")
			} else {
				fmt.Print("   |")
			}
		}
		fmt.Println()
		fmt.Println("   ----------------------------------------")
	}

	numRows := len(y)

	var eX []*paillier.Ciphertext
	eX = make([]*paillier.Ciphertext, numRows)
	var eY []*paillier.Ciphertext
	eY = make([]*paillier.Ciphertext, numRows)

	for i := 0; i < numRows; i++ {

		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
		eX[i] = mpc.Pk.Encrypt(plaintextX)
		eY[i] = mpc.Pk.Encrypt(plaintextY)
	}

	return &EncryptedDataset{
			Data:    [][]*paillier.Ciphertext{eX, eY},
			NumRows: numRows,
			NumCols: 2,
		},
		time.Now().Sub(dealerSetupStart)
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

func writeTestResultsToFile(
	r *TestReport) {
	filename := "./" + strconv.Itoa(r.RunId) + "_" +
		r.Test + "_[" + strconv.Itoa(r.NumRows) + "_" +
		strconv.Itoa(r.NumCols) + "]_n=" +
		strconv.Itoa(r.NumParties) + "_" + ".json"

	reportJson, _ := json.MarshalIndent(r, "", "\t")
	err := ioutil.WriteFile(
		filename,
		reportJson, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}
