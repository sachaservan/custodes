package main

import (
	"fmt"
	"hypocert"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

// Simulation of Pearson's coorelation coefficient
func PearsonsTestSimulation(mpc *hypocert.MPC, filepath string, debug bool, example bool) *TestResult {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

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
		// Test dataset (result should be 0.96...)
		x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
		y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}

		fmt.Println("   -------------------------------------")
		fmt.Print("X: |")
		for i := 0; i < len(x); i++ {
			fmt.Print(strconv.Itoa(int(x[i])))
			if i+1 < len(x) {
				fmt.Print(", ")
			} else {
				fmt.Print(" |")
			}
		}
		fmt.Print("\nY: |")
		for i := 0; i < len(y); i++ {
			fmt.Print(strconv.Itoa(int(y[i])))
			if i+1 < len(y) {
				fmt.Print(", ")
			} else {
				fmt.Print("|")
			}
		}
		fmt.Println()
		fmt.Println("   -------------------------------------")
	}

	if debug && !example {
		fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
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

	dealerSetupTime := time.Now().Sub(dealerSetupStart)

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// sum of the values
	sumX := mpc.Pk.EAdd(eX...)
	sumY := mpc.Pk.EAdd(eY...)

	meanX := mpc.ECMultFP(sumX, invNumRows)
	meanY := mpc.ECMultFP(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*paillier.Ciphertext, numRows)

	// SUM (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, numRows)

	// SUM (y_i - mean_y)^2
	devsY2 := make([]*paillier.Ciphertext, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			devX := mpc.Pk.ESub(eX[i], meanX)
			devY := mpc.Pk.ESub(eY[i], meanY)
			devsX2[i] = mpc.EMult(devX, devX)
			devsY2[i] = mpc.EMult(devY, devY)
			prodsXY[i] = mpc.EMult(devX, devY)
		}(i)
	}

	wg.Wait()

	// compute sum for all i (x_i - mean_x)(y_i - mean_y)
	sumXY := mpc.Pk.EAdd(prodsXY...)

	sumDevX2 := mpc.Pk.EAdd(devsX2...)
	sumDevY2 := mpc.Pk.EAdd(devsY2...)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := mpc.EMult(sumXY, sumXY)
	numerator = mpc.ETruncPR(numerator, 3*mpc.K, 3*mpc.FPPrecBits)

	denominator := mpc.EMult(sumDevX2, sumDevY2)
	denominator = mpc.ETruncPR(denominator, 3*mpc.K, 3*mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n", mpc.RevealFP(numerator, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealFP(denominator, mpc.FPPrecBits).String())
	}

	// convert to shares
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	// done with paillier computations
	endTimePaillier := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Share):   %s\n", mpc.RevealShareFP(numeratorShare, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR (Share): %s\n", mpc.RevealShareFP(denominatorShare, mpc.FPPrecBits).String())
	}

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	stat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	stat := stat2.Sqrt(stat2)

	endTime := time.Now()

	if debug {
		fmt.Printf("[DEBUG] PEARSON CORRELATION STATISTIC, r = %s\n", stat.String())
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:             "PEARSON",
		Value:            stat,
		NumRows:          len(x),
		NumColumns:       2,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		SetupTime:        dealerSetupTime,
		NumSharesCreated: mpc.DeleteAllShares(),
	}
}
