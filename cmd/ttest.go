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

func TTestSimulation(mpc *hypocert.MPC, filepath string, debug bool, example bool) *TestResult {

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
		// Test dataset (result should be 1.99...)
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

	if debug && !example {
		fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
	}

	numRows := len(y)

	var eX []*paillier.Ciphertext
	eX = make([]*paillier.Ciphertext, numRows)
	var eY []*paillier.Ciphertext
	eY = make([]*paillier.Ciphertext, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
			plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
			eX[i] = mpc.Pk.Encrypt(plaintextX)
			eY[i] = mpc.Pk.Encrypt(plaintextY)
		}(i)
	}

	wg.Wait()

	dealerSetupTime := time.Now().Sub(dealerSetupStart)

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	if debug {
		fmt.Println("[DEBUG] Finished encrypting dataset")
	}

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// sum of the squares
	sumX := mpc.Pk.EAdd(eX...)
	sumY := mpc.Pk.EAdd(eY...)

	meanX := mpc.ECMultFP(sumX, invNumRows)
	meanY := mpc.ECMultFP(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	sumsSdX := make([]*paillier.Ciphertext, numRows)
	sumsSdY := make([]*paillier.Ciphertext, numRows)

	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sdx := mpc.Pk.ESub(eX[i], meanX)
			sdy := mpc.Pk.ESub(eY[i], meanY)
			sumsSdX[i] = mpc.EMult(sdx, sdx)
			sumsSdY[i] = mpc.EMult(sdy, sdy)
		}(i)
	}

	wg.Wait()

	// compute the standard deviation
	sdX := mpc.Pk.EAdd(sumsSdX...)
	sdY := mpc.Pk.EAdd(sumsSdY...)

	sdX = mpc.ECMultFP(sdX, big.NewFloat(1.0/float64(numRows-1)))
	sdY = mpc.ECMultFP(sdY, big.NewFloat(1.0/float64(numRows-1)))

	numerator := mpc.Pk.ESub(meanX, meanY)
	numerator = mpc.EMult(numerator, numerator)
	numerator = mpc.ETruncPR(numerator, mpc.K, mpc.FPPrecBits)

	tx := mpc.Pk.ESub(mpc.Pk.ECMult(sdX, big.NewInt(int64(numRows))), sdX)
	ty := mpc.Pk.ESub(mpc.Pk.ECMult(sdY, big.NewInt(int64(numRows))), sdY)
	denominator := mpc.Pk.EAdd(tx, ty)
	denominator = mpc.ETruncPR(denominator, mpc.K, mpc.FPPrecBits)

	df := 1.0 / float64(numRows*numRows-numRows)
	denominator = mpc.ECMultFP(denominator, big.NewFloat(df))

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", mpc.RevealFP(numerator, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealFP(denominator, mpc.FPPrecBits).String())
	}

	// convert to shares for division
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (share): %s\n", mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (share): %s\n", mpc.RevealShare(denominatorShare).String())
	}

	// end paillier benchmark
	endTimePaillier := time.Now()

	res := mpc.FPDivision(numeratorShare, denominatorShare)
	tstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)

	// end division benchmark
	endTime := time.Now()

	tstat := tstat2.Sqrt(tstat2)

	if debug {
		fmt.Printf("[DEBUG] T-STATISTIC, t = %f\n", tstat)
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	// compute all the runtimes
	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:             "T-TEST",
		Value:            tstat,
		NumRows:          len(x),
		NumColumns:       2,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		SetupTime:        dealerSetupTime,
		NumSharesCreated: mpc.DeleteAllShares(),
	}
}
