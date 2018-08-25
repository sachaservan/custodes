package main

import (
	"fmt"
	"hypocert"
	"hypocert/party"
	"log"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

func ChiSquaredTestSimulation(mpc *hypocert.MPC, filepath string, debug bool, example bool) *TestResult {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

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
		fmt.Println("   -------------------------------------")
		fmt.Print("X: |")
		for i := 0; i < len(x); i++ {
			fmt.Print("(" + strconv.Itoa(int(x[i][0])) + ", " + strconv.Itoa(int(x[i][1])) + ")")
			if i+1 < len(x) {
				fmt.Print(", ")
			} else {
				fmt.Println("|")
			}
		}
		fmt.Println("   -------------------------------------")
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
				pt := mpc.Pk.EncodeFixedPoint(big.NewFloat(float64(x[i][j])), mpc.FPPrecBits)
				eX[i][j] = mpc.Pk.Encrypt(pt)
			}
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
		fmt.Println("[DEBUG] Dealer setup done...")
	}

	// keep track of runtime
	startTime := time.Now()

	// encryption of zero for init value
	e0 := mpc.Pk.Encrypt(big.NewInt(0))

	// compute encrypted histogram
	h := make([]*paillier.Ciphertext, numCategories)
	for i := 0; i < numCategories; i++ {
		categorySum := e0
		for j := 0; j < numRows; j++ {
			categorySum = mpc.Pk.EAdd(categorySum, eX[j][i])
		}

		h[i] = categorySum
	}

	// compute expected percentages per category
	expectedPercentage := make([]*big.Float, numCategories)
	for i := 0; i < numCategories; i++ {
		expectedPercentage[i] = big.NewFloat(1.0 / float64(numCategories))
	}

	// compute the expected value
	sumTotal := e0
	for i := 0; i < numCategories; i++ {
		sumTotal = mpc.Pk.EAdd(sumTotal, h[i])
	}

	expectedValues := make([]*paillier.Ciphertext, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			expectedValues[i] = mpc.ECMultFP(sumTotal, expectedPercentage[i])
		}(i)
	}
	wg.Wait()

	// compute the residuals
	residual := make([]*paillier.Ciphertext, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := mpc.Pk.ESub(h[i], expectedValues[i])
			residual[i] = mpc.EMult(res, res)
		}(i)
	}
	wg.Wait()

	residualShares := make([]*party.Share, numCategories)
	expectedValueShares := make([]*party.Share, numCategories)

	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			residualShares[i] = mpc.PaillierToShare(residual[i])
			expectedValueShares[i] = mpc.PaillierToShare(expectedValues[i])
		}(i)
	}
	wg.Wait()

	endTimePaillier := time.Now()

	// perform division and summation
	xi := make([]*party.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			xi[i] = mpc.FPDivision(residualShares[i], expectedValueShares[i])
		}(i)
	}
	wg.Wait()

	chi2 := mpc.CreateShares(big.NewInt(0))
	for i := 0; i < numCategories; i++ {
		chi2 = mpc.Add(chi2, xi[i])
	}

	chi2 = mpc.TruncPR(chi2, mpc.K, mpc.FPPrecBits)
	chi2Stat := mpc.RevealShareFP(chi2, mpc.FPPrecBits)
	endTime := time.Now()

	if debug {
		fmt.Printf("CHI^2 STATISTIC, x2 = %f\n", chi2Stat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:             "CHI2",
		Value:            chi2Stat,
		NumRows:          numRows,
		NumColumns:       numCategories,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		SetupTime:        dealerSetupTime,
		NumSharesCreated: mpc.DeleteAllShares(),
	}
}
