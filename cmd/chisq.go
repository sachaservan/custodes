package main

import (
	"fmt"
	"hypocert"
	"hypocert/party"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

func ChiSquaredTestSimulation(mpc *hypocert.MPC, encD *EncryptedDataset, debug bool) *TestResult {

	var wg sync.WaitGroup

	eX := encD.Data

	// keep track of runtime
	startTime := time.Now()

	// encryption of zero for init value
	e0 := mpc.Pk.Encrypt(big.NewInt(0))

	// compute encrypted histogram
	h := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		categorySum := e0
		for j := 0; j < encD.NumRows; j++ {
			categorySum = mpc.Pk.EAdd(categorySum, eX[j][i])
		}

		h[i] = categorySum
	}

	// compute expected percentages per category
	expectedPercentage := make([]*big.Float, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		expectedPercentage[i] = big.NewFloat(1.0 / float64(encD.NumCols))
	}

	// compute the expected value
	sumTotal := e0
	for i := 0; i < encD.NumCols; i++ {
		sumTotal = mpc.Pk.EAdd(sumTotal, h[i])
	}

	expectedValues := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			expectedValues[i] = mpc.ECMultFP(sumTotal, expectedPercentage[i])
		}(i)
	}
	wg.Wait()

	// compute the residuals
	residual := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := mpc.Pk.ESub(h[i], expectedValues[i])
			residual[i] = mpc.EMult(res, res)
		}(i)
	}
	wg.Wait()

	residualShares := make([]*party.Share, encD.NumCols)
	expectedValueShares := make([]*party.Share, encD.NumCols)

	for i := 0; i < encD.NumCols; i++ {
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
	xi := make([]*party.Share, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			xi[i] = mpc.FPDivision(residualShares[i], expectedValueShares[i])
		}(i)
	}
	wg.Wait()

	chi2 := mpc.CreateShares(big.NewInt(0))
	for i := 0; i < encD.NumCols; i++ {
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
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		NumSharesCreated: mpc.DeleteAllShares(),
	}
}
