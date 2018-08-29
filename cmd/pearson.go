package main

import (
	"fmt"
	"hypocert"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

// Simulation of Pearson's coorelation coefficient
func PearsonsTestSimulation(mpc *hypocert.MPC, dataset *EncryptedDataset, debug bool) *TestResult {

	eX := dataset.Data[0]
	eY := dataset.Data[1]

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	invNumRows := big.NewFloat(1.0 / float64(dataset.NumRows))

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
	prodsXY := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (y_i - mean_y)^2
	devsY2 := make([]*paillier.Ciphertext, dataset.NumRows)

	var wg sync.WaitGroup
	for i := 0; i < dataset.NumRows; i++ {
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
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		NumSharesCreated: mpc.DeleteAllShares(),
	}
}
