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
func PearsonsTestSimulation(
	mpc *hypocert.MPC,
	dataset *EncryptedDataset,
	debug bool) *TestResult {

	eX := dataset.Data[0]
	eY := dataset.Data[1]

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(dataset.NumRows))
	invNumRowsEncoded := mpc.Pk.EncodeFixedPoint(invNumRows, mpc.FPPrecBits)

	// sum of the squares
	sumX := mpc.Pk.EAdd(eX...)
	sumY := mpc.Pk.EAdd(eY...)

	meanXTmp := mpc.Pk.ECMult(sumX, invNumRowsEncoded)
	meanYTmp := mpc.Pk.ECMult(sumY, invNumRowsEncoded)

	meanX := mpc.ETruncPR(meanXTmp, mpc.K, mpc.FPPrecBits)
	meanY := mpc.ETruncPR(meanYTmp, mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n",
			mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n",
			mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (y_i - mean_y)^2
	devsY2 := make([]*paillier.Ciphertext, dataset.NumRows)

	var wg sync.WaitGroup
	wg.Add(dataset.NumRows)

	for i := 0; i < dataset.NumRows; i++ {
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
	sumDevX2 = mpc.ETruncPR(sumDevX2, 2*mpc.K, mpc.FPPrecBits)
	sumDevY2 = mpc.ETruncPR(sumDevY2, 2*mpc.K, mpc.FPPrecBits)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := sumXY

	denominatorTmp := mpc.EMult(sumDevX2, sumDevY2)
	denominator := mpc.ETruncPR(denominatorTmp, 2*mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n",
			mpc.RevealFP(numerator, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n",
			mpc.RevealFP(denominator, mpc.FPPrecBits).String())
	}

	// convert to shares
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	// done with paillier computations
	endTimePaillier := time.Now()

	startTimeSign := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Share):   %s\n",
			mpc.RevealShareFP(numeratorShare, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR (Share): %s\n",
			mpc.RevealShareFP(denominatorShare, mpc.FPPrecBits).String())
	}

	signbit := mpc.SignBit(numeratorShare)

	// reveal the sign bit since it's made public at the end regardless
	isNegative := mpc.RevealShare(signbit).Int64()

	endTimeSign := time.Now()

	rcpr := mpc.FPSqrtReciprocal(denominatorShare)

	if isNegative == 1 {
		numeratorShare = mpc.MultC(numeratorShare, new(big.Int).Sub(mpc.P, big.NewInt(1)))
		if debug {
			fmt.Printf("[DEBUG] NUMERATOR (abs): %s\n",
				mpc.RevealShare(numeratorShare).String())
		}
	}
	numeratorShare = mpc.TruncPR(numeratorShare, 2*mpc.K, mpc.FPPrecBits)
	precAdjust := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K/2-mpc.FPPrecBits)), nil)
	numeratorShare = mpc.MultC(numeratorShare, precAdjust)

	res := mpc.Mult(numeratorShare, rcpr)
	rstat := mpc.RevealShareFP(res, mpc.K)

	if isNegative == 1 {
		rstat.Mul(rstat, big.NewFloat(-1))
	}

	endTime := time.Now()

	if debug {
		fmt.Printf("[DEBUG] PEARSON CORRELATION STATISTIC, r = %s\n", rstat.String())
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	signExtractionTime := endTimeSign.Sub(startTimeSign)
	divTime := time.Now().Sub(endTimeSign)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:                  "PEARSON",
		Value:                 rstat,
		TotalRuntime:          totalTime,
		ComputeRuntime:        paillierTime,
		SignExtractionRuntime: signExtractionTime,
		DivRuntime:            divTime,
		NumSharesCreated:      mpc.DeleteAllShares(),
	}
}
