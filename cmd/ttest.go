package main

import (
	"fmt"
	"hypocert"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

func TTestSimulation(
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

	meanX := mpc.ETruncPR(meanXTmp, 2*mpc.K, mpc.FPPrecBits)
	meanY := mpc.ETruncPR(meanYTmp, 2*mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	sumdX := make([]*paillier.Ciphertext, dataset.NumRows)
	sumdY := make([]*paillier.Ciphertext, dataset.NumRows)

	var wg sync.WaitGroup
	wg.Add(dataset.NumRows)
	for i := 0; i < dataset.NumRows; i++ {
		go func(i int) {
			defer wg.Done()
			dx := mpc.Pk.ESub(eX[i], meanX)
			dy := mpc.Pk.ESub(eY[i], meanY)
			sumdX[i] = mpc.EMult(dx, dx)
			sumdY[i] = mpc.EMult(dy, dy)

		}(i)
	}
	wg.Wait()

	// compute the standard deviation
	dXtmp := mpc.Pk.EAdd(sumdX...)
	dYtmp := mpc.Pk.EAdd(sumdY...)

	dX := mpc.ETruncPR(dXtmp, 2*mpc.K, mpc.FPPrecBits)
	dY := mpc.ETruncPR(dYtmp, 2*mpc.K, mpc.FPPrecBits)

	// compute numerator
	numerator := mpc.Pk.ESub(meanX, meanY)

	// compute denominator
	denominatorTmp := mpc.Pk.EAdd(dX, dY)

	df := mpc.Pk.EncodeFixedPoint(
		big.NewFloat(1.0/float64(dataset.NumRows*dataset.NumRows-dataset.NumRows)),
		mpc.FPPrecBits)
	denominatorTmp = mpc.Pk.ECMult(denominatorTmp, df)
	denominator := mpc.ETruncPR(denominatorTmp, 2*mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n",
			mpc.RevealFP(numerator, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n",
			mpc.RevealFP(denominator, mpc.FPPrecBits).String())
	}

	// convert to shares for division
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	numerator = mpc.EMult(numerator, numerator)
	fmt.Printf("[DEBUG] NUMERATOR SQ (abs): %s\n",
		new(big.Int).Sqrt(mpc.RevealInt(numerator)).String())

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (share): %s\n",
			mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (share): %s\n",
			mpc.RevealShare(denominatorShare).String())
	}

	// end paillier benchmark
	endTimePaillier := time.Now()

	startTimeSign := time.Now()

	signbit := mpc.SignBit(numeratorShare)

	// reveal the sign bit since it's made public at the end regardless
	isNegative := mpc.RevealShare(signbit).Int64()

	if isNegative == 1 {
		numeratorShare = mpc.MultC(numeratorShare, new(big.Int).Sub(mpc.P, big.NewInt(1)))

		if debug {
			fmt.Printf("[DEBUG] NUMERATOR (abs): %s\n",
				mpc.RevealShare(numeratorShare).String())
		}
	}

	endTimeSign := time.Now()

	rcpr := mpc.FPSqrtReciprocal(denominatorShare)

	precAdjust := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K/2-mpc.FPPrecBits)), nil)
	numeratorShare = mpc.MultC(numeratorShare, precAdjust)

	res := mpc.Mult(numeratorShare, rcpr)

	tstat := mpc.RevealShareFP(res, mpc.K)

	if isNegative == 1 {
		tstat.Mul(tstat, big.NewFloat(-1))
	}

	// end division benchmark
	endTime := time.Now()

	if debug {
		fmt.Printf("[DEBUG] T-STATISTIC, t = %f\n", tstat)
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	// compute all the runtimes
	totalTime := endTime.Sub(startTime)
	signExtractionTime := endTimeSign.Sub(startTimeSign)
	divTime := time.Now().Sub(endTimeSign)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:                  "T-TEST",
		Value:                 tstat,
		TotalRuntime:          totalTime,
		ComputeRuntime:        paillierTime,
		SignExtractionRuntime: signExtractionTime,
		DivRuntime:            divTime,
		NumSharesCreated:      mpc.DeleteAllShares(),
	}
}
