package main

import (
	"encoding/csv"
	"fmt"
	"hypocert"
	"hypocert/party"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

func exampleChiSquaredSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, int, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	x, err := parseCategoricalDataset(filepath)
	if err != nil {
		panic(err)
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
			residual[i] = mpc.Pk.ESub(h[i], expectedValues[i])
			residual[i] = mpc.EMult(residual[i], residual[i])
		}(i)
	}
	wg.Wait()

	residualShares := make([]*node.Share, numCategories)
	expectedValueShares := make([]*node.Share, numCategories)

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
	xi := make([]*node.Share, numCategories)
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

	return chi2Stat, numRows, numCategories, totalTime, paillierTime, divTime, mpc.DeleteAllShares()
}

// Simulation of Pearson's coorelation coefficient
func examplePearsonsTestSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	x, y, err := parseDataset(filepath)
	if err != nil {
		panic(err)
	}
	// mini test dataset
	// x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	// y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}
	//result should be 0.96...

	if debug {
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

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// an encryption of zero to be used as initial value
	enc0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.FPPrecBits))

	// sum of the squares
	sumX := enc0
	sumY := enc0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])
	}

	meanX := mpc.ECMultFP(sumX, invNumRows)
	meanY := mpc.ECMultFP(sumY, invNumRows)

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*paillier.Ciphertext, numRows)

	// (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, numRows)

	// (y_i - mean_y)^2
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
	sumXY := enc0
	sumDevX2 := enc0
	sumDevY2 := enc0

	for i := 0; i < numRows; i++ {
		sumXY = mpc.Pk.EAdd(sumXY, prodsXY[i])
		sumDevX2 = mpc.Pk.EAdd(sumDevX2, devsX2[i])
		sumDevY2 = mpc.Pk.EAdd(sumDevY2, devsY2[i])
	}

	// adjust the prec after mult
	sumXY = mpc.ETruncPR(sumXY, mpc.K, mpc.FPPrecBits)
	sumDevX2 = mpc.ETruncPR(sumDevX2, mpc.K, mpc.FPPrecBits)
	sumDevY2 = mpc.ETruncPR(sumDevY2, mpc.K, mpc.FPPrecBits)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := sumXY

	denominator := mpc.EFPMult(sumDevX2, sumDevY2)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n", mpc.RevealInt(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealInt(denominator).String())
	}

	// convert to shares
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	// done with paillier computations
	endTimePaillier := time.Now()

	//the threshold for negative reps
	threshold := big.NewInt(0).Div(mpc.P, big.NewInt(2))

	//extract the sign bit
	numeratorShareBits := mpc.BitsDec(numeratorShare, mpc.K)
	sign := mpc.BitsLT(mpc.BitsBigEndian(threshold, mpc.K), numeratorShareBits)

	// done with paillier computations
	endTimeCmp := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Share):   %s\n", mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (Share): %s\n", mpc.RevealShare(denominatorShare).String())
		fmt.Printf("[DEBUG] SIGN BIT (Share):    %s\n", mpc.RevealShare(sign).String())
	}

	// square the numerator
	numeratorShare = mpc.Mult(numeratorShare, numeratorShare)
	numeratorShare = mpc.TruncPR(numeratorShare, mpc.K, mpc.FPPrecBits)

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	signBit := mpc.RevealShare(sign)

	pstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	pstat := pstat2.Sqrt(pstat2)
	pstat = big.NewFloat(0).Sub(pstat, big.NewFloat(0).Mul(big.NewFloat(2*float64(signBit.Int64())), pstat)) // pstat - 2*sign*pstat

	endTime := time.Now()

	if debug {
		fmt.Printf("PEARSON STATISTIC, p = %s\n", pstat.String())
		fmt.Println("Runtime: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	cmpTime := endTimeCmp.Sub(endTimePaillier)
	divTime := time.Now().Sub(endTimeCmp)
	paillierTime := endTimePaillier.Sub(startTime)

	numShares := mpc.DeleteAllShares()

	return pstat, len(x), totalTime, paillierTime, cmpTime, divTime, numShares
}

func exampleTTestSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	x, y, err := parseDataset(filepath)
	if err != nil {
		panic(err)
	}

	// mini test dataset
	// x = []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	// y = []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}
	// result should be 1.99...

	if debug {
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

	// encryption of zero for init value
	e0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.FPPrecBits))

	// compute sum x and sum y
	sumX := e0
	sumY := e0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])
	}

	meanX := mpc.ECMult(sumX, mpc.Pk.EncodeFixedPoint(invNumRows, mpc.FPPrecBits))
	meanX = mpc.ETruncPR(meanX, mpc.K, mpc.FPPrecBits)
	meanY := mpc.ECMult(sumY, mpc.Pk.EncodeFixedPoint(invNumRows, mpc.FPPrecBits))
	meanY = mpc.ETruncPR(meanY, mpc.K, mpc.FPPrecBits)

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
	sdX := e0
	sdY := e0
	for i := 0; i < numRows; i++ {
		sdX = mpc.Pk.EAdd(sdX, sumsSdX[i])
		sdY = mpc.Pk.EAdd(sdY, sumsSdY[i])
	}

	sdX = mpc.ETruncPR(sdX, mpc.K, mpc.FPPrecBits)
	sdY = mpc.ETruncPR(sdY, mpc.K, mpc.FPPrecBits)
	sdX = mpc.ECMultFP(sdX, big.NewFloat(1.0/float64(numRows-1)))
	sdY = mpc.ECMultFP(sdY, big.NewFloat(1.0/float64(numRows-1)))

	numerator := mpc.Pk.ESub(meanX, meanY)
	numerator = mpc.EFPMult(numerator, numerator)

	tx := mpc.Pk.ESub(mpc.ECMult(sdX, big.NewInt(int64(numRows))), sdX)
	ty := mpc.Pk.ESub(mpc.ECMult(sdY, big.NewInt(int64(numRows))), sdY)

	denominator := mpc.Pk.EAdd(tx, ty)

	df := 1.0 / float64(numRows*numRows-numRows)
	denominator = mpc.ECMultFP(denominator, big.NewFloat(df))

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", mpc.RevealInt(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealInt(denominator).String())
	}

	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (share): %s\n", mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (share): %s\n", mpc.RevealShare(denominatorShare).String())
	}

	endTimePaillier := time.Now()

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	tstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	endTime := time.Now()

	tstat := tstat2.Sqrt(tstat2)

	if debug {
		fmt.Printf("T STATISTIC, p = %f\n", tstat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	numShares := mpc.DeleteAllShares()

	return tstat, len(x), totalTime, paillierTime, divTime, numShares
}

func exampleChiSquaredSimulationWithSecretSharing(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, int, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	x, err := parseCategoricalDataset(filepath)
	if err != nil {
		panic(err)
	}

	numCategories := len(x[0])
	numRows := len(x)

	var eX [][]*node.Share
	eX = make([][]*node.Share, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eX[i] = make([]*node.Share, numCategories)
			for j := 0; j < numCategories; j++ {
				pt := mpc.Pk.EncodeFixedPoint(big.NewFloat(float64(x[i][j])), mpc.FPPrecBits)
				eX[i][j] = mpc.CreateShares(pt)
			}
		}(i)
	}

	wg.Wait()

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
	e0 := mpc.CreateShares(big.NewInt(0))

	// compute encrypted histogram
	h := make([]*node.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		categorySum := e0
		for j := 0; j < numRows; j++ {
			categorySum = mpc.Add(categorySum, eX[j][i])
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
		sumTotal = mpc.Add(sumTotal, h[i])
	}

	expectedValues := make([]*node.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			expected := mpc.MultC(sumTotal, mpc.EncodeFixedPoint(expectedPercentage[i], mpc.FPPrecBits))
			expectedValues[i] = mpc.TruncPR(expected, mpc.K, mpc.FPPrecBits)
		}(i)
	}
	wg.Wait()

	// compute the residuals
	residual := make([]*node.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			diff := mpc.Sub(h[i], expectedValues[i])
			residual[i] = mpc.Mult(diff, diff)
		}(i)
	}
	wg.Wait()

	endTimePaillier := time.Now()

	// perform division and summation
	xi := make([]*node.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			xi[i] = mpc.FPDivision(residual[i], expectedValues[i])
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
	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	if debug {
		fmt.Printf("CHI^2 STATISTIC, x2 = %f\n", chi2Stat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	return chi2Stat, numRows, numCategories, totalTime, paillierTime, divTime, mpc.DeleteAllShares()
}

func exampleTTestSimulationWithSecretSharing(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	x, y, err := parseDataset(filepath)
	if err != nil {
		panic(err)
	}

	// mini test dataset
	// x = []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	// y = []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}
	// result should be 1.99...

	if debug {
		fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
	}

	numRows := len(y)

	eX := make([]*node.Share, numRows)
	eY := make([]*node.Share, numRows)

	for i := 0; i < numRows; i++ {
		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
		eX[i] = mpc.CreateShares(plaintextX)
		eY[i] = mpc.CreateShares(plaintextY)
	}

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	if debug {
		fmt.Println("[DEBUG] Finished encrypting dataset")
	}

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	invNumRows := mpc.Pk.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows)), mpc.FPPrecBits)

	// an encryption of zero to be used as initial value
	enc0 := mpc.CreateShares(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.FPPrecBits))

	// sum of the squares
	sumX := enc0
	sumY := enc0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Add(sumX, eX[i])
		sumY = mpc.Add(sumY, eY[i])
	}

	meanX := mpc.MultC(sumX, invNumRows)
	meanX = mpc.TruncPR(meanX, mpc.K, mpc.FPPrecBits)
	meanY := mpc.MultC(sumY, invNumRows)
	meanY = mpc.TruncPR(meanY, mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X:   %s\n", mpc.RevealShareFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y:   %s\n", mpc.RevealShareFP(meanY, mpc.FPPrecBits).String())
	}

	sumsSdX := make([]*node.Share, numRows)
	sumsSdY := make([]*node.Share, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sdx := mpc.Sub(eX[i], meanX)
			sdy := mpc.Sub(eY[i], meanY)
			sumsSdX[i] = mpc.Mult(sdx, sdx)
			sumsSdY[i] = mpc.Mult(sdy, sdy)
		}(i)
	}

	wg.Wait()

	// compute the standard deviation
	sdX := enc0
	sdY := enc0
	for i := 0; i < numRows; i++ {
		sdX = mpc.Add(sdX, sumsSdX[i])
		sdY = mpc.Add(sdY, sumsSdY[i])
	}

	sdX = mpc.TruncPR(sdX, mpc.K, mpc.FPPrecBits)
	sdY = mpc.TruncPR(sdY, mpc.K, mpc.FPPrecBits)
	sdX = mpc.MultC(sdX, mpc.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows-1)), mpc.FPPrecBits))
	sdX = mpc.TruncPR(sdX, mpc.K, mpc.FPPrecBits)
	sdY = mpc.MultC(sdY, mpc.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows-1)), mpc.FPPrecBits))
	sdY = mpc.TruncPR(sdY, mpc.K, mpc.FPPrecBits)

	numerator := mpc.Sub(meanX, meanY)
	numerator = mpc.Mult(numerator, numerator)
	numerator = mpc.TruncPR(numerator, mpc.K, mpc.FPPrecBits)

	tx := mpc.Sub(mpc.MultC(sdX, big.NewInt(int64(numRows))), sdX)
	ty := mpc.Sub(mpc.MultC(sdY, big.NewInt(int64(numRows))), sdY)

	denominator := mpc.Add(tx, ty)

	df := 1.0 / float64(numRows*numRows-numRows)
	denominator = mpc.MultC(denominator, mpc.EncodeFixedPoint(big.NewFloat(df), mpc.FPPrecBits))
	denominator = mpc.TruncPR(denominator, mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", mpc.RevealShare(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealShare(denominator).String())
	}

	endTimeComp := time.Now()

	res := mpc.FPDivision(numerator, denominator)

	tstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	endTime := time.Now()

	tstat := tstat2.Sqrt(tstat2)

	if debug {
		fmt.Printf("T STATISTIC, p = %f\n", tstat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimeComp)
	compTime := endTimeComp.Sub(startTime)

	numShares := mpc.DeleteAllShares()

	return tstat, len(x), totalTime, compTime, divTime, numShares
}

// Simulation of Pearson's coorelation coefficient
func examplePearsonsTestSimulationWihSecretSharing(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	x, y, err := parseDataset(filepath)
	if err != nil {
		panic(err)
	}
	// // mini test dataset
	// x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	// y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}
	//result should be 0.96...

	if debug {
		fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
	}

	numRows := len(y)

	eX := make([]*node.Share, numRows)
	eY := make([]*node.Share, numRows)

	for i := 0; i < numRows; i++ {
		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
		eX[i] = mpc.CreateShares(plaintextX)
		eY[i] = mpc.CreateShares(plaintextY)
	}

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	invNumRows := mpc.Pk.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows)), mpc.FPPrecBits)

	// an encryption of zero to be used as initial value
	enc0 := mpc.CreateShares(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.FPPrecBits))

	// sum of the squares
	sumX := enc0
	sumY := enc0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Add(sumX, eX[i])
		sumY = mpc.Add(sumY, eY[i])
	}

	meanX := mpc.MultC(sumX, invNumRows)
	meanX = mpc.TruncPR(meanX, mpc.K, mpc.FPPrecBits)
	meanY := mpc.MultC(sumY, invNumRows)
	meanY = mpc.TruncPR(meanY, mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X:   %s\n", mpc.RevealShare(meanX).String())
		fmt.Printf("[DEBUG] MEAN Y:   %s\n", mpc.RevealShare(meanY).String())
	}

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*node.Share, numRows)

	// (x_i - mean_x)^2
	devsX2 := make([]*node.Share, numRows)

	// (y_i - mean_y)^2
	devsY2 := make([]*node.Share, numRows)

	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			devX := mpc.Sub(eX[i], meanX)
			devY := mpc.Sub(eY[i], meanY)
			devsX2[i] = mpc.Mult(devX, devX)
			devsY2[i] = mpc.Mult(devY, devY)
			prodsXY[i] = mpc.Mult(devX, devY)
		}(i)
	}

	wg.Wait()

	// compute sum for all i (x_i - mean_x)(y_i - mean_y)
	sumXY := enc0
	sumDevX2 := enc0
	sumDevY2 := enc0

	for i := 0; i < numRows; i++ {
		sumXY = mpc.Add(sumXY, prodsXY[i])
		sumDevX2 = mpc.Add(sumDevX2, devsX2[i])
		sumDevY2 = mpc.Add(sumDevY2, devsY2[i])
	}

	// adjust the prec after mult
	sumXY = mpc.TruncPR(sumXY, mpc.K, mpc.FPPrecBits)
	sumDevX2 = mpc.TruncPR(sumDevX2, mpc.K, mpc.FPPrecBits)
	sumDevY2 = mpc.TruncPR(sumDevY2, mpc.K, mpc.FPPrecBits)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := sumXY

	denominator := mpc.Mult(sumDevX2, sumDevY2)
	denominator = mpc.TruncPR(denominator, mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n", mpc.RevealShare(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealShare(denominator).String())
	}

	startCmpTime := time.Now()

	//the threshold for negative reps
	threshold := big.NewInt(0).Div(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K)), nil), big.NewInt(2))

	//extract the sign bit
	numeratorBits := mpc.BitsDec(numerator, mpc.K)
	sign := mpc.BitsLT(mpc.BitsBigEndian(threshold, mpc.P.BitLen()), numeratorBits)

	endCmpTime := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] SIGN BIT (Share):    %s\n", mpc.RevealShare(sign).String())
	}

	// square the numerator
	numerator = mpc.Mult(numerator, numerator)
	numerator = mpc.TruncPR(numerator, mpc.K, mpc.FPPrecBits)

	// done with computations
	endTimeComp := time.Now()

	res := mpc.FPDivision(numerator, denominator)

	signBit := mpc.RevealShare(sign)

	pstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	pstat := pstat2.Sqrt(pstat2)
	pstat = big.NewFloat(0).Sub(pstat, big.NewFloat(0).Mul(big.NewFloat(2*float64(signBit.Int64())), pstat)) // pstat - 2*sign*pstat

	endTime := time.Now()

	if debug {
		fmt.Printf("PEARSON STATISTIC, p = %s\n", pstat.String())
		fmt.Println("Runtime: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	cmpTime := endCmpTime.Sub(startCmpTime)
	divTime := time.Now().Sub(endTimeComp)
	computeTime := endTimeComp.Sub(startTime)
	computeTime = computeTime - cmpTime

	numShares := mpc.DeleteAllShares()

	return pstat, len(x), totalTime, computeTime, cmpTime, divTime, numShares
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
