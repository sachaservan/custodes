package main

import (
	"fmt"
	"hypocert"
	"hypocert/party"
	"log"
	"math/big"
	"sync"
	"time"
)

func ChiSquaredSecretSharingSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, int, time.Duration, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	dealerSetupStart := time.Now()

	x, err := parseCategoricalDataset(filepath)
	if err != nil {
		panic(err)
	}

	numCategories := len(x[0])
	numRows := len(x)

	var eX [][]*party.Share
	eX = make([][]*party.Share, numRows)

	for i := 0; i < numRows; i++ {

		eX[i] = make([]*party.Share, numCategories)
		for j := 0; j < numCategories; j++ {
			pt := mpc.Pk.EncodeFixedPoint(big.NewFloat(float64(x[i][j])), mpc.FPPrecBits)
			eX[i][j] = mpc.CreateShares(pt)
		}
	}

	dealerSetupTime := time.Now().Sub(dealerSetupStart)

	//**************************************************************************************
	//**************************************************************************************
	// END DEALER CODE
	//**************************************************************************************
	//**************************************************************************************

	var wg sync.WaitGroup

	if debug {
		fmt.Println("[DEBUG] Dealer setup done...")
	}

	// keep track of runtime
	startTime := time.Now()

	// encryption of zero for init value
	e0 := mpc.CreateShares(big.NewInt(0))

	// compute encrypted histogram
	h := make([]*party.Share, numCategories)
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

	expectedValues := make([]*party.Share, numCategories)
	for i := 0; i < numCategories; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			expected := mpc.MultC(sumTotal, mpc.EncodeFixedPoint(expectedPercentage[i], mpc.FPPrecBits))
			expectedValues[i] = mpc.TruncPR(expected, 2*mpc.K, mpc.FPPrecBits)
		}(i)
	}
	wg.Wait()

	// compute the residuals
	residual := make([]*party.Share, numCategories)
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
	xi := make([]*party.Share, numCategories)
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

	chi2 = mpc.TruncPR(chi2, 2*mpc.K, mpc.FPPrecBits)
	chi2Stat := mpc.RevealShareFP(chi2, mpc.FPPrecBits)

	endTime := time.Now()
	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	if debug {
		fmt.Printf("CHI^2 STATISTIC, x2 = %f\n", chi2Stat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	return chi2Stat, numRows, numCategories, dealerSetupTime, totalTime, paillierTime, divTime, mpc.DeleteAllShares()
}

func TTestSecretSharingSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	dealerSetupStart := time.Now()
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

	eX := make([]*party.Share, numRows)
	eY := make([]*party.Share, numRows)

	for i := 0; i < numRows; i++ {
		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
		eX[i] = mpc.CreateShares(plaintextX)
		eY[i] = mpc.CreateShares(plaintextY)
	}

	dealerSetupTime := time.Now().Sub(dealerSetupStart)

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
	meanX = mpc.TruncPR(meanX, 2*mpc.K, mpc.FPPrecBits)
	meanY := mpc.MultC(sumY, invNumRows)
	meanY = mpc.TruncPR(meanY, 2*mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X:   %s\n", mpc.RevealShareFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y:   %s\n", mpc.RevealShareFP(meanY, mpc.FPPrecBits).String())
	}

	sumsSdX := make([]*party.Share, numRows)
	sumsSdY := make([]*party.Share, numRows)

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

	sdX = mpc.TruncPR(sdX, 2*mpc.K, mpc.FPPrecBits)
	sdY = mpc.TruncPR(sdY, 2*mpc.K, mpc.FPPrecBits)
	sdX = mpc.MultC(sdX, mpc.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows-1)), mpc.FPPrecBits))
	sdX = mpc.TruncPR(sdX, 2*mpc.K, mpc.FPPrecBits)
	sdY = mpc.MultC(sdY, mpc.EncodeFixedPoint(big.NewFloat(1.0/float64(numRows-1)), mpc.FPPrecBits))
	sdY = mpc.TruncPR(sdY, 2*mpc.K, mpc.FPPrecBits)

	numerator := mpc.Sub(meanX, meanY)
	numerator = mpc.Mult(numerator, numerator)
	numerator = mpc.TruncPR(numerator, 2*mpc.K, mpc.FPPrecBits)

	tx := mpc.Sub(mpc.MultC(sdX, big.NewInt(int64(numRows))), sdX)
	ty := mpc.Sub(mpc.MultC(sdY, big.NewInt(int64(numRows))), sdY)

	denominator := mpc.Add(tx, ty)

	df := 1.0 / float64(numRows*numRows-numRows)
	denominator = mpc.MultC(denominator, mpc.EncodeFixedPoint(big.NewFloat(df), mpc.FPPrecBits))
	denominator = mpc.TruncPR(denominator, 2*mpc.K, mpc.FPPrecBits)

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

	return tstat, len(x), dealerSetupTime, totalTime, compTime, divTime, numShares
}

// Simulation of Pearson's coorelation coefficient
func PearsonsTestSecretSharingSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, time.Duration, int) {

	//**************************************************************************************
	//**************************************************************************************
	// START DEALER CODE
	//**************************************************************************************
	//**************************************************************************************
	dealerSetupStart := time.Now()

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

	eX := make([]*party.Share, numRows)
	eY := make([]*party.Share, numRows)

	for i := 0; i < numRows; i++ {
		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.FPPrecBits)
		eX[i] = mpc.CreateShares(plaintextX)
		eY[i] = mpc.CreateShares(plaintextY)
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
	meanX = mpc.TruncPR(meanX, 2*mpc.K, mpc.FPPrecBits)
	meanY := mpc.MultC(sumY, invNumRows)
	meanY = mpc.TruncPR(meanY, 2*mpc.K, mpc.FPPrecBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X:   %s\n", mpc.RevealShareFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y:   %s\n", mpc.RevealShareFP(meanY, mpc.FPPrecBits).String())
	}

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*party.Share, numRows)

	// (x_i - mean_x)^2
	devsX2 := make([]*party.Share, numRows)

	// (y_i - mean_y)^2
	devsY2 := make([]*party.Share, numRows)

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
	sumXY = mpc.TruncPR(sumXY, 2*mpc.K, mpc.FPPrecBits)
	sumDevX2 = mpc.TruncPR(sumDevX2, 2*mpc.K, mpc.FPPrecBits)
	sumDevY2 = mpc.TruncPR(sumDevY2, 2*mpc.K, mpc.FPPrecBits)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := sumXY

	denominator := mpc.Mult(sumDevX2, sumDevY2)
	denominator = mpc.TruncPR(denominator, 2*mpc.K, mpc.FPPrecBits)

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
	numerator = mpc.TruncPR(numerator, 2*mpc.K, mpc.FPPrecBits)

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

	return pstat, len(x), dealerSetupTime, totalTime, computeTime, divTime, numShares
}
