package main

import (
	"encoding/csv"
	"fmt"
	"hypocert"
	"hypocertnode"
	"io"
	"log"
	"math/big"
	"os"
	"paillier"
	"strconv"
	"sync"
	"time"
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
				pt := mpc.Pk.EncodeFixedPoint(big.NewFloat(float64(x[i][j])), mpc.Pk.FPPrecBits)
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
			expectedValues[i] = mpc.ECMult(sumTotal, mpc.EncodeFixedPoint(expectedPercentage[i], mpc.Pk.FPPrecBits))
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
			residual[i] = mpc.EFPMult(residual[i], residual[i])
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
			residualShare := mpc.PaillierToShare(residual[i])
			residualShare = mpc.TruncPR(residualShare, 2*mpc.Pk.K, 2*mpc.Pk.FPPrecBits)
			expectedValueShare := mpc.PaillierToShare(expectedValues[i])
			expectedValueShare = mpc.TruncPR(expectedValueShare, mpc.Pk.K, mpc.Pk.FPPrecBits)
			xi[i] = mpc.FPDivision(residualShare, expectedValueShare)
		}(i)
	}
	wg.Wait()

	chi2 := mpc.CreateShares(big.NewInt(0))
	for i := 0; i < numCategories; i++ {
		chi2 = mpc.Add(chi2, xi[i])
	}

	chi2Stat := mpc.RevealShareFP(chi2, mpc.Pk.FPPrecBits)
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
func examplePearsonsTestSimulation(mpc *hypocert.MPC, filepath string, debug bool) (*big.Float, int, time.Duration, time.Duration, time.Duration, int) {

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
		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.Pk.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.Pk.FPPrecBits)
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
	enc0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.Pk.FPPrecBits))

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
	sumXY = mpc.ETruncPR(sumXY, mpc.Pk.K, mpc.Pk.FPPrecBits)
	sumDevX2 = mpc.ETruncPR(sumDevX2, mpc.Pk.K, mpc.Pk.FPPrecBits)
	sumDevY2 = mpc.ETruncPR(sumDevY2, mpc.Pk.K, mpc.Pk.FPPrecBits)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numerator := sumXY

	denominator := mpc.EFPMult(sumDevX2, sumDevY2)

	// done with paillier computations
	endTimePaillier := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n", mpc.RevealInt(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", mpc.RevealInt(denominator).String())
	}

	// convert to shares
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	//the threshold for negative reps
	threshold := big.NewInt(0).Div(mpc.Pk.P, big.NewInt(2))

	//extract the sign bit
	numeratorShareBits := mpc.BitsDec(numeratorShare, mpc.Pk.K)
	sign := mpc.BitsLT(mpc.BitsBigEndian(threshold, mpc.Pk.K), numeratorShareBits)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Share):   %s\n", mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (Share): %s\n", mpc.RevealShare(denominatorShare).String())
		fmt.Printf("[DEBUG] SIGN BIT (Share):    %s\n", mpc.RevealShare(sign).String())
	}

	// square the numerator
	numeratorShare = mpc.Mult(numeratorShare, numeratorShare)
	numeratorShare = mpc.TruncPR(numeratorShare, mpc.Pk.K, mpc.Pk.FPPrecBits)

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	signBit := mpc.RevealShare(sign)

	pstat2 := mpc.RevealShareFP(res, mpc.Pk.FPPrecBits)
	pstat := pstat2.Sqrt(pstat2)
	pstat = big.NewFloat(0).Sub(pstat, big.NewFloat(0).Mul(big.NewFloat(2*float64(signBit.Int64())), pstat)) // pstat - 2*sign*pstat

	endTime := time.Now()

	if debug {
		fmt.Printf("PEARSON STATISTIC, p = %s\n", pstat.String())
		fmt.Println("Runtime: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	numShares := mpc.DeleteAllShares()

	return pstat, len(x), totalTime, paillierTime, divTime, numShares
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
			plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.Pk.FPPrecBits)
			plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.Pk.FPPrecBits)
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
	e0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.Pk.FPPrecBits))

	// compute sum x and sum y
	sumX := e0
	sumY := e0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])
	}

	meanX := mpc.ECMultFP(sumX, invNumRows)
	meanY := mpc.ECMultFP(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.Pk.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.Pk.FPPrecBits).String())
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

	sdX = mpc.ETruncPR(sdX, mpc.Pk.K, mpc.Pk.FPPrecBits)
	sdY = mpc.ETruncPR(sdY, mpc.Pk.K, mpc.Pk.FPPrecBits)
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

	endTimePaillier := time.Now()

	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (share): %s\n", mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (share): %s\n", mpc.RevealShare(denominatorShare).String())
	}

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	tstat2 := mpc.RevealShareFP(res, mpc.Pk.FPPrecBits)
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
