package main

import (
	"encoding/csv"
	"fmt"
	"hypocert"
	"io"
	"log"
	"math/big"
	"os"
	"paillier"
	"strconv"
	"sync"
	"time"
)

// Simulation of Pearson's coorelation coefficient
func examplePearsonsTestSimulation(params *hypocert.MPCKeyGenParams, filepath string, debug bool) (*big.Float, time.Duration) {

	mpc := hypocert.NewMPCKeyGen(params)

	// BEGIN [DEALER]
	//**************************************************************************************

	x, y, err := parseDataset(filepath)

	if err != nil {
		panic(err)
	}

	// mini test dataset
	// x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	// y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}
	// result should be 0.96...

	if debug {
		fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
	}

	numRows := len(y)

	var eX []*paillier.Ciphertext
	eX = make([]*paillier.Ciphertext, numRows)
	var eY []*paillier.Ciphertext
	eY = make([]*paillier.Ciphertext, numRows)

	sumXActual := 0.0
	sumYActual := 0.0

	for i := 0; i < numRows; i++ {

		sumXActual += x[i]
		sumYActual += y[i]

		plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.Pk.FPPrecBits)
		plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.Pk.FPPrecBits)

		eX[i] = mpc.Pk.Encrypt(plaintextX)
		eY[i] = mpc.Pk.Encrypt(plaintextY)
	}

	//**************************************************************************************
	// END [DEALER]

	// keep track of runtime
	startTime := time.Now()

	// store for later use
	numRowsFlt := big.NewFloat(float64(numRows))

	// an encryption of zero to be used as initial value
	enc0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.Pk.FPPrecBits))

	// sum of the squares
	sumX2 := enc0
	sumY2 := enc0
	sumX := enc0
	sumY := enc0

	// compute sum of squares and sum of rows
	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])

		x2 := mpc.EFPMult(eX[i], eX[i])
		sumX2 = mpc.Pk.EAdd(sumX2, x2)

		y2 := mpc.EFPMult(eY[i], eY[i])
		sumY2 = mpc.Pk.EAdd(sumY2, y2)
	}

	// compute (sum x)^2 and (sum y)^2
	sum2X := mpc.EFPMult(sumX, sumX)
	sum2Y := mpc.EFPMult(sumY, sumY)

	// compute n*(sum x^2) - (sum x)^2
	varianceX := mpc.Pk.ESub(mpc.ECMultFP(sumX2, numRowsFlt), sum2X)

	// compute n*(sum y^2) - (sum y)^2
	varianceY := mpc.Pk.ESub(mpc.ECMultFP(sumY2, numRowsFlt), sum2Y)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] VARIANCE X: %s\n", mpc.RevealFP(varianceX, mpc.Pk.FPPrecBits).String())
		fmt.Printf("[DEBUG] VARIANCE Y: %s\n", mpc.RevealFP(varianceY, mpc.Pk.FPPrecBits).String())
	}

	// compute sum xy
	sumOfProduct := enc0
	for i := 0; i < numRows; i++ {
		sumOfProduct = mpc.Pk.EAdd(sumOfProduct, mpc.EFPMult(eX[i], eY[i]))
	}

	covariance := mpc.EFPMult(varianceY, varianceX)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] SUM OF PRODUCTS: %s\n", mpc.RevealFP(sumOfProduct, mpc.Pk.FPPrecBits).String())
		fmt.Printf("[DEBUG] COVARIANCE: %s\n", mpc.RevealFP(covariance, mpc.Pk.FPPrecBits).String())

	}

	// compute (sum x)(sum y)
	prodSums := mpc.EFPMult(sumY, sumX)

	// compute the numerator^2 = [n*(sum xy) - (sum x)(sum y)]^2
	numerator := mpc.Pk.ESub(mpc.ECMultFP(sumOfProduct, numRowsFlt), prodSums)
	numerator = mpc.EFPMult(numerator, numerator)
	denominator := covariance

	numerator = mpc.EFPTruncPR(numerator, mpc.Pk.K, mpc.Pk.FPPrecBits)
	denominator = mpc.EFPTruncPR(denominator, mpc.Pk.K, mpc.Pk.FPPrecBits)

	if debug {
		fmt.Printf("[DEBUG] DENOMINATOR (before scale): %s\n", mpc.RevealInt(denominator).String())
	}

	// ensure denominator reciprocal within the necessary resolution
	denominator, dscaleInv := mpc.EFPTruncToPrec(denominator)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", mpc.RevealInt(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR (after scale): %s\n", mpc.RevealInt(denominator).String())
		fmt.Printf("[DEBUG] DENOMINATOR SCALE: %s/2^%d\n", mpc.RevealInt(dscaleInv).String(), mpc.Pk.K)
	}

	res := mpc.EFPDivision(numerator, denominator)
	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.K-mpc.Pk.FPPrecBits)), nil)

	res = mpc.Pk.ECMult(res, pow)
	fmt.Printf("[DEBUG] DIV RES: %s\n", mpc.RevealInt(res).String())

	res = mpc.EMult(res, dscaleInv) // dscaleInv has resolution of K-bits

	pstat2 := mpc.RevealFP(res, 2*mpc.Pk.K)

	endTime := time.Now()

	pstat := pstat2.Sqrt(pstat2)

	if debug {
		fmt.Printf("PEARSON STATISTIC, p = %s\n", pstat.String())
		fmt.Println("Runtime: " + endTime.Sub(startTime).String())
	}

	return pstat, endTime.Sub(startTime)
}

func exampleTTestSimulation(params *hypocert.MPCKeyGenParams, filepath string, debug bool) (*big.Float, time.Duration) {

	mpc := hypocert.NewMPCKeyGen(params)

	// Start dealer code
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

	sumXActual := 0.0
	sumYActual := 0.0
	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			sumXActual += x[i]
			sumYActual += y[i]

			plaintextX := mpc.Pk.EncodeFixedPoint(big.NewFloat(x[i]), mpc.Pk.FPPrecBits)
			plaintextY := mpc.Pk.EncodeFixedPoint(big.NewFloat(y[i]), mpc.Pk.FPPrecBits)

			eX[i] = mpc.Pk.Encrypt(plaintextX)
			eY[i] = mpc.Pk.Encrypt(plaintextY)
		}(i)
	}

	wg.Wait()

	//**************************************************************************************
	// End dealer code

	if debug {
		fmt.Println("[DEBUG] Finished encrypting dataset")
	}

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// encryption of zero for init value
	e0 := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(0.0), mpc.Pk.FPPrecBits))

	// compute sum x^2 and sum y^2
	sumX2 := e0
	sumY2 := e0

	// compute sum x and sum y
	sumX := e0
	sumY := e0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])

		x2 := mpc.EFPMult(eX[i], eX[i])
		sumX2 = mpc.Pk.EAdd(sumX2, x2)

		y2 := mpc.EFPMult(eY[i], eY[i])
		sumY2 = mpc.Pk.EAdd(sumY2, y2)
	}

	meanX := mpc.ECMultFP(sumX, invNumRows)
	meanY := mpc.ECMultFP(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.Pk.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.Pk.FPPrecBits).String())
	}

	numerator := mpc.Pk.ESub(meanX, meanY)
	numerator = mpc.EFPMult(numerator, numerator)

	ta := mpc.Pk.ESub(sumX2, mpc.ECMultFP(mpc.EFPMult(sumX, sumX), invNumRows))
	tb := mpc.Pk.ESub(sumY2, mpc.ECMultFP(mpc.EFPMult(sumY, sumY), invNumRows))

	denominator := mpc.Pk.EAdd(ta, tb)
	df := 2.0 / (float64((numRows + numRows - 2) * numRows))
	denominator = mpc.ECMultFP(denominator, big.NewFloat(df))

	if debug {
		fmt.Printf("[DEBUG] DENOMINATOR (before scale): %s\n", mpc.RevealInt(denominator).String())
	}

	// ensure denominator reciprocal within the necessary resolution
	//denominator, dscaleInv := mpc.EFPTruncToPrec(denominator)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", mpc.RevealInt(numerator).String())
		fmt.Printf("[DEBUG] DENOMINATOR (after scale): %s\n", mpc.RevealInt(denominator).String())
		//	fmt.Printf("[DEBUG] DENOMINATOR SCALE: %s/2^%d\n", mpc.RevealInt(dscaleInv).String(), mpc.Pk.K)
	}

	res := mpc.EFPDivision(numerator, denominator)

	//	res = mpc.EMult(res, dscaleInv) // dscaleInv has resolution of K-bits

	tstat2 := mpc.RevealFP(res, mpc.Pk.FPPrecBits)
	endTime := time.Now()

	tstat := tstat2.Sqrt(tstat2)

	if debug {
		fmt.Printf("T STATISTIC, p = %f\n", tstat)
		log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	return tstat, endTime.Sub(startTime)
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

	isHeader := true
	for {
		row, err := csvr.Read()

		if isHeader {
			isHeader = false
			continue
		}
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

		// fmt.Printf("Val is %f", val1)
		// fmt.Printf("Val is %f", val2)

		data1 = append(data1, val1)
		data2 = append(data2, val2)

	}

}
