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
func examplePearsonsTestSimulation(params *hypocert.MPCKeyGenParams) {

	mpc := hypocert.NewMPCKeyGen(params)

	debug := true

	// BEGIN dealer code
	//**************************************************************************************

	x, y, err := parseLocation("/home/azuka/Desktop/age_sex.csv")

	if err != nil {
		panic(err)
	}

	fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))

	// mini test dataset
	// x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	// y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}

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

		plaintextX := mpc.Pk.NewPlaintext(big.NewFloat(x[i]))
		plaintextY := mpc.Pk.NewPlaintext(big.NewFloat(y[i]))

		eX[i] = mpc.Pk.Encrypt(plaintextX)
		eY[i] = mpc.Pk.Encrypt(plaintextY)
	}
	//**************************************************************************************
	// END dealer code

	// keep track of time
	startTime := time.Now()

	// store for later use
	invNumRows := big.NewFloat(1.0 / float64(numRows))
	numRowsFlt := big.NewFloat(float64(numRows))

	// an encryption of zero to be used as initial value
	enc0 := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))

	// sum of the squares
	sumX2 := enc0
	sumY2 := enc0
	sumX := enc0
	sumY := enc0

	// compute sum of squares and sum of rows
	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])

		x2 := mpc.EMult(eX[i], eX[i])
		sumX2 = mpc.Pk.EAdd(sumX2, x2)

		y2 := mpc.EMult(eY[i], eY[i])
		sumY2 = mpc.Pk.EAdd(sumY2, y2)
	}

	// get the mean
	meanX := mpc.Pk.ECFloatMult(sumX, invNumRows)
	meanY := mpc.Pk.ECFloatMult(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s, SUM X: %s\n", mpc.Reveal(meanX).String(), mpc.Reveal(sumX).String())
		fmt.Printf("[DEBUG] MEAN Y: %s, SUM Y: %s\n", mpc.Reveal(meanY).String(), mpc.Reveal(sumY).String())
	}

	// compute (sum x)^2 and (sum y)^2
	sum2X := mpc.EMult(sumX, sumX)
	sum2Y := mpc.EMult(sumY, sumY)

	// compute n*(sum x^2) - (sum x)^2
	varianceX := mpc.Pk.ESub(mpc.Pk.ECFloatMult(sumX2, numRowsFlt), sum2X)

	// compute n*(sum y^2) - (sum y)^2
	varianceY := mpc.Pk.ESub(mpc.Pk.ECFloatMult(sumY2, numRowsFlt), sum2Y)

	// compute sum xy
	sumOfProduct := enc0
	for i := 0; i < numRows; i++ {
		sumOfProduct = mpc.Pk.EAdd(sumOfProduct, mpc.EMult(eX[i], eY[i]))
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] VARIANCE X: %s\n", mpc.Reveal(varianceX).String())
		fmt.Printf("[DEBUG] VARIANCE Y: %s\n", mpc.Reveal(varianceY).String())
	}

	covariance := mpc.EMult(varianceY, varianceX)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] SUM OF PRODUCTS: %s\n", mpc.Reveal(sumOfProduct).String())
		fmt.Printf("[DEBUG] COVARIANCE: %s\n", mpc.Reveal(covariance).String())

	}

	// compute (sum x)(sum y)
	prodSums := mpc.EMult(sumY, sumX)

	// compute the numerator^2 = [n*(sum xy) - (sum x)(sum y)]^2
	numerator := mpc.Pk.ESub(mpc.Pk.ECFloatMult(sumOfProduct, numRowsFlt), prodSums)
	numerator = mpc.EMult(numerator, numerator)
	denominator := covariance

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s/3^%d\n", mpc.Reveal(numerator).String(), numerator.FPScaleFactor)
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] DENOMINATOR: %s/3^%d\n", mpc.Reveal(denominator).String(), denominator.FPScaleFactor)
	}

	// numeratorScaleFactor := numerator.FPScaleFactor
	// denominatorScaleFactor := denominator.FPScaleFactor

	numerator.FPScaleFactor = 0
	denominator.FPScaleFactor = 0

	//q := mpc.IntegerDivisionRevealMPC(denominator, numerator) // num < den

	// scaleFactor := big.NewFloat(0).SetInt(big.NewInt(0).Exp(big.NewInt(int64(mpc.Pk.FPScaleBase)), big.NewInt(int64(denominatorScaleFactor-numeratorScaleFactor)), nil))
	// res := big.NewFloat(0.0).Quo(scaleFactor, big.NewFloat(0.0).SetInt(q))
	endTime := time.Now()

	// fmt.Printf("Pearson's corelation coefficient, r = %s\n", res.Sqrt(res).String())
	fmt.Println("Runtime: " + endTime.Sub(startTime).String())
}

func exampleTTestSimulation(params *hypocert.MPCKeyGenParams) {

	mpc := hypocert.NewMPCKeyGen(params)

	debug := true

	// Start dealer code
	//**************************************************************************************
	x, y, err := parseLocation("/home/azuka/Desktop/age_sex.csv")

	if err != nil {
		panic(err)
	}

	// mini test dataset
	// x := []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	// y := []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}

	fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))
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

			plaintextX := mpc.Pk.NewPlaintext(big.NewFloat(x[i]))
			plaintextY := mpc.Pk.NewPlaintext(big.NewFloat(y[i]))

			eX[i] = mpc.Pk.Encrypt(plaintextX)
			eY[i] = mpc.Pk.Encrypt(plaintextY)
		}(i)
	}

	wg.Wait()

	//**************************************************************************************
	// End dealer code

	fmt.Println("[DEBUG] Finished encrypting dataset")

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// encryption of zero for init value
	e0 := mpc.Pk.Encrypt(mpc.Pk.NewPlaintext(big.NewFloat(0.0)))

	// compute sum x^2 and sum y^2
	sumX2 := e0
	sumY2 := e0

	// compute sum x and sum y
	sumX := e0
	sumY := e0

	for i := 0; i < numRows; i++ {
		sumX = mpc.Pk.EAdd(sumX, eX[i])
		sumY = mpc.Pk.EAdd(sumY, eY[i])

		x2 := mpc.EMult(eX[i], eX[i])
		sumX2 = mpc.Pk.EAdd(sumX2, x2)

		y2 := mpc.EMult(eY[i], eY[i])
		sumY2 = mpc.Pk.EAdd(sumY2, y2)
	}

	meanX := mpc.Pk.ECFloatMult(sumX, invNumRows)
	meanY := mpc.Pk.ECFloatMult(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.Reveal(meanX).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.Reveal(meanY).String())
	}

	numerator := mpc.Pk.ESub(meanX, meanY)
	numerator = mpc.EMult(numerator, numerator)

	ta := mpc.Pk.ESub(sumX2, mpc.Pk.ECFloatMult(mpc.EMult(sumX, sumX), invNumRows))
	tb := mpc.Pk.ESub(sumY2, mpc.Pk.ECFloatMult(mpc.EMult(sumY, sumY), invNumRows))

	denominator := mpc.Pk.EAdd(ta, tb)
	df := 2.0 / (float64((numRows + numRows - 2) * numRows))
	denominator = mpc.Pk.ECFloatMult(denominator, big.NewFloat(df))

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s/3^%d\n", mpc.RevealInt(numerator).String(), numerator.FPScaleFactor)
		fmt.Printf("[DEBUG] DENOMINATOR: %s/3^%d\n", mpc.RevealInt(denominator).String(), denominator.FPScaleFactor)
	}

	// numeratorScaleFactor := numerator.FPScaleFactor
	// denominatorScaleFactor := denominator.FPScaleFactor

	// numerator.FPScaleFactor = 0
	// denominator.FPScaleFactor = 0

	// q := mpc.IntegerDivisionRevealMPC(denominator, numerator) // num < den

	// scaleFactor := big.NewFloat(0).SetInt(big.NewInt(0).Exp(big.NewInt(int64(mpc.Pk.FPScaleBase)), big.NewInt(int64(denominatorScaleFactor-numeratorScaleFactor)), nil))
	// res := big.NewFloat(0.0).Quo(scaleFactor, big.NewFloat(0.0).SetInt(q))

	endTime := time.Now()

	// fmt.Printf("T STATISTIC, p = %f\n", res.Sqrt(res))
	log.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
}

func parseLocation(file string) ([]float64, []float64, error) {
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
