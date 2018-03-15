package main

import (
	"bgn"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"secstat"
	"strconv"
	"sync"
	"time"
)

// Simulation of Pearson's coorelation coefficient
func examplePearsonsTestSimulation(numParties int, keyBits int, messageSpace *big.Int, polyBase int, fpScalarBase int, fpPrecision float64, debug bool) {

	pk, sk, parties, err := secstat.NewMPCKeyGen(numParties, keyBits, messageSpace, polyBase, fpScalarBase, fpPrecision, true)
	mpc := &secstat.MPC{Parties: parties, Pk: pk, Sk: sk}

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

	var eX []*bgn.Ciphertext
	eX = make([]*bgn.Ciphertext, numRows)
	var eY []*bgn.Ciphertext
	eY = make([]*bgn.Ciphertext, numRows)

	sumXActual := 0.0
	sumYActual := 0.0

	for i := 0; i < numRows; i++ {

		sumXActual += x[i]
		sumYActual += y[i]

		plaintextX := pk.NewPlaintext(big.NewFloat(x[i]))
		plaintextY := pk.NewPlaintext(big.NewFloat(y[i]))

		eX[i] = pk.Encrypt(plaintextX)
		eY[i] = pk.Encrypt(plaintextY)
	}
	//**************************************************************************************
	// END dealer code

	// keep track of time
	startTime := time.Now()

	// store for later use
	invNumRows := big.NewFloat(1.0 / float64(numRows))
	numRowsFlt := big.NewFloat(float64(numRows))

	// an encryption of zero to be used as initial value
	enc0 := pk.Encrypt(pk.NewPlaintext(big.NewFloat(0.0)))

	// sum of the squares
	sumX2 := enc0
	sumY2 := enc0
	sumX := enc0
	sumY := enc0

	// compute sum of squares and sum of rows
	for i := 0; i < numRows; i++ {
		sumX = pk.EAdd(sumX, eX[i])
		sumY = pk.EAdd(sumY, eY[i])

		x2 := pk.EMult(eX[i], eX[i])
		sumX2 = pk.EAdd(sumX2, x2)

		y2 := pk.EMult(eY[i], eY[i])
		sumY2 = pk.EAdd(sumY2, y2)
	}

	// get the mean
	meanX := pk.EMultC(sumX, invNumRows)
	meanY := pk.EMultC(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s, SUM X: %s\n", sk.Decrypt(meanX, pk).String(), sk.Decrypt(sumX, pk).String())
		fmt.Printf("[DEBUG] MEAN Y: %s, SUM Y: %s\n", sk.Decrypt(meanY, pk).String(), sk.Decrypt(sumY, pk).String())
	}

	// compute (sum x)^2 and (sum y)^2
	sum2X := pk.EMult(sumX, sumX)
	sum2Y := pk.EMult(sumY, sumY)

	// compute n*(sum x^2) - (sum x)^2
	varianceX := pk.EAdd(pk.EMultC(sumX2, numRowsFlt), pk.AInv(sum2X))

	// compute n*(sum y^2) - (sum y)^2
	varianceY := pk.EAdd(pk.EMultC(sumY2, numRowsFlt), pk.AInv(sum2Y))

	// compute sum xy
	sumOfProduct := enc0
	for i := 0; i < numRows; i++ {
		sumOfProduct = pk.EAdd(sumOfProduct, pk.EMult(eX[i], eY[i]))
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] VARIANCE X: %s\n", sk.Decrypt(varianceX, pk).String())
		fmt.Printf("[DEBUG] VARIANCE Y: %s\n", sk.Decrypt(varianceY, pk).String())
	}

	covariance := pk.EMult(mpc.ReEncryptMPC(varianceY), mpc.ReEncryptMPC(varianceX))

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] SUM OF PRODUCTS: %s\n", sk.Decrypt(sumOfProduct, pk).String())
		fmt.Printf("[DEBUG] COVARIANCE: %s\n", sk.Decrypt(covariance, pk).String())

	}

	// compute (sum x)(sum y)
	prodSums := pk.EMult(sumY, sumX)

	// compute the numerator^2 = [n*(sum xy) - (sum x)(sum y)]^2
	numerator := pk.EAdd(pk.EMultC(sumOfProduct, numRowsFlt), pk.AInv(prodSums))
	numerator = mpc.ReEncryptMPC(numerator)
	numerator = pk.EMult(numerator, numerator)

	denominator := covariance

	numerator = mpc.ReEncryptMPC(numerator)
	denominator = mpc.ReEncryptMPC(denominator)

	numeratorZn := pk.EPolyEval(numerator, 12)
	denominatorZn := pk.EPolyEval(denominator, 12)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s/3^%d DEGREE: %d\n", sk.DecryptElement(numeratorZn, pk).String(), numerator.ScaleFactor, numerator.Degree)
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] DENOMINATOR: %s/3^%d DEGREE: %d\n", sk.DecryptElement(denominatorZn, pk).String(), denominator.ScaleFactor, denominator.Degree)
	}

	q := mpc.IntegerDivisionRevealMPC(mpc.Pk.EMultCElement(numeratorZn, big.NewInt(100)), denominatorZn) // num < den

	scaleFactor := big.NewFloat(0).SetInt(big.NewInt(0).Exp(big.NewInt(int64(mpc.Pk.PolyBase)), big.NewInt(int64(numerator.ScaleFactor-denominator.ScaleFactor)), nil))

	res := big.NewFloat(0.0).Quo(big.NewFloat(0.0).SetInt(q), scaleFactor)
	res.Quo(res, big.NewFloat(100))

	endTime := time.Now()

	fmt.Printf("Pearson's corelation coefficient, r = %s\n", res.Sqrt(res).String())
	fmt.Println("Runtime: " + endTime.Sub(startTime).String())
}

func exampleTTestSimulation(numParties int, keyBits int, messageSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64, debug bool) {

	pk, sk, parties, err := secstat.NewMPCKeyGen(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	mpc := &secstat.MPC{Parties: parties, Pk: pk, Sk: sk}

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

	var eX []*bgn.Ciphertext
	eX = make([]*bgn.Ciphertext, numRows)
	var eY []*bgn.Ciphertext
	eY = make([]*bgn.Ciphertext, numRows)

	sumXActual := 0.0
	sumYActual := 0.0
	var wg sync.WaitGroup
	for i := 0; i < numRows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			sumXActual += x[i]
			sumYActual += y[i]

			plaintextX := pk.NewPlaintext(big.NewFloat(x[i]))
			plaintextY := pk.NewPlaintext(big.NewFloat(y[i]))

			eX[i] = pk.Encrypt(plaintextX)
			eY[i] = pk.Encrypt(plaintextY)
		}(i)
	}

	wg.Wait()

	//**************************************************************************************
	// End dealer code

	fmt.Println("[DEBUG] Finished encrypting dataset")

	startTime := time.Now()

	invNumRows := big.NewFloat(1.0 / float64(numRows))

	// encryption of zero for init value
	e0 := pk.Encrypt(pk.NewPlaintext(big.NewFloat(0.0)))

	// compute sum x^2 and sum y^2
	sumX2 := e0
	sumY2 := e0

	// compute sum x and sum y
	sumX := e0
	sumY := e0

	for i := 0; i < numRows; i++ {
		sumX = pk.EAdd(sumX, eX[i])
		sumY = pk.EAdd(sumY, eY[i])

		x2 := pk.EMult(eX[i], eX[i])
		sumX2 = pk.EAdd(sumX2, x2)

		y2 := pk.EMult(eY[i], eY[i])
		sumY2 = pk.EAdd(sumY2, y2)
	}

	meanX := pk.EMultC(sumX, invNumRows)
	meanY := pk.EMultC(sumY, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.DecryptMPC(meanX).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.DecryptMPC(meanY).String())
	}

	top := pk.EAdd(meanX, pk.AInv(meanY))
	top = pk.EMult(top, top)

	ta := pk.EAdd(sumX2, pk.AInv(pk.EMultC(pk.EMult(sumX, sumX), invNumRows)))
	tb := pk.EAdd(sumY2, pk.AInv(pk.EMultC(pk.EMult(sumY, sumY), invNumRows)))

	bottom := pk.EAdd(ta, tb)
	df := 2.0 / (float64((numRows + numRows - 2) * numRows))
	bottom = pk.EMultC(bottom, big.NewFloat(df))

	numerator := mpc.ReEncryptMPC(top)
	denom := mpc.ReEncryptMPC(bottom)

	// fmt.Printf("[TEMP DEBUG] numerator scalefactor: %d\n", numerator.ScaleFactor)
	// fmt.Printf("[TEMP DEBUG] denominator scalefactor: %d\n", bottom.ScaleFactor)

	numeratorZn := pk.EPolyEval(numerator, 6)
	denominatorZn := pk.EPolyEval(denom, 6)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Zn): %s/3^%d\n", sk.DecryptElement(numeratorZn, pk).String(), numerator.ScaleFactor)
		fmt.Printf("[DEBUG] DENOMINATOR (Zn): %s/3^%d\n", sk.DecryptElement(denominatorZn, pk).String(), numerator.ScaleFactor)
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s DEGREE: %d\n", sk.Decrypt(numerator, pk).String(), numerator.Degree)
		fmt.Printf("[DEBUG] DENOMINATOR: %s DEGREE: %d\n", sk.Decrypt(denom, pk).String(), denom.Degree)

	}

	q := mpc.IntegerDivisionRevealMPC(mpc.Pk.EMultCElement(denominatorZn, big.NewInt(100)), numeratorZn) // num < den

	scaleFactor := big.NewFloat(0).SetInt(big.NewInt(0).Exp(big.NewInt(int64(mpc.Pk.PolyBase)), big.NewInt(int64(bottom.ScaleFactor-numerator.ScaleFactor)), nil))
	res := big.NewFloat(0.0).Quo(scaleFactor, big.NewFloat(0.0).SetInt(q))
	res.Mul(res, big.NewFloat(100))

	endTime := time.Now()

	fmt.Printf("T statistic, p = %f\n", res.Sqrt(res))
	log.Println("Runtime: " + endTime.Sub(startTime).String())
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
