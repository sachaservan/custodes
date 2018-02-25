package main

import (
	"bgn"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"secstat"
	"strconv"
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
	x = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	y = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}

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

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR: %s\n", sk.Decrypt(numerator, pk).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n", sk.Decrypt(denominator, pk).String())
	}

	// compute division in the clear
	num, _ := sk.Decrypt(numerator, pk).PolyEval().Float64()
	denom, _ := sk.Decrypt(denominator, pk).PolyEval().Float64()

	res := num / denom

	r := math.Sqrt(res)

	endTime := time.Now()

	fmt.Printf("Pearson's corelation coefficient, r = %f\n", r)
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

	fmt.Printf("Finished parsing CSV file with no errors! |X|: %d, |Y|: %d\n", len(x), len(y))

	// mini test dataset
	// x := []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	// y := []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}

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
		fmt.Printf("[DEBUG] MEAN X: %s\n", sk.Decrypt(meanX, pk).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", sk.Decrypt(meanY, pk).String())
	}

	top := pk.EAdd(meanX, pk.AInv(meanY))
	top = pk.EMult(top, top)

	ta := pk.EAdd(sumX2, pk.AInv(pk.EMultC(pk.EMult(sumX, sumX), invNumRows)))
	tb := pk.EAdd(sumY2, pk.AInv(pk.EMultC(pk.EMult(sumY, sumY), invNumRows)))

	bottom := pk.EAdd(ta, tb)
	fmt.Printf("[TEMP DEBUG]: 0 scalefactor %d\n", bottom.ScaleFactor)
	bottom = pk.EMultC(bottom, big.NewFloat(1.0/(float64(numRows+numRows-2))))
	fmt.Printf("[TEMP DEBUG]: 1 scalefactor %d\n", bottom.ScaleFactor)

	bottom = pk.EMultC(bottom, big.NewFloat(2.0/float64(numRows)))
	fmt.Printf("[TEMP DEBUG]: 2 scalefactor %d\n", bottom.ScaleFactor)

	numerator := mpc.ReEncryptMPC(top)

	fmt.Printf("[TEMP DEBUG] numerator scalefactor: %d\n", numerator.ScaleFactor)
	fmt.Printf("[TEMP DEBUG] denominator scalefactor: %d\n", bottom.ScaleFactor)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] numerator: %s\n", sk.Decrypt(numerator, pk).String())
	}

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] denominator: %s, %f\n", sk.Decrypt(bottom, pk).String(), 1.0/(float64(numRows+numRows-2)))
	}

	num, _ := mpc.DecryptMPC(numerator).PolyEval().Float64()
	denom, _ := mpc.DecryptMPC(bottom).PolyEval().Float64()

	tstatistic := num / denom

	endTime := time.Now()

	fmt.Printf("T statistic, p = %f\n", math.Sqrt(tstatistic))
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
