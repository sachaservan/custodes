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

	trans := newMPCTranscript(dataset.NumRows + 6)

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

	// entry #1 for TruncPR interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{meanXTmp, meanYTmp},
		CtOut:    []*paillier.Ciphertext{meanX, meanY},
	})

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN X: %s\n", mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n", mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	sumsSdX := make([]*paillier.Ciphertext, dataset.NumRows)
	sumsSdY := make([]*paillier.Ciphertext, dataset.NumRows)

	var wg sync.WaitGroup
	wg.Add(dataset.NumRows)
	for i := 0; i < dataset.NumRows; i++ {
		go func(i int) {
			defer wg.Done()
			sdx := mpc.Pk.ESub(eX[i], meanX)
			sdy := mpc.Pk.ESub(eY[i], meanY)
			sumsSdX[i] = mpc.EMult(sdx, sdx)
			sumsSdY[i] = mpc.EMult(sdy, sdy)

			// entry #2 for Mult interactive protocol
			trans.setEntryAtIndex(&MPCTranscriptEntry{
				Protocol: EMult,
				CtIn:     []*paillier.Ciphertext{sdx, sdy},
				CtOut:    []*paillier.Ciphertext{sumsSdX[i], sumsSdY[i]},
			}, i+1)
		}(i)
	}
	wg.Wait()

	trans.Next = dataset.NumRows + 1

	// compute the standard deviation
	sdX := mpc.Pk.EAdd(sumsSdX...)
	sdY := mpc.Pk.EAdd(sumsSdY...)

	denEncoded := mpc.Pk.EncodeFixedPoint(
		big.NewFloat(1.0/float64(dataset.NumRows-1)),
		mpc.FPPrecBits)

	sdXTmp := mpc.Pk.ECMult(sdX, denEncoded)
	sdYTmp := mpc.Pk.ECMult(sdY, denEncoded)

	sdX = mpc.ETruncPR(sdXTmp, mpc.K, mpc.FPPrecBits)
	sdY = mpc.ETruncPR(sdYTmp, mpc.K, mpc.FPPrecBits)

	// entry #3 for TruncPR interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{sdXTmp, sdYTmp},
		CtOut:    []*paillier.Ciphertext{sdX, sdY},
	})

	numeratorTmp := mpc.Pk.ESub(meanX, meanY)
	numerator := mpc.EMult(numeratorTmp, numeratorTmp)

	// entry #4 for Mult interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: EMult,
		CtIn:     []*paillier.Ciphertext{numeratorTmp},
		CtOut:    []*paillier.Ciphertext{numerator},
	})

	numeratorTmp = mpc.ETruncPR(numerator, mpc.K, mpc.FPPrecBits)

	// entry #5 for TruncPR interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{numerator},
		CtOut:    []*paillier.Ciphertext{numeratorTmp},
	})

	numerator = numeratorTmp

	tx := mpc.Pk.ESub(mpc.Pk.ECMult(sdX, big.NewInt(int64(dataset.NumRows))), sdX)
	ty := mpc.Pk.ESub(mpc.Pk.ECMult(sdY, big.NewInt(int64(dataset.NumRows))), sdY)
	denominatorTmp := mpc.Pk.EAdd(tx, ty)
	denominator := mpc.ETruncPR(denominatorTmp, mpc.K, mpc.FPPrecBits)

	// entry #6 for TruncPR interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{denominatorTmp},
		CtOut:    []*paillier.Ciphertext{denominator},
	})

	df := mpc.Pk.EncodeFixedPoint(
		big.NewFloat(1.0/float64(dataset.NumRows*dataset.NumRows-dataset.NumRows)),
		mpc.FPPrecBits)
	denominatorTmp = mpc.Pk.ECMult(denominator, df)

	denominator = mpc.ETruncPR(denominatorTmp, mpc.K, mpc.FPPrecBits)

	// entry #7 for TruncPR interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{denominatorTmp},
		CtOut:    []*paillier.Ciphertext{denominator},
	})

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

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (share): %s\n",
			mpc.RevealShare(numeratorShare).String())
		fmt.Printf("[DEBUG] DENOMINATOR (share): %s\n",
			mpc.RevealShare(denominatorShare).String())
	}

	// end paillier benchmark
	endTimePaillier := time.Now()

	res := mpc.FPDivision(numeratorShare, denominatorShare)
	tstat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)

	// end division benchmark
	endTime := time.Now()

	tstat := tstat2.Sqrt(tstat2)

	if debug {
		fmt.Printf("[DEBUG] T-STATISTIC, t = %f\n", tstat)
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	// compute all the runtimes
	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:             "T-TEST",
		Value:            tstat,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		NumSharesCreated: mpc.DeleteAllShares(),
		Transcript:       trans,
	}
}

func TTestAuditSimulation(
	pk *paillier.PublicKey,
	fpprec int,
	dataset *EncryptedDataset,
	trans *MPCTranscript) (bool, time.Duration) {

	verified := true

	eX := dataset.Data[0]
	eY := dataset.Data[1]

	numRows := len(eX)

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(numRows))
	invNumRowsEncoded := pk.EncodeFixedPoint(invNumRows, fpprec)

	// sum of the squares
	sumX := pk.EAdd(eX...)
	sumY := pk.EAdd(eY...)

	meanXTmp := pk.ECMult(sumX, invNumRowsEncoded)
	meanYTmp := pk.ECMult(sumY, invNumRowsEncoded)

	if meanXTmp.C.Cmp(trans.Entries[0].CtIn[0].C) != 0 {
		verified = false
	}

	if meanYTmp.C.Cmp(trans.Entries[0].CtIn[1].C) != 0 {
		verified = false
	}

	meanX := trans.Entries[0].CtOut[0]
	meanY := trans.Entries[0].CtOut[1]

	sumsSdX := make([]*paillier.Ciphertext, numRows)
	sumsSdY := make([]*paillier.Ciphertext, numRows)

	for i := 0; i < numRows; i++ {
		sdx := pk.ESub(eX[i], meanX)
		sdy := pk.ESub(eY[i], meanY)

		if sdx.C.Cmp(trans.Entries[i+1].CtIn[0].C) != 0 {
			verified = false
		}

		if sdy.C.Cmp(trans.Entries[i+1].CtIn[1].C) != 0 {
			verified = false
		}

		sumsSdX[i] = trans.Entries[i+1].CtOut[0]
		sumsSdY[i] = trans.Entries[i+1].CtOut[1]
	}

	// compute the standard deviation
	sdX := pk.EAdd(sumsSdX...)
	sdY := pk.EAdd(sumsSdY...)

	denEncoded := pk.EncodeFixedPoint(
		big.NewFloat(1.0/float64(numRows-1)),
		fpprec)
	sdXTmp := pk.ECMult(sdX, denEncoded)
	sdYTmp := pk.ECMult(sdY, denEncoded)

	if sdXTmp.C.Cmp(trans.Entries[numRows+1].CtIn[0].C) != 0 {
		verified = false
	}

	if sdYTmp.C.Cmp(trans.Entries[numRows+1].CtIn[1].C) != 0 {
		verified = false
	}

	sdX = trans.Entries[numRows+1].CtOut[0]
	sdY = trans.Entries[numRows+1].CtOut[1]

	numerator := pk.ESub(meanX, meanY)
	if numerator.C.Cmp(trans.Entries[numRows+2].CtIn[0].C) != 0 {
		verified = false
	}

	numeratorTmp := trans.Entries[numRows+2].CtOut[0]

	if numeratorTmp.C.Cmp(trans.Entries[numRows+3].CtIn[0].C) != 0 {
		verified = false
	}

	tx := pk.ESub(pk.ECMult(sdX, big.NewInt(int64(dataset.NumRows))), sdX)
	ty := pk.ESub(pk.ECMult(sdY, big.NewInt(int64(dataset.NumRows))), sdY)
	denominatorTmp := pk.EAdd(tx, ty)

	if denominatorTmp.C.Cmp(trans.Entries[numRows+4].CtIn[0].C) != 0 {
		verified = false
	}

	denominator := trans.Entries[numRows+4].CtOut[0]

	df := pk.EncodeFixedPoint(
		big.NewFloat(1.0/float64(dataset.NumRows*dataset.NumRows-dataset.NumRows)),
		fpprec)
	denominatorTmp = pk.ECMult(denominator, df)

	if denominatorTmp.C.Cmp(trans.Entries[numRows+5].CtIn[0].C) != 0 {
		verified = false
	}

	denominator = trans.Entries[numRows+5].CtOut[0]

	return verified, time.Now().Sub(startTime)
}
