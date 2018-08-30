package main

import (
	"fmt"
	"hypocert"
	"hypocert/party"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

func ChiSquaredTestSimulation(
	mpc *hypocert.MPC,
	encD *EncryptedDataset,
	debug bool) *TestResult {

	// raw data
	eX := encD.Data

	trans := newMPCTranscript(2 * encD.NumCols)

	// keep track of runtime
	startTime := time.Now()

	// compute encrypted histogram
	h := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		h[i] = mpc.Pk.EAdd(eX[i]...)
	}

	// compute expected percentages per category
	expectedPercentage := make([]*big.Float, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		expectedPercentage[i] = big.NewFloat(1.0 / float64(encD.NumCols))
	}

	var wg sync.WaitGroup

	// compute the expected value
	sumTotal := mpc.Pk.EAdd(h...)

	expectedValues := make([]*paillier.Ciphertext, encD.NumCols)
	wg.Add(encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		go func(i int) {
			defer wg.Done()

			w := mpc.Pk.EncodeFixedPoint(expectedPercentage[i], mpc.FPPrecBits)
			expectedValueTmp := mpc.Pk.ECMult(sumTotal, w)
			expectedValues[i] = mpc.ETruncPR(expectedValueTmp, mpc.K, mpc.FPPrecBits)

			// entry #1 for TruncPR interactive protocol
			trans.setEntryAtIndex(&MPCTranscriptEntry{
				Protocol: ETruncPR,
				CtIn:     []*paillier.Ciphertext{expectedValueTmp},
				CtOut:    []*paillier.Ciphertext{expectedValues[i]},
			}, i)
		}(i)
	}

	wg.Wait()

	// compute the residuals
	residual := make([]*paillier.Ciphertext, encD.NumCols)
	wg.Add(encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		go func(i int) {
			defer wg.Done()

			res := mpc.Pk.ESub(h[i], expectedValues[i])
			residual[i] = mpc.EMult(res, res)

			trans.setEntryAtIndex(&MPCTranscriptEntry{
				Protocol: EMult,
				CtIn:     []*paillier.Ciphertext{res, res},
				CtOut:    []*paillier.Ciphertext{residual[i]},
			}, encD.NumCols+i)
		}(i)
	}

	wg.Wait()

	residualShares := make([]*party.Share, encD.NumCols)
	expectedValueShares := make([]*party.Share, encD.NumCols)

	for i := 0; i < encD.NumCols; i++ {
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
	xi := make([]*party.Share, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			xi[i] = mpc.FPDivision(residualShares[i], expectedValueShares[i])
		}(i)
	}
	wg.Wait()

	chi2 := mpc.CreateShares(big.NewInt(0))
	for i := 0; i < encD.NumCols; i++ {
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

	return &TestResult{
		Test:             "CHI2",
		Value:            chi2Stat,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		NumSharesCreated: mpc.DeleteAllShares(),
		Transcript:       trans,
	}
}

func ChiSquaredAuditSimulation(
	pk *paillier.PublicKey,
	fpprec int,
	encD *EncryptedDataset,
	trans *MPCTranscript) (bool, time.Duration) {

	verified := true

	eX := encD.Data

	// keep track of runtime
	startTime := time.Now()

	// compute encrypted histogram
	h := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		h[i] = pk.EAdd(eX[i]...)
	}

	// compute expected percentages per category
	expectedPercentage := make([]*big.Float, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		expectedPercentage[i] = big.NewFloat(1.0 / float64(encD.NumCols))
	}

	// compute the expected value
	sumTotal := pk.EAdd(h...)

	expectedValues := make([]*paillier.Ciphertext, encD.NumCols)
	for i := 0; i < encD.NumCols; i++ {
		w := pk.EncodeFixedPoint(expectedPercentage[i], fpprec)
		expectedValueTmp := pk.ECMult(sumTotal, w)

		if expectedValueTmp.C.Cmp(trans.Entries[i].CtIn[0].C) != 0 {
			verified = false
		}

		expectedValues[i] = trans.Entries[i].CtOut[0]

	}

	// compute the residuals
	for i := 0; i < encD.NumCols; i++ {
		res := pk.ESub(h[i], expectedValues[i])
		if res.C.Cmp(trans.Entries[encD.NumCols+i].CtIn[0].C) != 0 {
			verified = false
		}
	}

	return verified, time.Now().Sub(startTime)

}
