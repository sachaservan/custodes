package main

import (
	"fmt"
	"hypocert"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

// Simulation of Pearson's coorelation coefficient
func PearsonsTestSimulation(
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
		fmt.Printf("[DEBUG] MEAN X: %s\n",
			mpc.RevealFP(meanX, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] MEAN Y: %s\n",
			mpc.RevealFP(meanY, mpc.FPPrecBits).String())
	}

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (y_i - mean_y)^2
	devsY2 := make([]*paillier.Ciphertext, dataset.NumRows)

	var wg sync.WaitGroup
	wg.Add(dataset.NumRows)

	for i := 0; i < dataset.NumRows; i++ {
		go func(i int) {
			defer wg.Done()
			devX := mpc.Pk.ESub(eX[i], meanX)
			devY := mpc.Pk.ESub(eY[i], meanY)
			devsX2[i] = mpc.EMult(devX, devX)
			devsY2[i] = mpc.EMult(devY, devY)
			prodsXY[i] = mpc.EMult(devX, devY)

			// entry #2 for Mult interactive protocol
			trans.setEntryAtIndex(&MPCTranscriptEntry{
				Protocol: EMult,
				CtIn:     []*paillier.Ciphertext{devX, devY},
				CtOut:    []*paillier.Ciphertext{devsX2[i], devsY2[i], prodsXY[i]},
			}, i+1)
		}(i)
	}

	wg.Wait()

	trans.Next = dataset.NumRows + 1

	// compute sum for all i (x_i - mean_x)(y_i - mean_y)
	sumXY := mpc.Pk.EAdd(prodsXY...)

	sumDevX2 := mpc.Pk.EAdd(devsX2...)
	sumDevY2 := mpc.Pk.EAdd(devsY2...)

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numeratorTmp := mpc.EMult(sumXY, sumXY)

	// entry #3 for Trunc interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: EMult,
		CtIn:     []*paillier.Ciphertext{sumXY, sumXY},
		CtOut:    []*paillier.Ciphertext{numeratorTmp},
	})

	numerator := mpc.ETruncPR(numeratorTmp, 3*mpc.K, 3*mpc.FPPrecBits)

	// entry #3 for Trunc interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: ETruncPR,
		CtIn:     []*paillier.Ciphertext{numeratorTmp},
		CtOut:    []*paillier.Ciphertext{numerator},
	})

	denominatorTmp := mpc.EMult(sumDevX2, sumDevY2)
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: EMult,
		CtIn:     []*paillier.Ciphertext{sumDevX2, sumDevY2},
		CtOut:    []*paillier.Ciphertext{denominatorTmp},
	})

	denominator := mpc.ETruncPR(denominatorTmp, 3*mpc.K, 3*mpc.FPPrecBits)

	// entry #4 for Trunc interactive protocol
	trans.addEntry(&MPCTranscriptEntry{
		Protocol: EMult,
		CtIn:     []*paillier.Ciphertext{denominatorTmp},
		CtOut:    []*paillier.Ciphertext{denominator},
	})

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR:   %s\n",
			mpc.RevealFP(numerator, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR: %s\n",
			mpc.RevealFP(denominator, mpc.FPPrecBits).String())
	}

	// convert to shares
	numeratorShare := mpc.PaillierToShare(numerator)
	denominatorShare := mpc.PaillierToShare(denominator)

	// done with paillier computations
	endTimePaillier := time.Now()

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] NUMERATOR (Share):   %s\n",
			mpc.RevealShareFP(numeratorShare, mpc.FPPrecBits).String())
		fmt.Printf("[DEBUG] DENOMINATOR (Share): %s\n",
			mpc.RevealShareFP(denominatorShare, mpc.FPPrecBits).String())
	}

	res := mpc.FPDivision(numeratorShare, denominatorShare)

	stat2 := mpc.RevealShareFP(res, mpc.FPPrecBits)
	stat := stat2.Sqrt(stat2)

	endTime := time.Now()

	if debug {
		fmt.Printf("[DEBUG] PEARSON CORRELATION STATISTIC, r = %s\n", stat.String())
		fmt.Println("[DEBUG] RUNTIME: " + endTime.Sub(startTime).String())
	}

	totalTime := endTime.Sub(startTime)
	divTime := time.Now().Sub(endTimePaillier)
	paillierTime := endTimePaillier.Sub(startTime)

	return &TestResult{
		Test:             "PEARSON",
		Value:            stat,
		TotalRuntime:     totalTime,
		ComputeRuntime:   paillierTime,
		DivRuntime:       divTime,
		NumSharesCreated: mpc.DeleteAllShares(),
		Transcript:       trans,
	}
}

func PearsonAuditSimulation(
	pk *paillier.PublicKey,
	fpprec int,
	dataset *EncryptedDataset,
	trans *MPCTranscript) (bool, time.Duration) {

	verified := true

	eX := dataset.Data[0]
	eY := dataset.Data[1]

	startTime := time.Now()
	invNumRows := big.NewFloat(1.0 / float64(dataset.NumRows))
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

	// compute (x_i - mean_x)(y_i - mean_y)
	prodsXY := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (x_i - mean_x)^2
	devsX2 := make([]*paillier.Ciphertext, dataset.NumRows)

	// SUM (y_i - mean_y)^2
	devsY2 := make([]*paillier.Ciphertext, dataset.NumRows)

	for i := 0; i < dataset.NumRows; i++ {

		devX := pk.ESub(eX[i], meanX)
		devY := pk.ESub(eY[i], meanY)
		if devX.C.Cmp(trans.Entries[i+1].CtIn[0].C) != 0 {
			verified = false
		}

		if devY.C.Cmp(trans.Entries[i+1].CtIn[1].C) != 0 {
			verified = false
		}

		devsX2[i] = trans.Entries[i+1].CtOut[0]
		devsY2[i] = trans.Entries[i+1].CtOut[1]
		prodsXY[i] = trans.Entries[i+1].CtOut[2]

	}

	// compute sum for all i (x_i - mean_x)(y_i - mean_y)
	sumXY := pk.EAdd(prodsXY...)

	sumDevX2 := pk.EAdd(devsX2...)
	sumDevY2 := pk.EAdd(devsY2...)

	if sumXY.C.Cmp(trans.Entries[dataset.NumRows+1].CtIn[0].C) != 0 {
		verified = false
	}

	// compute the numerator = [sum for all i (x_i - mean_x)(y_i - mean_y)]
	numeratorTmp := trans.Entries[dataset.NumRows+1].CtOut[0]

	if numeratorTmp.C.Cmp(trans.Entries[dataset.NumRows+2].CtIn[0].C) != 0 {
		verified = false
	}

	if sumDevX2.C.Cmp(trans.Entries[dataset.NumRows+3].CtIn[0].C) != 0 {
		verified = false
	}

	if sumDevY2.C.Cmp(trans.Entries[dataset.NumRows+3].CtIn[1].C) != 0 {
		verified = false
	}

	denominatorTmp := trans.Entries[dataset.NumRows+3].CtOut[0]

	if denominatorTmp.C.Cmp(trans.Entries[dataset.NumRows+4].CtIn[0].C) != 0 {
		verified = false
	}

	return verified, time.Now().Sub(startTime)
}
