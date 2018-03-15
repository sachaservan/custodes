package main

import (
	"fmt"
	"log"
	"math/big"
	"runtime"
	"secstat"
	"time"
)

func main() {
	printWelcome()

	// Some primes for message space:
	// 269 					---  8 bits
	// 1021 				--- 10 bits
	// 15551 				--- 14 bits
	// 16427 				--- 15 bits
	// 32797 				--- 16 bits
	// 100043 				--- 17 bits
	// 16777633 			--- 25 bits
	// 1073741833 			--- 30 bits
	// 1099511628323 		--- 40 bits

	numParties := 2
	keyBits := 64 // length of q1 and q2
	messageSpace := big.NewInt(16777633)

	polyBase := 3
	fpScaleBase := 3
	fpPrecision := 0.01

	runtime.GOMAXPROCS(10000)

	//examplePearsonsTestSimulation(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	exampleTTestSimulation(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	//exampleMultiParty(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision)

}

func exampleMultiParty(numParties int, keyBits int, messageSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64) {

	pk, sk, parties, _ := secstat.NewMPCKeyGen(numParties, keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)
	mpc := &secstat.MPC{parties, pk, sk}

	gskG1 := pk.P.NewFieldElement()
	gskG1.PowBig(pk.P, sk.Key)

	gskGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gskGT.PowBig(gskGT, sk.Key)

	pk.ComputeDLCache(gskG1, gskGT)
	fmt.Println("[DEBUG]: Finished computing DL cache.")

	mpc.PrecomputeData()
	fmt.Println("[DEBUG]: Finished computing offline data.")

	// var wg sync.WaitGroup
	// wg.Add(100)

	// for i := 0; i < 100; i++ {

	// 	go func() {
	// 		defer wg.Done()
	// 		startTime := time.Now()
	// 		a := big.NewInt(16777632)
	// 		b := big.NewInt(1029)
	// 		Q := big.NewInt(0).Div(a, b)
	// 		result := mpc.IntegerDivisionRevealMPC(pk.EncryptElement(a), pk.EncryptElement(b))
	// 		endTime := time.Now()
	// 		fmt.Printf("T bits %d, runtime = %s\n", mpc.Pk.T.BitLen(), endTime.Sub(startTime).String())
	// 		log.Println("Runtime: " + endTime.Sub(startTime).String())
	// 		//fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + mpc.DecryptElementMPC(result, true, false).String())
	// 		fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + result.String())
	// 		fmt.Println("Actual: " + a.String() + "/" + b.String() + " = " + Q.String())

	// 	}()
	// }

	// wg.Wait()

	startTime := time.Now()
	a := big.NewInt(12032)
	b := big.NewInt(1029)
	Q := big.NewInt(0).Div(a, b)
	result := mpc.IntegerDivisionRevealMPC(pk.EncryptElement(a), pk.EncryptElement(b))
	endTime := time.Now()
	fmt.Printf("T bits %d, runtime = %s\n", mpc.Pk.T.BitLen(), endTime.Sub(startTime).String())
	log.Println("Runtime: " + endTime.Sub(startTime).String())
	//fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + mpc.DecryptElementMPC(result, true, false).String())
	fmt.Println("Using div protocol: " + a.String() + "/" + b.String() + " = " + result.String())
	fmt.Println("Actual: " + a.String() + "/" + b.String() + " = " + Q.String())

}

func printWelcome() {
	fmt.Println("=====================================")
	fmt.Println(" _    _                    _____          _  ")
	fmt.Println("| |  | |                  / ____|        | |  ")
	fmt.Println("| |__| |_   _ _ __   ___ | |     ___ _ __| |_ ")
	fmt.Println("|  __  | | | | '_ \\ / _ \\| |    / _ \\ '__| __|")
	fmt.Println("| |  | | |_| | |_) | (_) | |___|  __/ |  | |_ ")
	fmt.Println("|_|  |_|\\__, | .__/ \\___/ \\_____\\___|_|   \\__|")
	fmt.Println("	 __/ | |                              ")
	fmt.Println("	|___/|_|                           ")
	fmt.Println("Secure Hypothesis Testing")
	fmt.Println("=====================================")

}
