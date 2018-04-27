package hypocert

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"node"
	"paillier"
	"sync"
	"time"
)

// Constants
var big2Inv *big.Int
var big2 *big.Int
var big1 *big.Int
var big0 *big.Int

type MPC struct {
	Party     *node.Party   // party initiating the requests
	Parties   []*node.Party // all other parties in the system
	Threshold int
	Pk        *paillier.PublicKey
	Verify    bool
}

type MPCKeyGenParams struct {
	NumParties      int
	Threshold       int  // decryption threshold
	KeyBits         int  // at least 512 for Paillier
	Verify          bool // run zkp proofs in decryption process
	MessageBits     int  // used for binary decomposition
	ModulusBits     int  // for faster decryption. Must be > SecurityBits + MessageBits + (NumParties choose Threshold)
	SecurityBits    int  // at least 40 bits
	FPPrecisionBits int
}

func (mpc *MPC) RevealShare(shareID string) *big.Int {

	var wg sync.WaitGroup
	shares := make([]*node.Share, len(mpc.Parties))
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			share, err := mpc.Parties[i].RevealShare(shareID)
			if err != nil {
				panic(err)
			}
			shares[i] = share
		}(i)
	}

	wg.Wait()

	return mpc.ReconstructShare(shares)
}

func (mpc *MPC) CreateShares(value *big.Int) ([]*node.Share, string) {
	id := node.GenShareID(paillier.CryptoRandom(mpc.Pk.N).String())
	return mpc.Party.CreateShares(value, id)
}

func (mpc *MPC) DistributeShares(shares []*node.Share) {
	mpc.Party.DistributeShares(shares)
}

func (mpc *MPC) AddShares(shareID1, shareID2 string) string {

	var id string
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		id, err = mpc.Parties[i].Add(shareID1, shareID2)
		if err != nil {
			panic(err)
		}
	}

	return id
}

func (mpc *MPC) MultCShares(shareID string, c *big.Int) string {

	var id string
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		id, err = mpc.Parties[i].MultC(shareID, c)
		if err != nil {
			panic(err)
		}
	}

	return id
}

func (mpc *MPC) MultShares(shareID1, shareID2 string) string {

	var id string
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		id, err = mpc.Parties[i].Mult(shareID1, shareID2)
		if err != nil {
			panic(err)
		}
	}

	return id
}

// EFPNormalize returns a tuple (b, v) such that a/2^v is between 0.5 and 1
func (mpc *MPC) EFPNormalize(b *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	bitsa := mpc.ReverseBits(mpc.EBitsDec(b, mpc.Pk.K))
	ybits := mpc.ReverseBits(mpc.EBitsPrefixOR(bitsa))

	for i := 0; i < mpc.Pk.K-1; i++ {
		ybits[i] = mpc.Pk.ESub(ybits[i], ybits[i+1])
	}

	v := mpc.Pk.Encrypt(big.NewInt(0))
	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.K-1)), nil)

	for i := 0; i < mpc.Pk.K; i++ {
		t := mpc.Pk.ECMult(ybits[i], pow)
		v = mpc.Pk.EAdd(v, t)
		pow.Div(pow, big.NewInt(2))
	}

	u := mpc.EMult(b, v)

	return u, v
}

//EFPFanInMULT returns the vector containing powers of a from 1 ... pow
func (mpc *MPC) EFPFanInMULT(a *paillier.Ciphertext, exp int) []*paillier.Ciphertext {

	res := make([]*paillier.Ciphertext, exp)
	res[0] = a

	// todo make parallel and efficient
	for i := 1; i < exp; i++ {

		c := mpc.EMult(res[i-1], a)
		res[i] = mpc.EFPTruncPR(c, 2*mpc.Pk.K, mpc.Pk.FPPrecBits)
	}

	return res
}

//EFPReciprocal return an approximation of [1/b]
func (mpc *MPC) EFPReciprocal(b *paillier.Ciphertext) *paillier.Ciphertext {

	a := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(1.0), mpc.Pk.FPPrecBits))
	return mpc.EFPDivision(a, b)
}

// EFPDivision return the approximate result of [a/b]
func (mpc *MPC) EFPDivision(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	// init goldschmidt constants
	theta := int(math.Ceil(math.Log2(float64(mpc.Pk.K) / 3.75)))
	alphaEnc := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(1.0), mpc.Pk.K))

	w := mpc.initReciprocal(b)

	// x = theta - bw
	x := mpc.Pk.ESub(alphaEnc, mpc.EMult(b, w))

	// y = a*w
	y := mpc.EMult(a, w)
	y = mpc.EFPTruncPR(y, 2*mpc.Pk.K, mpc.Pk.K/2)

	for i := 0; i < theta; i++ {

		// y = y * (alpha + x)
		y = mpc.EMult(y, mpc.Pk.EAdd(alphaEnc, x))
		y = mpc.EFPTruncPR(y, 2*mpc.Pk.K, mpc.Pk.K)

		if i+1 < theta {
			x = mpc.EMult(x, x)
			x = mpc.EFPTruncPR(x, 2*mpc.Pk.K, mpc.Pk.K)
		}
	}

	return mpc.EFPTruncPR(y, 2*mpc.Pk.K, mpc.Pk.K/2-mpc.Pk.FPPrecBits)
}

func (mpc *MPC) initReciprocal(b *paillier.Ciphertext) *paillier.Ciphertext {

	// init goldschmidt constant
	alpha := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(2.9142), mpc.Pk.K))

	// normalize the denominator
	u, v := mpc.EFPNormalize(b)

	// d = alpha - 2u
	d := mpc.Pk.ESub(alpha, mpc.Pk.ECMult(u, big.NewInt(2)))

	// w = d*v
	w := mpc.EMult(d, v)

	// return the normalize initial approximation
	w = mpc.EFPTruncPR(w, 2*mpc.Pk.K, mpc.Pk.K)

	return w
}

func NewMPCKeyGen(params *MPCKeyGenParams) *MPC {

	nu := big.NewInt(0).Binomial(int64(params.NumParties), int64(params.Threshold)).Int64()
	if int64(params.MessageBits+params.SecurityBits+params.FPPrecisionBits)+nu >= int64(2*params.KeyBits) {
		panic("modulus not big enough for given parameters")
	}

	if params.MessageBits < params.FPPrecisionBits {
		panic("message space is smaller than the precision")
	}

	tkh := paillier.GetThresholdKeyGenerator(params.KeyBits, params.NumParties, params.Threshold, rand.Reader)
	tpks, err := tkh.Generate()
	pk := &tpks[0].PublicKey
	pk.S = params.SecurityBits
	pk.K = params.MessageBits
	pk.V = int(nu)
	pk.FPPrecBits = params.FPPrecisionBits

	if err != nil {
		panic(err)
	}

	parties := make([]*node.Party, len(tpks))
	for i := 0; i < len(tpks); i++ {

		// generate the Beta value used for
		// share reconstruction
		si := big.NewInt(int64(i + 1))
		beta := big.NewInt(1)
		for j := 1; j <= len(tpks); j++ {
			denom := big.NewInt(1)

			if i+1 != j {
				sj := big.NewInt(int64(j))
				beta.Mul(beta, sj)

				// denom = (sj - si)^-1
				denom.Mul(denom, big.NewInt(0).Sub(sj, si))

				denom.ModInverse(denom, pk.N)
				beta.Mul(beta, denom)
			}
		}

		parties[i] = &node.Party{ID: i, Sk: tpks[i], Pk: pk, Beta: beta, Threshold: params.Threshold, Parties: parties}
	}

	mpc := &MPC{parties[0], parties, params.Threshold, pk, params.Verify}

	// init constants
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2Inv = big.NewInt(0).ModInverse(big2, pk.N)

	return mpc
}

func (mpc *MPC) ReconstructShare(shares []*node.Share) *big.Int {

	s := big.NewInt(0)

	for i := 0; i < len(shares); i++ {
		d := big.NewInt(0).Mul(shares[i].Value, mpc.Parties[shares[i].PartyID].Beta)
		s.Add(s, d)
	}

	return s.Mod(s, mpc.Pk.N)
}

// Paillier MPC functions
func (mpc *MPC) EMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	mask, val := mpc.ERandomMultShare(a)

	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res = mpc.Pk.ESub(res, val)

	return res
}

func (mpc *MPC) ECMultFP(ct *paillier.Ciphertext, fp *big.Float) *paillier.Ciphertext {
	e := mpc.Pk.EncodeFixedPoint(fp, mpc.Pk.FPPrecBits)
	m := new(big.Int).Exp(ct.C, e, mpc.Pk.GetNSquare())
	return mpc.EFPTruncPR(&paillier.Ciphertext{m}, mpc.Pk.K, mpc.Pk.FPPrecBits)
}

func (mpc *MPC) EFPMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	stime := time.Now()

	mask, val := mpc.ERandomMultShare(a)

	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res = mpc.Pk.ESub(res, val)

	res = mpc.EFPTruncPR(res, mpc.Pk.K, mpc.Pk.FPPrecBits)

	fmt.Println("end: " + time.Now().Sub(stime).String())
	return res
}

func (mpc *MPC) RevealInt(ciphertext *paillier.Ciphertext) *big.Int {

	var val *big.Int
	var err error

	if !mpc.Verify {

		partialDecrypts := make([]*paillier.PartialDecryption, len(mpc.Parties))

		for i := 0; i < len(mpc.Parties); i++ {
			partialDecrypts[i] = mpc.Parties[i].PartialDecrypt(ciphertext)
		}

		val, err = mpc.Party.Sk.CombinePartialDecryptions(partialDecrypts)
		if err != nil {
			panic(err)
		}

	} else {

		partialDecryptsZkps := make([]*paillier.PartialDecryptionZKP, len(mpc.Parties))

		for i := 0; i < len(mpc.Parties); i++ {
			partialDecryptsZkps[i] = mpc.Parties[i].PartialDecryptAndProof(ciphertext)
		}

		val, err = mpc.Party.Sk.CombinePartialDecryptionsZKP(partialDecryptsZkps)
		if err != nil {
			panic(err)
		}
	}

	return val
}

func (mpc *MPC) RevealFP(ciphertext *paillier.Ciphertext, scale int) *big.Float {

	val := mpc.RevealInt(ciphertext)
	scaleFactor := big.NewInt(0).Exp(big2, big.NewInt(int64(scale)), nil)
	fp := big.NewFloat(0.0).SetInt(val)
	fp.Quo(fp, big.NewFloat(0.0).SetInt(scaleFactor))
	return fp
}

//EBitsTruncPR truncates a bitwise sharing where the last bit is
// probabilistically rounded up or down
func (mpc *MPC) EFPTruncPR(a *paillier.Ciphertext, k, m int) *paillier.Ciphertext {

	// get 2^k-1 + a
	b := mpc.Pk.Encrypt(big.NewInt(0).Exp(big2, big.NewInt(int64(k-1)), nil))
	b = mpc.Pk.EAdd(b, a)

	// 2^m
	big2m := big.NewInt(0).Exp(big2, big.NewInt(int64(m)), nil)
	big2mInv := big.NewInt(0).ModInverse(big2m, mpc.Pk.N)

	// get solved bits
	//_, r, _ := mpc.ESolvedBits(m)
	r := mpc.ERandomShare(big.NewInt(0).Div(big2m, big.NewInt(int64(len(mpc.Parties)))))

	exp := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.Pk.S+k-m)), nil)
	rnd := mpc.ERandomShare(exp)

	// 2^m*rnd + r
	mask := mpc.Pk.ECMult(rnd, big2m)
	mask = mpc.Pk.EAdd(mask, r)

	c := mpc.RevealInt(mpc.Pk.EAdd(b, mask))
	c = c.Mod(c, big2m)

	res := mpc.Pk.Encrypt(c)
	res = mpc.Pk.ESub(res, r)
	res = mpc.Pk.ESub(a, res)
	res = mpc.Pk.ECMult(res, big2mInv)

	return res
}
