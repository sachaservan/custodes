package hypocert

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"math/big"
	"paillier"
)

// Constants
var big2Inv *big.Int
var big2 *big.Int
var big1 *big.Int
var big0 *big.Int

type MPC struct {
	Parties []*Party
	Pk      *paillier.PublicKey
	Verify  bool
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

// PrecomputeData generates values needed ahead of time
// to speed up the online phase
func (mpc *MPC) PrecomputeData() {

	bitLen := mpc.Pk.K

	// TODO: calculate this value for better estimates of precomputation needs
	// arbitrary guess at the moment
	expectedNumRounds := 30 * int(math.Pow(float64(bitLen), 2))

	// compute the lagrange poly coeffs ahead of time
	mpc.computeBinaryFunctionCache(bitLen)

	fmt.Println("[DEBUG]: Finished computing Lagrange polynomials.")

	fmt.Println("[DEBUG]: Finished computing solved bits.")

	// precompute random shares for later use
	for _, party := range mpc.Parties {
		party.precomputeRandomShares(expectedNumRounds)
	}

	fmt.Println("[DEBUG]: Finished computing random shares.")

}

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

	mask, val := mpc.ERandomMultShare(a)

	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res = mpc.Pk.ESub(res, val)

	res = mpc.EFPTruncPR(res, mpc.Pk.K, mpc.Pk.FPPrecBits)

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

		val, err = mpc.Parties[0].Sk.CombinePartialDecryptions(partialDecrypts)
		if err != nil {
			panic(err)
		}

	} else {

		partialDecryptsZkps := make([]*paillier.PartialDecryptionZKP, len(mpc.Parties))

		for i := 0; i < len(mpc.Parties); i++ {
			partialDecryptsZkps[i] = mpc.Parties[i].PartialDecryptAndProof(ciphertext)
		}

		val, err = mpc.Parties[0].Sk.CombinePartialDecryptionsZKP(partialDecryptsZkps)
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

//EBitsTruncPR truncates a bitwise sharing where the last bit is
// probabilistically rounded up or down
func (mpc *MPC) EFPTruncToPrecPR(a, b *paillier.Ciphertext, k int) *paillier.Ciphertext {
	return mpc.EFPTruncPR(mpc.Pk.ESub(a, b), 2*mpc.Pk.K, mpc.Pk.K+mpc.Pk.FPPrecBits)
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

// EFPTruncToPrec takes b and return the value of b such that b bits < prec bits
func (mpc *MPC) EFPTruncToPrec(b *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	bitsb := mpc.ReverseBits(mpc.EBitsDec(b, mpc.Pk.K))
	ybits := mpc.ReverseBits(mpc.EBitsPrefixOR(bitsb))

	for i := 0; i < mpc.Pk.K-1; i++ {
		ybits[i] = mpc.Pk.ESub(ybits[i], ybits[i+1])
	}

	v := mpc.Pk.Encrypt(big.NewInt(0))
	s := mpc.Pk.Encrypt(big.NewInt(0))

	pow2f := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(2*mpc.Pk.FPPrecBits)), nil)

	// if c = 1, then v = 0 ==> u = 0
	c := mpc.EBitsLT(mpc.ReverseBits(bitsb), mpc.EBitsBigEndian(pow2f, mpc.Pk.K))

	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.K-1-2*mpc.Pk.FPPrecBits)), nil)

	scale := big.NewInt(1)

	for i := mpc.Pk.FPPrecBits * 2; i < mpc.Pk.K; i++ {
		t := mpc.Pk.ECMult(ybits[i], pow)
		v = mpc.Pk.EAdd(v, t)
		pow.Div(pow, big2)

		scale.Mul(scale, big2)

		scaleInv := big.NewFloat(0).Quo(big.NewFloat(1.0), big.NewFloat(0).SetInt(scale))
		t2 := mpc.Pk.ECMult(ybits[i], mpc.Pk.EncodeFixedPoint(scaleInv, mpc.Pk.K))
		s = mpc.Pk.EAdd(s, t2)
	}

	u := mpc.EMult(b, v)

	pow2kf := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.K-2*mpc.Pk.FPPrecBits)), nil)
	u = mpc.Pk.EAdd(u, mpc.EMult(c, mpc.Pk.ECMult(b, pow2kf)))
	u = mpc.EFPTruncPR(u, 2*mpc.Pk.K, mpc.Pk.K-2*mpc.Pk.FPPrecBits)

	s = mpc.Pk.EAdd(s, c)

	return u, s
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
	alphaEnc := mpc.Pk.Encrypt(mpc.Pk.EncodeFixedPoint(big.NewFloat(1.0), 2*mpc.Pk.FPPrecBits))

	w := mpc.initReciprocal(b)

	// x = theta - bw
	x := mpc.Pk.ESub(alphaEnc, mpc.EMult(b, w))

	// y = a*w
	y := mpc.EMult(a, w)
	y = mpc.EFPTruncPR(y, 2*mpc.Pk.K, mpc.Pk.FPPrecBits)

	for i := 0; i < theta; i++ {

		// y = y * (alpha + x)
		y = mpc.EMult(y, mpc.Pk.EAdd(alphaEnc, x))
		y = mpc.EFPTruncPR(y, 2*mpc.Pk.K, 2*mpc.Pk.FPPrecBits)

		if i+1 < theta {
			x = mpc.EMult(x, x)
			x = mpc.EFPTruncPR(x, 2*mpc.Pk.K, 2*mpc.Pk.FPPrecBits)
		}
	}

	return y
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
	w = mpc.EFPTruncPR(w, 2*mpc.Pk.K, 2*(mpc.Pk.K-mpc.Pk.FPPrecBits))

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

	parties := make([]*Party, len(tpks))
	for i := 0; i < len(tpks); i++ {
		parties[i] = &Party{tpks[i], pk}
	}

	mpc := &MPC{parties, pk, params.Verify}

	// init constants
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2Inv = big.NewInt(0).ModInverse(big2, pk.N)

	return mpc
}

// generates a new random number < max
func random(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}
