package hypocert

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"

	"hypocert/party"
)

// Constants
var big2InvN *big.Int
var big2InvP *big.Int
var big2 *big.Int
var big1 *big.Int
var big0 *big.Int

type MPC struct {
	Party      *node.Party   // party initiating the requests
	Parties    []*node.Party // all other parties in the system
	Threshold  int
	Pk         *paillier.PublicKey
	Verify     bool
	K          int      // message space 2^K < N
	S          int      // security parameter for statistical secure MPC
	P          *big.Int // secret share prime
	FPPrecBits int      // fixed point precision bits
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
	NetworkLatency  time.Duration // for network latency testing
}

func (mpc *MPC) RevealShareFP(share *node.Share, scale int) *big.Float {

	val := mpc.RevealShare(share)
	scaleFactor := big.NewInt(0).Exp(big2, big.NewInt(int64(scale)), nil)
	fp := big.NewFloat(0.0).SetInt(val)
	fp.Quo(fp, big.NewFloat(0.0).SetInt(scaleFactor))
	return fp
}

func (mpc *MPC) RevealShare(share *node.Share) *big.Int {

	var wg sync.WaitGroup
	values := make([]*big.Int, len(mpc.Parties))
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			val, err := mpc.Parties[i].RevealShare(share)
			if err != nil {
				panic(err)
			}
			val.Mul(val, mpc.Parties[i].BetaT)
			values[i] = val
		}(i)
	}

	wg.Wait()

	return mpc.ReconstructShare(values[0:mpc.Threshold])
}

func (mpc *MPC) DeleteAllShares() int {

	numShares := node.NewShareID()

	for i := 0; i < len(mpc.Parties); i++ {
		mpc.Parties[i].DeleteAllShares()
	}

	return numShares
}

func (mpc *MPC) CopyShare(share *node.Share) *node.Share {

	id := node.NewShareID()
	for i := 0; i < len(mpc.Parties); i++ {
		mpc.Parties[i].CopyShare(share, id)
	}

	return &node.Share{mpc.Party.ID, id}
}

func (mpc *MPC) ReconstructShare(values []*big.Int) *big.Int {

	s := big.NewInt(0)

	for i := 0; i < len(values); i++ {
		s.Add(s, values[i])
	}

	return s.Mod(s, mpc.P)
}
func (mpc *MPC) CreateShares(value *big.Int) *node.Share {

	id := node.NewShareID()
	shares, values, _ := mpc.Party.CreateShares(value, id)
	mpc.Party.DistributeShares(shares, values)
	return shares[mpc.Party.ID]
}

func (mpc *MPC) EncodeFixedPoint(a *big.Float, prec int) *big.Int {

	precPow := big.NewFloat(0.0).SetInt(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(prec)), nil))
	scaled := big.NewFloat(0).Mul(a, precPow)

	floor := big.NewInt(0)
	floor, _ = scaled.Int(floor)
	return floor
}

func (mpc *MPC) Add(share1, share2 *node.Share) *node.Share {

	id := node.NewShareID()

	var res *node.Share
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].Add(share1, share2, id)
		if err != nil {
			panic(err)
		}
	}

	return res
}
func (mpc *MPC) Sub(share1, share2 *node.Share) *node.Share {

	id := node.NewShareID()

	var res *node.Share
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].Sub(share1, share2, id)
		if err != nil {
			panic(err)
		}
	}

	return res
}

func (mpc *MPC) MultC(share *node.Share, c *big.Int) *node.Share {

	id := node.NewShareID()

	var res *node.Share
	var err error
	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err = mpc.Parties[i].MultC(share, c, id)
			if err != nil {
				panic(err)
			}
		}(i)
	}

	wg.Wait()

	return res
}

func (mpc *MPC) Mult(share1, share2 *node.Share) *node.Share {

	id := node.NewShareID()

	var res *node.Share
	var err error
	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err = mpc.Parties[i].Mult(share1, share2, id)
			if err != nil {
				panic(err)
			}
		}(i)
	}

	wg.Wait()

	return res
}

// EFPNormalize returns a tuple (b, v) such that a/2^v is between 0.5 and 1
func (mpc *MPC) FPNormalize(b *node.Share) (*node.Share, *node.Share) {

	bitsa := mpc.ReverseBits(mpc.BitsDec(b, mpc.K))
	ybits := mpc.ReverseBits(mpc.BitsPrefixOR(bitsa))

	for i := 0; i < mpc.K-1; i++ {
		ybits[i] = mpc.Sub(ybits[i], ybits[i+1])
	}

	v := mpc.CreateShares(big.NewInt(0))

	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K-1)), nil)

	for i := 0; i < mpc.K; i++ {
		t := mpc.MultC(ybits[i], pow)
		v = mpc.Add(v, t)
		pow.Div(pow, big.NewInt(2))
	}

	u := mpc.Mult(b, v)

	return u, v
}

//EFPReciprocal return an approximation of [1/b]
func (mpc *MPC) FPReciprocal(b *node.Share) *node.Share {

	a := mpc.CreateShares((mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.FPPrecBits)))
	return mpc.FPDivision(a, b)
}

// FPDivision return the approximate result of [a/b]
func (mpc *MPC) FPDivision(a, b *node.Share) *node.Share {

	// init goldschmidt constants
	theta := int(math.Ceil(math.Log2(float64(mpc.K) / 3.75)))
	alphaEnc := mpc.CreateShares(mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.K))

	w := mpc.initReciprocal(b)

	// x = theta - bw
	x := mpc.Sub(alphaEnc, mpc.Mult(b, w))

	// y = a*w
	y := mpc.Mult(a, w)
	y = mpc.TruncPR(y, 2*mpc.K, mpc.K/2)

	for i := 0; i < theta; i++ {

		// y = y * (alpha + x)
		y = mpc.Mult(y, mpc.Add(alphaEnc, x))
		y = mpc.TruncPR(y, 2*mpc.K, mpc.K)

		if i+1 < theta {
			x = mpc.Mult(x, x)
			x = mpc.TruncPR(x, 2*mpc.K, mpc.K)
		}
	}

	return mpc.TruncPR(y, 2*mpc.K, mpc.K/2-mpc.FPPrecBits)
}

func (mpc *MPC) initReciprocal(b *node.Share) *node.Share {

	// init goldschmidt constant
	alpha := mpc.CreateShares(mpc.EncodeFixedPoint(big.NewFloat(2.9142), mpc.K))

	// normalize the denominator
	u, v := mpc.FPNormalize(b)

	// d = alpha - 2u
	d := mpc.Sub(alpha, mpc.MultC(u, big.NewInt(2)))

	// w = d*v
	w := mpc.Mult(d, v)

	// return the normalize initial approximation
	t := mpc.TruncPR(w, 2*mpc.K, mpc.K)

	return t
}

func (mpc *MPC) TruncPR(a *node.Share, k, m int) *node.Share {

	// get 2^k-1 + a
	b := mpc.CreateShares(big.NewInt(0).Exp(big2, big.NewInt(int64(k-1)), nil))
	z := mpc.Add(b, a)

	// 2^m
	big2m := big.NewInt(0).Exp(big2, big.NewInt(int64(m)), nil)
	big2mInv := big.NewInt(0).ModInverse(big2m, mpc.P)

	// get solved bits
	_, r, _ := mpc.SolvedBits(m)

	exp := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.S+k-m)), nil)
	rnd := mpc.RandomShare(exp)

	// 2^m*rnd + r
	q := mpc.MultC(rnd, big2m)
	mask := mpc.Add(q, r)

	e := mpc.Add(z, mask)
	c := mpc.RevealShare(e)
	c = c.Mod(c, big2m)

	res := mpc.CreateShares(c)
	res = mpc.Sub(res, r)
	res = mpc.Sub(a, res)
	res = mpc.MultC(res, big2mInv)

	return res
}

func NewMPCKeyGen(params *MPCKeyGenParams) *MPC {

	nu := int(math.Log2(float64(params.NumParties)))
	if int64(params.MessageBits+params.SecurityBits+params.FPPrecisionBits+nu+1) >= int64(2*params.KeyBits) {
		panic("modulus not big enough for given parameters")
	}

	shareModulusBits := 2*params.MessageBits + params.FPPrecisionBits + params.SecurityBits + nu + 1
	secretSharePrime, err := rand.Prime(rand.Reader, shareModulusBits)

	tkh := paillier.GetThresholdKeyGenerator(params.KeyBits, params.NumParties, params.Threshold, rand.Reader)
	tpks, err := tkh.Generate()
	pk := &tpks[0].PublicKey

	if err != nil {
		panic("could not generate share prime")
	}

	if err != nil {
		panic(err)
	}

	// generate shamir polynomial
	parties := make([]*node.Party, params.NumParties)
	for i := 0; i < params.NumParties; i++ {

		// generate the Beta value used for
		// share reconstruction
		si := big.NewInt(int64(i + 1))
		betaThreshold := big.NewInt(1)
		betaFull := big.NewInt(1)

		denomThreshold := big.NewInt(1)
		denomFull := big.NewInt(1)

		for j := 1; j <= params.NumParties; j++ {

			if i+1 != j {
				sj := big.NewInt(int64(j))

				if j <= params.Threshold {
					betaThreshold.Mul(betaThreshold, sj)
					denomThreshold.Mul(denomThreshold, big.NewInt(0).Sub(sj, si))
				}

				betaFull.Mul(betaFull, sj)
				denomFull.Mul(denomFull, big.NewInt(0).Sub(sj, si))
			}
		}

		denomThreshold.ModInverse(denomThreshold, secretSharePrime)
		denomFull.ModInverse(denomFull, secretSharePrime)

		betaThreshold.Mul(betaThreshold, denomThreshold)
		betaThreshold.Mod(betaThreshold, secretSharePrime)
		betaFull.Mul(betaFull, denomFull)
		betaFull.Mod(betaFull, secretSharePrime)

		parties[i] = &node.Party{
			ID:             i,
			Sk:             tpks[i],
			Pk:             pk,
			P:              secretSharePrime,
			BetaT:          betaThreshold,
			BetaN:          betaFull,
			Threshold:      params.Threshold,
			Parties:        parties,
			NetworkLatency: params.NetworkLatency}
	}

	mpc := &MPC{parties[0], parties, params.Threshold, pk, params.Verify, params.MessageBits, params.SecurityBits, secretSharePrime, params.FPPrecisionBits}

	// init constants
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2InvN = big.NewInt(0).ModInverse(big2, pk.N)
	big2InvP = big.NewInt(0).ModInverse(big2, secretSharePrime)

	return mpc
}