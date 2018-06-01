package hypocert

import (
	"crypto/rand"
	"hypocertnode"
	"math"
	"math/big"
	"paillier"
	"sync"
	"time"
)

// Benchmark

var MultCountPaillier int
var MultCountShares int

// Constants
var big2InvN *big.Int
var big2InvP *big.Int
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

	values := make([]*big.Int, mpc.Threshold)
	for i := 0; i < mpc.Threshold; i++ {
		val, err := mpc.Parties[i].RevealShare(share)
		if err != nil {
			panic(err)
		}
		val.Mul(val, mpc.Parties[i].BetaT)
		values[i] = val
	}

	return mpc.ReconstructShare(values)
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

	return s.Mod(s, mpc.Pk.P)
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
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].MultC(share, c, id)
		if err != nil {
			panic(err)
		}
	}

	return res
}

func (mpc *MPC) Mult(share1, share2 *node.Share) *node.Share {

	id := node.NewShareID()

	var res *node.Share
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].Mult(share1, share2, id)
		if err != nil {
			panic(err)
		}
	}

	MultCountShares++

	return res
}

func (mpc *MPC) PaillierToShare(ct *paillier.Ciphertext) *node.Share {

	bound := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.S)), nil)
	r, rshare := mpc.ERandomAndShare(bound)
	val := mpc.RevealInt(mpc.Pk.EAdd(ct, r))
	share := mpc.CreateShares(val)
	res := mpc.Sub(share, rshare)

	return res
}

// EFPNormalize returns a tuple (b, v) such that a/2^v is between 0.5 and 1
func (mpc *MPC) EFPNormalize(b *node.Share) (*node.Share, *node.Share) {

	bitsa := mpc.ReverseBits(mpc.BitsDec(b, mpc.Pk.K))
	ybits := mpc.ReverseBits(mpc.BitsPrefixOR(bitsa))

	for i := 0; i < mpc.Pk.K-1; i++ {
		ybits[i] = mpc.Sub(ybits[i], ybits[i+1])
	}

	v := mpc.CreateShares(big.NewInt(0))

	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.Pk.K-1)), nil)

	for i := 0; i < mpc.Pk.K; i++ {
		t := mpc.MultC(ybits[i], pow)
		v = mpc.Add(v, t)
		pow.Div(pow, big.NewInt(2))
	}

	u := mpc.Mult(b, v)

	return u, v
}

//EFPReciprocal return an approximation of [1/b]
func (mpc *MPC) FPReciprocal(b *node.Share) *node.Share {

	a := mpc.CreateShares((mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.Pk.FPPrecBits)))
	return mpc.FPDivision(a, b)
}

// FPDivision return the approximate result of [a/b]
func (mpc *MPC) FPDivision(a, b *node.Share) *node.Share {

	// init goldschmidt constants
	theta := int(math.Ceil(math.Log2(float64(mpc.Pk.K) / 3.75)))
	alphaEnc := mpc.CreateShares(mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.Pk.K))

	w := mpc.initReciprocal(b)

	// x = theta - bw
	x := mpc.Sub(alphaEnc, mpc.Mult(b, w))

	// y = a*w
	y := mpc.Mult(a, w)
	y = mpc.TruncPR(y, 2*mpc.Pk.K, mpc.Pk.K/2)

	for i := 0; i < theta; i++ {

		// y = y * (alpha + x)
		y = mpc.Mult(y, mpc.Add(alphaEnc, x))
		y = mpc.TruncPR(y, 2*mpc.Pk.K, mpc.Pk.K)

		if i+1 < theta {
			x = mpc.Mult(x, x)
			x = mpc.TruncPR(x, 2*mpc.Pk.K, mpc.Pk.K)
		}
	}

	return mpc.TruncPR(y, 2*mpc.Pk.K, mpc.Pk.K/2-mpc.Pk.FPPrecBits)
}

func (mpc *MPC) initReciprocal(b *node.Share) *node.Share {

	// init goldschmidt constant
	alpha := mpc.CreateShares(mpc.EncodeFixedPoint(big.NewFloat(2.9142), mpc.Pk.K))

	// normalize the denominator
	u, v := mpc.EFPNormalize(b)

	// d = alpha - 2u
	d := mpc.Sub(alpha, mpc.MultC(u, big.NewInt(2)))

	// w = d*v
	w := mpc.Mult(d, v)

	// return the normalize initial approximation
	t := mpc.TruncPR(w, 2*mpc.Pk.K, mpc.Pk.K)

	return t
}

func (mpc *MPC) TruncPR(a *node.Share, k, m int) *node.Share {

	// get 2^k-1 + a
	b := mpc.CreateShares(big.NewInt(0).Exp(big2, big.NewInt(int64(k-1)), nil))
	z := mpc.Add(b, a)

	// 2^m
	big2m := big.NewInt(0).Exp(big2, big.NewInt(int64(m)), nil)
	big2mInv := big.NewInt(0).ModInverse(big2m, mpc.Pk.P)

	// get solved bits
	_, r, _ := mpc.SolvedBits(m)

	exp := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.Pk.S+k-m)), nil)
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

// Paillier MPC functions
func (mpc *MPC) EMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {

	mask, val := mpc.ERandomMultShare(a)

	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res = mpc.Pk.ESub(res, val)

	MultCountPaillier++

	return res
}

func (mpc *MPC) ECMultFP(ct *paillier.Ciphertext, fp *big.Float) *paillier.Ciphertext {
	e := mpc.Pk.EncodeFixedPoint(fp, mpc.Pk.FPPrecBits)
	m := new(big.Int).Exp(ct.C, e, mpc.Pk.GetNSquare())
	return mpc.EFPTruncPR(&paillier.Ciphertext{m}, mpc.Pk.K, mpc.Pk.FPPrecBits)
}

func (mpc *MPC) ECMult(ct *paillier.Ciphertext, c *big.Int) *paillier.Ciphertext {
	m := new(big.Int).Exp(ct.C, c, mpc.Pk.GetNSquare())
	return &paillier.Ciphertext{m}
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
	r := mpc.ERandom(big.NewInt(0).Div(big2m, big.NewInt(int64(len(mpc.Parties)))))

	exp := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.Pk.S+k-m)), nil)
	rnd := mpc.ERandom(exp)

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

// RandomMultShare returns a random encrypted integer and c*r
// in {1...Pk.N}, jointly generated by all parties
func (mpc *MPC) ERandomMultShare(c *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	shares := make([]*paillier.Ciphertext, len(mpc.Parties))
	sharesMult := make([]*paillier.Ciphertext, len(mpc.Parties))

	var wg sync.WaitGroup

	for i := 0; i < len(mpc.Parties); i++ {

		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			share, mult := mpc.Parties[i].GetRandomMultEnc(c)
			shares[i] = share

			sharesMult[i] = mult
		}(i)
	}

	wg.Wait()

	shareSum := mpc.Pk.Encrypt(big.NewInt(0))
	shareMult := mpc.Pk.Encrypt(big.NewInt(0))

	for i := 0; i < len(mpc.Parties); i++ {
		shareSum = mpc.Pk.EAdd(shareSum, shares[i])
		shareMult = mpc.Pk.EAdd(shareMult, sharesMult[i])
	}

	return shareSum, shareMult
}

// ERandom returns a random encrypted integer
// in {1...Pk.T}, jointly generated by all parties
func (mpc *MPC) ERandom(bound *big.Int) *paillier.Ciphertext {

	shares := make([]*paillier.Ciphertext, len(mpc.Parties))

	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			share := mpc.Parties[i].GetRandomEnc(bound)
			shares[i] = share
		}(i)
	}

	wg.Wait()

	shareSum := mpc.Pk.Encrypt(big.NewInt(0))
	for i := 0; i < len(mpc.Parties); i++ {
		shareSum = mpc.Pk.EAdd(shareSum, shares[i])
	}

	return shareSum
}

// ERandomAndShare returns a random encrypted integer (in paillier)
// and the corresponding values shared in Shamir, both jointly generated by all parties
func (mpc *MPC) ERandomAndShare(bound *big.Int) (*paillier.Ciphertext, *node.Share) {

	id := node.NewShareID()
	rand := make([]*paillier.Ciphertext, len(mpc.Parties))
	var randShare *node.Share

	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			enc, share := mpc.Parties[i].GetRandomEncAndShare(id, bound)
			randShare = share
			rand[i] = enc
		}(i)
	}

	wg.Wait()

	sum := mpc.Pk.Encrypt(big.NewInt(0))
	for i := 0; i < len(mpc.Parties); i++ {
		sum = mpc.Pk.EAdd(sum, rand[i])
	}

	return sum, randShare
}

func NewMPCKeyGen(params *MPCKeyGenParams) *MPC {

	//nu := big.NewInt(0).Binomial(int64(params.NumParties), int64(params.Threshold)).Int64()
	if int64(params.MessageBits+params.SecurityBits+params.FPPrecisionBits) >= int64(2*params.KeyBits) {
		panic("modulus not big enough for given parameters")
	}

	if params.MessageBits < params.FPPrecisionBits {
		panic("message space is smaller than the precision")
	}

	shareModulusBits := 2*params.KeyBits + 1

	tkh := paillier.GetThresholdKeyGenerator(params.KeyBits, params.NumParties, params.Threshold, rand.Reader)
	tpks, err := tkh.Generate()
	pk := &tpks[0].PublicKey
	pk.S = params.SecurityBits
	pk.K = params.MessageBits
	pk.P, err = rand.Prime(rand.Reader, shareModulusBits)
	if err != nil {
		panic("could not generate share prime")
	}

	pk.FPPrecBits = params.FPPrecisionBits

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

		denomThreshold.ModInverse(denomThreshold, pk.P)
		denomFull.ModInverse(denomFull, pk.P)

		betaThreshold.Mul(betaThreshold, denomThreshold)
		betaThreshold.Mod(betaThreshold, pk.P)
		betaFull.Mul(betaFull, denomFull)
		betaFull.Mod(betaFull, pk.P)

		parties[i] = &node.Party{
			ID:           i,
			Sk:           tpks[i],
			Pk:           pk,
			BetaT:        betaThreshold,
			BetaN:        betaFull,
			Threshold:    params.Threshold,
			Parties:      parties,
			DebugLatency: params.NetworkLatency}
	}

	mpc := &MPC{parties[0], parties, params.Threshold, pk, params.Verify}

	// init constants
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2InvN = big.NewInt(0).ModInverse(big2, pk.N)
	big2InvP = big.NewInt(0).ModInverse(big2, pk.P)

	return mpc
}
