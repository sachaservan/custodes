package hypocert

import (
	"math"
	"math/big"
	"sync"

	"hypocert/party"
)

func (mpc *MPC) RevealShareFP(share *party.Share, scale int) *big.Float {

	val := mpc.RevealShare(share)
	scaleFactor := big.NewInt(0).Exp(big2, big.NewInt(int64(scale)), nil)
	fp := big.NewFloat(0.0).SetInt(val)
	fp.Quo(fp, big.NewFloat(0.0).SetInt(scaleFactor))
	return fp
}

func (mpc *MPC) RevealShare(share *party.Share) *big.Int {

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

	numShares := party.NewShareID()

	for i := 0; i < len(mpc.Parties); i++ {
		mpc.Parties[i].DeleteAllShares()
	}

	return numShares
}

func (mpc *MPC) CopyShare(share *party.Share) *party.Share {

	id := party.NewShareID()
	for i := 0; i < len(mpc.Parties); i++ {
		mpc.Parties[i].CopyShare(share, id)
	}

	return &party.Share{mpc.Party.ID, id}
}

func (mpc *MPC) ReconstructShare(values []*big.Int) *big.Int {

	s := big.NewInt(0)

	for i := 0; i < len(values); i++ {
		s.Add(s, values[i])
	}

	s.Mod(s, mpc.P)

	return s
}
func (mpc *MPC) CreateShares(value *big.Int) *party.Share {

	id := party.NewShareID()
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

func (mpc *MPC) Add(share1, share2 *party.Share) *party.Share {

	id := party.NewShareID()

	var res *party.Share
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].Add(share1, share2, id)
		if err != nil {
			panic(err)
		}
	}

	return res
}
func (mpc *MPC) Sub(share1, share2 *party.Share) *party.Share {

	id := party.NewShareID()

	var res *party.Share
	var err error
	for i := 0; i < len(mpc.Parties); i++ {
		res, err = mpc.Parties[i].Sub(share1, share2, id)
		if err != nil {
			panic(err)
		}
	}

	return res
}

func (mpc *MPC) MultC(share *party.Share, c *big.Int) *party.Share {

	id := party.NewShareID()

	var res *party.Share
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

func (mpc *MPC) Mult(share1, share2 *party.Share) *party.Share {

	id := party.NewShareID()

	var res *party.Share
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
func (mpc *MPC) FPNormalize(b *party.Share) (*party.Share, *party.Share) {

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
func (mpc *MPC) FPReciprocal(b *party.Share) *party.Share {

	a := mpc.CreateShares((mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.FPPrecBits)))
	return mpc.FPDivision(a, b)
}

// FPDivision return the approximate result of [a/b]
func (mpc *MPC) FPDivision(a, b *party.Share) *party.Share {

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

	return y
}

func (mpc *MPC) initReciprocal(b *party.Share) *party.Share {

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

// FPDivision return the approximate result of [a/b]
func (mpc *MPC) FPSqrtReciprocal(a *party.Share) *party.Share {

	// init goldschmidt constants
	theta := int(math.Ceil(math.Log2(float64(mpc.K) / 3.75)))

	// get initial reciprocal  approximation
	b := mpc.CopyShare(a)
	precPow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K/2-mpc.FPPrecBits)), nil)

	b = mpc.MultC(b, precPow)
	y := mpc.initSquareRoot(a)
	z := mpc.CopyShare(y)

	for i := 0; i < theta; i++ {

		// compute y^2
		y2 := mpc.Mult(y, y)
		y2 = mpc.TruncPR(y2, 2*mpc.K, mpc.K/2)

		b = mpc.Mult(b, y2)
		b = mpc.TruncPR(b, 2*mpc.K, mpc.K/2)

		three := mpc.CreateShares(mpc.EncodeFixedPoint(big.NewFloat(3.0), mpc.K/2))
		half := mpc.EncodeFixedPoint(big.NewFloat(0.5), mpc.K/2)

		y = mpc.Sub(three, b)
		y = mpc.MultC(y, half)
		y = mpc.TruncPR(y, 2*mpc.K, mpc.K/2)

		z = mpc.Mult(z, y)
		z = mpc.TruncPR(z, 2*mpc.K, mpc.K/2)

	}

	return z
}

func (mpc *MPC) initSquareRoot(a *party.Share) *party.Share {

	bitsa := mpc.ReverseBits(mpc.BitsDec(a, mpc.K))
	ybits := mpc.ReverseBits(mpc.BitsPrefixOR(bitsa))

	for i := 0; i < mpc.K-1; i++ {
		ybits[i] = mpc.Sub(ybits[i], ybits[i+1])
	}

	v := mpc.CreateShares(big.NewInt(0))

	aprx := mpc.EncodeFixedPoint(big.NewFloat(1.0), mpc.K/2)

	for i := 0; i < mpc.K; i++ {
		t := mpc.MultC(ybits[i], aprx)
		v = mpc.Add(v, t)
		aprx = mpc.EncodeFixedPoint(big.NewFloat(1.0/math.Sqrt(math.Pow(2, float64(i-mpc.FPPrecBits+1)))), mpc.K/2)
	}

	return v
}

func (mpc *MPC) TruncPR(a *party.Share, k, m int) *party.Share {

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

func (mpc *MPC) SignBit(a *party.Share) *party.Share {
	big2K := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.K-1)), nil)

	shiftShare := mpc.CreateShares(big2K)
	pos := mpc.Add(a, shiftShare)
	aBits := mpc.BitsDec(pos, mpc.K)
	thresholdBits := mpc.BitsBigEndian(big2K, mpc.K)
	signbit := mpc.BitsLT(aBits, thresholdBits)
	return signbit

	// 	fmt.Println("[DEBUG] SHIFTED: " + mpc.RevealShare(pos).String())
	// 	fmt.Println("[DEBUG] BITS: ")
	// 	for i := len(aBits) - 1; i >= 0; i-- {
	// 		fmt.Print(mpc.RevealShare(aBits[i]))
	// 	}
	// 	fmt.Println()
}
