package hypocert

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"hypocert/party"
)

// set/propagate/kill wrapper used in the
// BitsCarries protocol
type spk struct {
	s, p, k *party.Share
}

type BooleanFunction int

const (
	BooleanOR  BooleanFunction = iota
	BooleanXOR BooleanFunction = iota
)

// RandomBits returns a random bit vector from {0,1}^l
func (mpc *MPC) RandomBits(m int) []*party.Share {

	bits := make([]*party.Share, m)
	twoInv := big.NewInt(0).ModInverse(big.NewInt(2), mpc.P)
	one := mpc.CreateShares(big.NewInt(1))

	var c *big.Int
	for i := 0; i < m; i++ {

		for {
			a := mpc.RandomShare(mpc.P)
			a2 := mpc.Mult(a, a)
			c = mpc.RevealShare(a2)
			if c.Cmp(big0) != 0 {
				c.ModSqrt(c, mpc.P)
				c.ModInverse(c, mpc.P)
				b := mpc.MultC(a, c)
				b = mpc.Add(b, one)
				bits[i] = mpc.MultC(b, twoInv)
				break
			}
		}
	}

	return bits
}

// RandomShare returns a shared random value between 0...n*bound
func (mpc *MPC) RandomShare(bound *big.Int) *party.Share {

	id := party.NewShareID()

	var r *party.Share
	for i := 0; i < len(mpc.Parties); i++ {
		r = mpc.Parties[i].CreateRandomShare(bound, id)
	}

	return r
}

// RandomInvertibleShare returns a random encrypted integer
// in {1...P} and its inverse (mod P)
func (mpc *MPC) RandomInvertibleShare() (*party.Share, *party.Share, error) {

	a := mpc.RandomShare(mpc.P)
	b := mpc.RandomShare(mpc.P)
	m := mpc.Mult(a, b)
	c := mpc.RevealShare(m)

	if c.Int64() == 0 {
		return nil, nil, errors.New("abort")
	}

	cInv := big.NewInt(0).ModInverse(c, mpc.P)
	aInv := mpc.MultC(b, cInv)

	return a, aInv, nil
}

// SolvedBits returns a random bit string from {0,1}^m and the corresponding
func (mpc *MPC) SolvedBits(m int) ([]*party.Share, *party.Share, error) {

	bits := mpc.RandomBits(m)

	// convert bits to an encrypted integer
	val := mpc.BitsToEInteger(bits)

	return bits, val, nil
}

// BitsExp returns 2^x where x = integer(bits)
func (mpc *MPC) BitsExp(bits []*party.Share) *party.Share {

	base := big.NewInt(2)
	one := mpc.CreateShares(big.NewInt(1))
	res := mpc.CreateShares(big.NewInt(1))

	for i := 0; i < len(bits); i++ {

		pow := mpc.MultC(bits[i], base)
		t1 := mpc.Mult(res, pow)
		t2 := mpc.Mult(mpc.Sub(one, bits[i]), one)
		t2 = mpc.Mult(t2, res)
		res = mpc.Add(t1, t2)
		base = base.Exp(base, big.NewInt(2), mpc.P)
	}
	return res
}

//BitsMult returns the bitwise sharing of a*b (note: a*b < pk.T)
func (mpc *MPC) BitsMult(a, b []*party.Share) []*party.Share {

	length := len(a) + 1
	l2 := int(math.Floor(float64(length) / 2.0))

	resBits := make([]*party.Share, length)
	partialSum := make([]*party.Share, length)

	zero := mpc.CreateShares(big.NewInt(0))
	for i := 0; i < length; i++ {
		partialSum[i] = zero
		resBits[i] = zero
	}

	for i := l2; i >= 0; i-- {
		for k := l2; k >= 0; k-- {
			c := mpc.Mult(a[i], b[k])
			partialSum[i+k] = c
		}

		if i == l2 {
			resBits = partialSum
		} else {
			resBits = mpc.BitsADD(resBits, partialSum)
			resBits = resBits[0:mpc.K]
		}
	}

	return resBits[0:mpc.K]

}

//BitsToEInteger returns the integer (in Zn) representation of an encrypted binary string
func (mpc *MPC) BitsToEInteger(bits []*party.Share) *party.Share {

	acc := mpc.CreateShares(big.NewInt(0))
	base := big.NewInt(2)
	for i := len(bits) - 1; i >= 0; i-- {
		res := mpc.MultC(acc, base)
		acc = mpc.Add(res, bits[i])
	}

	return acc
}

//BitsDec returns a bit representation of an integer in {0...T}
func (mpc *MPC) BitsDec(a *party.Share, m int) []*party.Share {

	// get solved bits
	solvedBits, d, err := mpc.SolvedBits(m)
	for err != nil {
		solvedBits, d, err = mpc.SolvedBits(m)
	}

	bound := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.S+mpc.K-m)), nil)
	r := mpc.RandomShare(bound)
	q := mpc.MultC(r, big.NewInt(0).Exp(big2, big.NewInt(int64(m)), nil))
	r = mpc.Add(q, d)

	max := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.K+mpc.S)), nil)
	max.Add(max, big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.K)), nil))

	// compute 2^(k + s + v) + 2^k + a - r where d is the integer returned from solvedbits
	maxShare := mpc.CreateShares(max)
	rev := mpc.RevealShare(mpc.Sub(mpc.Add(maxShare, a), d))

	// only keep the m least significant bits
	rev.Mod(rev, big.NewInt(0).Exp(big2, big.NewInt(int64(m)), nil))

	revBits := mpc.BitsBigEndian(rev, m+1)
	sumBits := mpc.BitsADD(revBits, solvedBits)

	return sumBits[0:m]
}

// FanInMULT efficiently computes [x,x^2,x^3...x^n] where n = len(elements)
// Note: can be used as a PrefixAND when elements are binary
func (mpc *MPC) FanInMULT(elements []*party.Share) []*party.Share {

	n := len(elements)
	res := make([]*party.Share, n)
	res[0] = elements[0]

	if n == 1 {
		return res
	}

	shares := make([]*party.Share, n)
	sharesInv := make([]*party.Share, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			var err error
			shares[i], sharesInv[i], err = mpc.RandomInvertibleShare()
			for err != nil {
				shares[i], sharesInv[i], err = mpc.RandomInvertibleShare()
			}
		}(i)
	}

	wg.Wait()

	d := make([]*party.Share, n)
	d[0] = shares[0]
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d[i] = mpc.Mult(shares[i], sharesInv[i-1])
		}(i)

	}
	wg.Wait()

	c := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := mpc.Mult(d[i], elements[i])
			c[i] = mpc.RevealShare(q)
		}(i)
	}
	wg.Wait()

	acc := c[0]
	for i := 1; i < n; i++ {
		acc.Mul(acc, c[i])
		res[i] = mpc.MultC(sharesInv[i], acc)
	}

	return res
}

func (mpc *MPC) BitsPrefixOR(bits []*party.Share) []*party.Share {

	degree := len(bits)

	// find the nearest square to len(bits)
	lambda := int(math.Ceil(math.Sqrt(float64(len(bits)))))
	zero := mpc.CreateShares(big.NewInt(0))

	diff := lambda*lambda - len(bits)
	for i := 0; i < diff; i++ {
		bits = append(bits, zero)
	}

	var wg sync.WaitGroup
	// Compute Row wise OR of elements in A
	rowOr := make([]*party.Share, lambda)
	for i := 0; i < lambda; i++ {
		wg.Add(1)
		row := make([]*party.Share, lambda)
		for j := 0; j < lambda; j++ {
			row[j] = bits[i*lambda+j]
		}

		go func(i int, row []*party.Share) {
			defer wg.Done()

			res := mpc.BitsOR(row)
			rowOr[i] = res

		}(i, row)
	}

	wg.Wait()

	// Compute ORs of Xis
	rowRes := make([]*party.Share, lambda)
	rowRes[0] = rowOr[0]

	wg.Add(lambda - 1)
	for n := 1; n < lambda; n++ {

		row := make([]*party.Share, n+1)
		for i := 0; i <= n; i++ {
			row[i] = rowOr[i]
		}

		go func(n int, row []*party.Share) {
			defer wg.Done()

			res := mpc.BitsOR(row)
			rowRes[n] = res

		}(n, row)
	}

	wg.Wait()

	f := make([]*party.Share, lambda)
	f[0] = rowOr[0]
	for i := 1; i < lambda; i++ {
		f[i] = mpc.Sub(rowRes[i], rowRes[i-1])
	}

	g := make([]*party.Share, lambda)
	for j := 0; j < lambda; j++ {
		sum := zero
		for i := 0; i < lambda; i++ {
			sum = mpc.Add(sum, mpc.Mult(bits[i*lambda+j], f[i]))
		}
		g[j] = sum
	}

	// Compute PrefixOr of ci
	b := make([]*party.Share, lambda)
	b[0] = g[0]

	wg.Add(lambda - 1)
	for n := 1; n < lambda; n++ {

		row := make([]*party.Share, n+1)
		for i := 0; i <= n; i++ {
			row[i] = g[i]
		}

		go func(n int, row []*party.Share) {
			defer wg.Done()

			res := mpc.BitsOR(row)
			b[n] = res

		}(n, row)
	}

	wg.Wait()

	s := make([]*party.Share, lambda)
	for i := 0; i < lambda; i++ {
		s[i] = mpc.Sub(rowRes[i], f[i])
	}

	result := make([]*party.Share, lambda*lambda)
	for i := 0; i < lambda; i++ {
		for j := 0; j < lambda; j++ {

			if lambda*i+j >= degree {
				break
			}

			sum := mpc.Mult(b[j], f[i])
			sum = mpc.Add(sum, s[i])

			res := sum

			result[i*lambda+j] = res
		}
	}

	return result[0:degree]
}

func (mpc *MPC) BitsPrefixSPK(bits []*spk) []*spk {

	degree := len(bits)

	var wg sync.WaitGroup
	wg.Add(degree)

	res := make([]*spk, degree)
	for i := 0; i < degree; i++ {
		go func(i int) {
			defer wg.Done()

			row := make([]*spk, i+1)
			for k := 0; k <= i; k++ {
				row[k] = bits[k]
			}

			spk := mpc.BitsSPK(row)
			res[i] = spk

		}(i)
	}

	wg.Wait()

	return res
}

// BitsADD outputs the bitwise representation of a+b
func (mpc *MPC) BitsADD(a, b []*party.Share) []*party.Share {

	if len(a) < len(b) {
		a = mpc.makeEqualLength(a, b)
	} else {
		b = mpc.makeEqualLength(b, a)
	}

	degree := len(a)
	carries := mpc.BitsCarries(a, b)

	sum := make([]*party.Share, degree+1)
	lsb := mpc.Add(a[0], b[0])
	lsb = mpc.Sub(lsb, mpc.MultC(carries[0], big.NewInt(2)))
	sum[0] = lsb
	sum[degree] = carries[degree-1]

	for i := 1; i < degree; i++ {
		sum[i] = mpc.Add(a[i], b[i])
		sum[i] = mpc.Add(sum[i], carries[i-1])
		sum[i] = mpc.Sub(sum[i], mpc.MultC(carries[i], big.NewInt(2)))
	}

	return sum
}

// BitsLT returns [0] if a > b, [1] otherwise
func (mpc *MPC) BitsLT(a, b []*party.Share) *party.Share {

	if len(a) < len(b) {
		a = mpc.makeEqualLength(a, b)
	} else {
		b = mpc.makeEqualLength(b, a)
	}

	degree := len(a) // len(a) = len(b) now
	e := make([]*party.Share, degree)

	var wg sync.WaitGroup

	for i := 0; i < degree; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := mpc.Sub(a[i], b[i])
			d2 := mpc.Mult(d, d)
			e[degree-i-1] = d2
		}(i)
	}

	wg.Wait()

	f := mpc.BitsPrefixOR(e)

	g := make([]*party.Share, degree)
	g[0] = f[0]
	for i := degree - 1; i > 0; i-- {
		g[i] = mpc.Sub(f[i], f[i-1])
	}

	wg.Wait()

	h := make([]*party.Share, degree)
	for i := 0; i < degree; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h[i] = mpc.Mult(g[degree-i-1], b[i])
		}(i)
	}

	wg.Wait()

	res := mpc.CreateShares(big.NewInt(0))

	for i := 0; i < degree; i++ {
		res = mpc.Add(res, h[i])
	}

	return res
}

func (mpc *MPC) BitsCarries(a, b []*party.Share) []*party.Share {

	one := mpc.CreateShares(big.NewInt(1))
	degree := len(a) // len(a) = len(b) now

	s := make([]*party.Share, degree)
	p := make([]*party.Share, degree)
	k := make([]*party.Share, degree)
	spks := make([]*spk, degree)

	for i := 0; i < degree; i++ {
		s[i] = mpc.Mult(a[i], b[i])
	}

	for i := 0; i < degree; i++ {
		// compute propagate bit
		d := mpc.Add(a[i], b[i])
		q := mpc.MultC(s[i], big.NewInt(2))
		p[i] = mpc.Sub(d, q)

		// compute kill bit
		d = mpc.Add(s[i], p[i])
		k[i] = mpc.Sub(one, d)

		spks[i] = &spk{s: s[i], p: p[i], k: k[i]}
	}

	f := mpc.BitsPrefixSPK(spks)

	res := make([]*party.Share, degree)

	for i := 0; i < degree; i++ {
		res[i] = f[i].s
	}

	return res
}

func (mpc *MPC) BitsSPK(tups []*spk) *spk {

	//fmt.Println("[DEBUG]:  bitsSPK()")

	size := len(tups)

	b := mpc.CopyShare(tups[0].p)
	for i := 1; i < size; i++ {
		b = mpc.Mult(b, tups[i].p) // equiv to AND operation
	}

	allPs := make([]*party.Share, size)
	for i := 0; i < size; i++ {
		allPs[i] = mpc.CopyShare(tups[size-i-1].p)
	}

	preAnd := mpc.ReverseBits(mpc.FanInMULT(allPs))

	carries := make([]*party.Share, size)
	carries[size-1] = tups[size-1].k

	var wg sync.WaitGroup
	wg.Add(size - 1)
	for i := 0; i < size-1; i++ {
		go func(i int) {
			defer wg.Done()
			carries[i] = mpc.Mult(tups[i].k, preAnd[i+1]) // equiv to AND operation
		}(i)
	}

	wg.Wait()

	zero := mpc.CreateShares(big.NewInt(0))
	one := mpc.CreateShares(big.NewInt(1))

	sum := zero
	for i := 0; i < size; i++ {
		sum = mpc.Add(sum, carries[i])
	}

	diff := mpc.Add(b, sum)
	a := mpc.Sub(one, diff)

	// cleanup
	return &spk{s: a, p: b, k: sum}
}

func (mpc *MPC) ReverseBits(bits []*party.Share) []*party.Share {

	size := len(bits)
	bitsR := make([]*party.Share, size)
	for i := 0; i < size; i++ {
		bitsR[size-i-1] = bits[i]
	}

	return bitsR
}

// BitsBigEndian returns the n-bit (encrypted) representation of an integer a
func (mpc *MPC) BitsBigEndian(a *big.Int, n int) []*party.Share {

	s := fmt.Sprintf("%b", a)
	bits := make([]*party.Share, len(s))
	k := 0
	for i := len(s) - 1; i >= 0; i-- {
		bits[k] = mpc.CreateShares(big.NewInt(int64(s[i] - '0')))
		k++
	}

	zero := mpc.CreateShares(big.NewInt(0))
	for i := n - len(s) - 1; i >= 0; i-- {
		bits = append(bits, zero)
	}

	return bits
}

// BitsZero returns the n-bit vector of zeros
func (mpc *MPC) BitsZero() []*party.Share {

	n := mpc.K
	bits := make([]*party.Share, n)
	zero := mpc.CreateShares(big.NewInt(0))

	for i := 0; i < n; i++ {
		bits[i] = zero
	}

	return bits
}

func (mpc *MPC) symmetricBooleanFunction(bits []*party.Share, f BooleanFunction) *party.Share {

	n := len(bits)

	sum := mpc.CreateShares(big.NewInt(1))
	for i := 0; i < n; i++ {
		s := mpc.Add(sum, bits[i])
		sum = s
	}

	a := make([]*party.Share, n+1)
	for i := 0; i <= n; i++ {
		a[i] = sum
	}

	mul := mpc.FanInMULT(a)

	var poly []*big.Int
	if f == BooleanOR {
		poly = funcORInterpolation(n, mpc.P)
	} else if f == BooleanXOR {
		poly = funcXORInterpolation(n, mpc.P)
	}

	res := mpc.CreateShares(poly[n])
	for i := 1; i <= n; i++ {
		c := mpc.MultC(mul[i-1], poly[n-i])
		res = mpc.Add(res, c)
	}

	return res
}

// BitsXOR computes the XOR of all the bits
func (mpc *MPC) BitsXOR(bits []*party.Share) *party.Share {
	return mpc.symmetricBooleanFunction(bits, BooleanXOR)
}

// BitsOR computes the OR of all the bits
func (mpc *MPC) BitsOR(bits []*party.Share) *party.Share {
	return mpc.symmetricBooleanFunction(bits, BooleanOR)
}

// BitsAND computes the AND of all the bits
func (mpc *MPC) BitsAND(bits []*party.Share) *party.Share {

	degree := len(bits)

	res := bits[0]
	for i := 1; i < degree; i++ {
		res = mpc.Mult(res, bits[i])
	}

	return res
}

func (mpc *MPC) makeEqualLength(a, b []*party.Share) []*party.Share {
	zero := mpc.CreateShares(big.NewInt(0))
	delta := len(b) - len(a)
	zeroArray := make([]*party.Share, delta)
	for i := 0; i < delta; i++ {
		zeroArray[i] = zero
	}

	return append(a, zeroArray...)
}
