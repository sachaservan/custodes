package sbst

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
)

// set/propagate/kill wrapper used in the
// carries protocol
type spk struct {
	s, p, k *pbc.Element
}

func (mpc *MPC) RandomShare() *pbc.Element {

	share := mpc.Pk.EncryptElement(big.NewInt(0))
	for i := 0; i < len(mpc.Parties); i++ {
		share = mpc.Pk.EAddElements(share, mpc.Parties[i].getRandomShare())
	}
	return share
}

func (mpc *MPC) RandomInvertableShare() (*pbc.Element, *pbc.Element) {

	a := mpc.RandomShare()
	b := mpc.RandomShare()

	c := mpc.DecryptElementMPC(mpc.Pk.EMultElements(a, b), true)

	cinv := big.NewInt(0).ModInverse(c, mpc.Pk.T)
	ainv := mpc.Pk.EMultCElement(b, cinv, true)

	return a, ainv
}

func (mpc *MPC) RandomBit() (*pbc.Element, error) {

	r := mpc.RandomShare()
	r2 := mpc.Pk.EMultElements(r, r)
	a := mpc.DecryptElementMPC(r2, true)

	if a.Cmp(big.NewInt(0)) == 0 {
		// abort
		return nil, errors.New("aborted")
	}

	b := a.ModSqrt(a, mpc.Pk.T)

	bInv := big.NewInt(0).ModInverse(b, mpc.Pk.T)               // find b^-1 mod T
	twoInv := big.NewInt(0).ModInverse(big.NewInt(2), mpc.Pk.T) // find 2^-1 mod T

	c := mpc.Pk.EMultCElement(r, bInv, mpc.Pk.Deterministic)
	c = mpc.Pk.EAddElements(c, mpc.Pk.EncryptElement(big.NewInt(1)))

	ebit := mpc.Pk.EMultCElement(c, twoInv, mpc.Pk.Deterministic)

	return ebit, nil
}

func (mpc *MPC) SolvedBits(n int) (error, []*pbc.Element, *pbc.Element) {

	// TODO: generate bits for the full message space!

	bits := make([]*pbc.Element, n)
	for i := 0; i < n; i++ {
		bit, err := mpc.RandomBit()
		// err if protocol aborts; a low probability event
		for err != nil {
			bit, err = mpc.RandomBit()
		}

		bits[i] = bit
	}

	maxBits := mpc.EBitsBigEndian(mpc.Pk.T, n)

	fmt.Print("BITS(T) = ")
	for i := 0; i < len(maxBits); i++ {
		d := mpc.DecryptElementMPC(maxBits[len(maxBits)-i-1], false)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	fmt.Print("BITS(R) = ")
	for i := 0; i < len(bits); i++ {
		d := mpc.DecryptElementMPC(bits[len(bits)-i-1], false)
		fmt.Printf("%d", d)
	}
	fmt.Println()

	bad := mpc.EBitsLessThan(maxBits, bits)
	if mpc.DecryptElementMPC(bad, true).Int64() == 1 {
		fmt.Println("[DEBUG]: Solved bits aborted.")
		return errors.New("aborted"), nil, nil
	}

	val := mpc.Pk.EncryptElement(big.NewInt(0))
	pow := big.NewInt(1)
	for i := 0; i < len(bits); i++ {
		val = mpc.Pk.EAddElements(val, mpc.Pk.EMultCElement(bits[i], pow, true))
		pow = pow.Mul(pow, big.NewInt(2))
	}

	return nil, bits, val
}

func (mpc *MPC) EBitsDecompose(a *pbc.Element, n int, p *big.Int) []*pbc.Element {

	// TODO: generate bits for the full message space!, not just n
	// also figure out what the relation between 'l' and 'p' is

	max := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(n)), nil)
	maxEBits := mpc.EBitsBigEndian(p, n)
	deltaBits := mpc.BitsBigEndian(big.NewInt(0).Sub(max, p), n)

	err, sbits, d := mpc.SolvedBits(n)
	for err != nil {
		err, sbits, d = mpc.SolvedBits(n)
	}

	fmt.Println("[DEBUG]: Done getting solved bits.")
	r := mpc.DecryptElementMPC(mpc.Pk.ESubElements(a, d), false)

	rbits := mpc.EBitsBigEndian(r, n)
	sumBits := mpc.EBitsSum(rbits, sbits)

	q := mpc.ReEncryptElementMPC(mpc.EBitsLessThan(maxEBits, sumBits))
	g := make([]*pbc.Element, n)
	for i := 0; i < n; i++ {
		g[i] = mpc.Pk.EMultCElement(q, deltaBits[i], true)
	}

	h := mpc.EBitsSum(sumBits, g)
	return h[0 : len(h)-1] // drop the two most significant bits to correct error

}

func (mpc *MPC) EFanInMult(elements []*pbc.Element) []*pbc.Element {

	degree := len(elements)
	randomBits := make([]*pbc.Element, degree+1)
	randomBitsInv := make([]*pbc.Element, degree+1)
	for i := 0; i <= degree; i++ {
		randomBits[i], randomBitsInv[i] = mpc.RandomInvertableShare()
	}

	res := make([]*pbc.Element, degree)
	powerMult := elements[0]
	for i := 0; i < degree; i++ {
		d := mpc.Pk.EMultElements(randomBits[i], powerMult)
		d = mpc.ReEncryptElementMPC(d)
		d = mpc.Pk.EMultElements(d, randomBitsInv[i+1])

		q := mpc.DecryptElementMPC(d, true)

		inv := mpc.Pk.EMultElements(randomBitsInv[i], randomBits[i+1])
		res[i] = mpc.ReEncryptElementMPC(mpc.Pk.EMultCElementL2(inv, q, true))

		if i+1 < degree {
			powerMult = mpc.Pk.EMultElements(powerMult, elements[i+1])
			powerMult = mpc.ReEncryptElementMPC(powerMult)
		}
	}

	return res
}

func (mpc *MPC) EBitsOR(bits []*pbc.Element) *pbc.Element {

	degree := len(bits)
	poly := BitORPolynomial(degree, mpc.Pk.T)

	sum := mpc.Pk.EncryptElement(big.NewInt(1))
	for i := 0; i < degree; i++ {
		sum = mpc.Pk.EAddElements(sum, bits[i])
	}

	a := make([]*pbc.Element, degree+1)
	for i := 0; i <= degree; i++ {
		a[i] = sum
	}

	a = mpc.EFanInMult(a)

	res := mpc.Pk.EncryptElement(poly[degree].Add(poly[degree], big.NewInt(1)))
	for i := 1; i <= degree; i++ {
		c := mpc.Pk.EMultCElement(a[i-1], poly[degree-i], true)
		res = mpc.Pk.EAddElements(res, c)
	}

	return res
}

func (mpc *MPC) EBitsAND(bits []*pbc.Element) *pbc.Element {

	degree := len(bits)

	res := bits[0]
	for i := 1; i < degree; i++ {
		c := mpc.Pk.EMultElements(res, bits[i])
		res = mpc.ReEncryptElementMPC(c)
	}

	return res
}

func (mpc *MPC) EBitsPrefixOR(bits []*pbc.Element) []*pbc.Element {

	degree := len(bits)

	// TODO: process this loop in parallel
	res := make([]*pbc.Element, degree)
	for i := 0; i < degree; i++ {
		row := make([]*pbc.Element, i+1)
		for k := 0; k <= i; k++ {
			if k <= i {
				row[k] = bits[k]
			}
		}

		res[i] = mpc.EBitsOR(row)
	}

	return res
}

func (mpc *MPC) EBitsPrefixSPK(bits []*spk) []*spk {

	degree := len(bits)
	// TODO: process this loop in parallel
	res := make([]*spk, degree)
	for i := 0; i < degree; i++ {
		row := make([]*spk, i+1)
		for k := 0; k <= i; k++ {
			row[k] = bits[k]
		}

		res[i] = mpc.bitsSPK(row)
	}

	return res
}

func (mpc *MPC) EBitsSum(a, b []*pbc.Element) []*pbc.Element {

	if len(a) < len(b) {
		a = mpc.makeEqualLength(a, b)
	} else {
		b = mpc.makeEqualLength(b, a)
	}

	degree := len(a) // len(a) = len(b) now

	carries := mpc.EBitsCarries(a, b)
	sum := make([]*pbc.Element, degree+1)
	lsb := mpc.Pk.EAddElements(a[0], b[0])
	lsb = mpc.Pk.ESubElements(lsb, mpc.Pk.EMultCElement(carries[0], big.NewInt(2), true))
	sum[0] = lsb
	sum[degree] = carries[degree-1]

	for i := 1; i < degree; i++ {
		sum[i] = mpc.Pk.EAddElements(a[i], b[i])
		sum[i] = mpc.Pk.EAddElements(sum[i], carries[i-1])
		sum[i] = mpc.Pk.ESubElements(sum[i], mpc.Pk.EMultCElement(carries[i], big.NewInt(2), true))
	}

	return sum[0 : len(sum)-1] // correct the bit length
}

func (mpc *MPC) EBitsLessThan(a, b []*pbc.Element) *pbc.Element {

	if len(a) < len(b) {
		a = mpc.makeEqualLength(a, b)
	} else {
		b = mpc.makeEqualLength(b, a)
	}

	degree := len(a) // len(a) = len(b) now
	e := make([]*pbc.Element, degree)

	for i := 0; i < degree; i++ {
		d := mpc.Pk.ESubElements(a[i], b[i])
		e[degree-i-1] = mpc.ReEncryptElementMPC(mpc.Pk.EMultElements(d, d))
	}

	f := mpc.EBitsPrefixOR(e)

	g := make([]*pbc.Element, degree)
	g[0] = f[0]
	for i := degree - 1; i > 0; i-- {
		g[i] = mpc.Pk.ESubElements(f[i], f[i-1])
	}

	h := make([]*pbc.Element, degree)
	for i := 0; i < degree; i++ {
		h[i] = mpc.Pk.EMultElements(g[degree-i-1], b[i])
	}

	res := mpc.Pk.ToDeterministicL2Element(mpc.Pk.EncryptElement(big.NewInt(0)))

	for i := 0; i < degree; i++ {
		res = mpc.Pk.EAddL2Elements(res, h[i])
	}

	return res
}

func (mpc *MPC) EBitsCarries(a, b []*pbc.Element) []*pbc.Element {

	if len(a) < len(b) {
		a = mpc.makeEqualLength(a, b)
	} else {
		b = mpc.makeEqualLength(b, a)
	}

	one := mpc.Pk.EncryptElement(big.NewInt(1))
	degree := len(a) // len(a) = len(b) now

	s := make([]*pbc.Element, degree)
	p := make([]*pbc.Element, degree)
	k := make([]*pbc.Element, degree)
	spks := make([]*spk, degree)

	// TODO: process this loop in parallel
	for i := 0; i < degree; i++ {
		c := mpc.Pk.EMultElements(a[i], b[i])
		s[i] = mpc.ReEncryptElementMPC(c)
	}

	for i := 0; i < degree; i++ {

		// compute propagate bit
		d := mpc.Pk.EAddElements(a[i], b[i])
		p[i] = mpc.Pk.ESubElements(d, mpc.Pk.EMultCElement(s[i], big.NewInt(2), true))

		// compute kill bit
		d = mpc.Pk.EAddElements(s[i], p[i])
		k[i] = mpc.Pk.ESubElements(one, d)

		spks[i] = &spk{s: s[i], p: p[i], k: k[i]}
	}

	// for i := 0; i < degree; i++ {

	// 	fmt.Printf("spks = (%d,%d,%d)", mpc.DecryptElementMPC(spks[i].s, false), mpc.DecryptElementMPC(spks[i].p, false), mpc.DecryptElementMPC(spks[i].k, false))
	// }
	// fmt.Println()

	f := mpc.EBitsPrefixSPK(spks)

	res := make([]*pbc.Element, degree)

	for i := 0; i < degree; i++ {

		//fmt.Printf("f[i] = (%d,%d,%d)", mpc.DecryptElementMPC(f[i].s, false), mpc.DecryptElementMPC(f[i].p, true), mpc.DecryptElementMPC(f[i].k, true))
		res[i] = f[i].s
	}

	return res
}

func (mpc *MPC) makeEqualLength(a, b []*pbc.Element) []*pbc.Element {
	zero := mpc.Pk.EncryptElement(big.NewInt(0))
	delta := len(b) - len(a)
	zeroArray := make([]*pbc.Element, delta)
	for i := 0; i < delta; i++ {
		zeroArray[i] = zero
	}

	return append(a, zeroArray...)
}

func (mpc *MPC) bitsSPK(tups []*spk) *spk {

	size := len(tups)

	b := tups[0].p
	for i := 1; i < size; i++ {
		c := mpc.Pk.EMultElements(b, tups[i].p) // equiv to AND operation
		b = mpc.ReEncryptElementMPC(c)
	}

	allPs := make([]*pbc.Element, size)
	for i := 0; i < size; i++ {
		allPs[i] = tups[size-i-1].p
	}

	preAnd := mpc.ReverseBits(mpc.EFanInMult(allPs))

	carries := make([]*pbc.Element, size)
	carries[size-1] = mpc.Pk.ToDeterministicL2Element(tups[size-1].k)

	// TODO: process this loop in parallel
	for i := 0; i < size-1; i++ {
		q := mpc.Pk.EMultElements(tups[i].k, preAnd[i+1]) // equiv to AND operation
		carries[i] = q
	}

	zero := mpc.Pk.EncryptElement(big.NewInt(0))
	one := mpc.Pk.EncryptElement(big.NewInt(1))

	c := mpc.Pk.ToDeterministicL2Element(zero)
	for i := 0; i < size; i++ {
		c = mpc.Pk.EAddL2Elements(c, carries[i])
	}

	b = mpc.Pk.ToDeterministicL2Element(b)
	diff := mpc.Pk.EAddL2Elements(b, c)
	a := mpc.Pk.ESubL2Elements(mpc.Pk.ToDeterministicL2Element(one), diff)
	a = mpc.ReEncryptElementMPC(a)

	return &spk{s: a, p: b, k: c}
}

func (mpc *MPC) ReverseBits(bits []*pbc.Element) []*pbc.Element {

	size := len(bits)
	bitsR := make([]*pbc.Element, size)
	for i := 0; i < size; i++ {
		bitsR[size-i-1] = bits[i]
	}

	return bitsR
}

func reverseBigs(nums []*big.Int) []*big.Int {
	if len(nums) == 0 {
		return nums
	}

	return append(reverseBigs(nums[1:]), nums[0])
}

func (mpc *MPC) BitsBigEndian(a *big.Int, n int) []*big.Int {
	s := fmt.Sprintf("%b", a)
	bits := make([]*big.Int, len(s))
	k := 0
	for i := len(s) - 1; i >= 0; i-- {
		bits[k] = big.NewInt(int64(s[i] - '0'))
		k++
	}

	for i := n - len(s); i >= 0; i-- {
		bits = append(bits, big.NewInt(0))
	}

	return bits
}

func (mpc *MPC) EBitsBigEndian(a *big.Int, n int) []*pbc.Element {
	s := fmt.Sprintf("%b", a)
	bits := make([]*pbc.Element, len(s))
	k := 0
	for i := len(s) - 1; i >= 0; i-- {
		bits[k] = mpc.Pk.EncryptElement(big.NewInt(int64(s[i] - '0')))
		k++
	}

	zero := mpc.Pk.EncryptDeterministic(big.NewInt(0))
	for i := n - len(s); i >= 0; i-- {
		bits = append(bits, zero)
	}

	return bits
}

func neg(a *big.Int, p *big.Int) *big.Int {
	return big.NewInt(0).Sub(p, a)
}

func BitORPolynomial(n int, p *big.Int) []*big.Int {

	var numerator []*big.Int
	var poly []*big.Int

	denom := big.NewInt(1)
	poly = make([]*big.Int, n)

	for k := 0; k < n; k++ {
		poly[k] = big.NewInt(0)
	}

	for i := 1; i <= n; i++ {
		for j := 0; j <= n; j++ {
			if i != j {
				xi := big.NewInt(int64(i + 1))
				xj := big.NewInt(int64(j + 1))

				if numerator == nil {
					numerator = []*big.Int{big.NewInt(1), neg(xi, p)}
				} else {
					numerator = polyMult(numerator, []*big.Int{big.NewInt(1), neg(xj, p)})
				}

				denom.Mul(denom, big.NewInt(0).Add(xi, neg(xj, p)))
			}
		}

		if big.NewInt(0).Abs(denom).Cmp(big.NewInt(1)) != 0 {
			denom = denom.ModInverse(denom, p)
		}

		for i := 0; i < len(numerator); i++ {
			numerator[i].Mul(numerator[i], denom)
		}

		poly = polyAdd(poly, numerator)

		// reset
		denom = big.NewInt(1)
		numerator = nil

	}

	for i := 0; i < len(poly); i++ {
		if poly[i].Cmp(big.NewInt(0)) < 0 {
			poly[i] = poly[i].Neg(poly[i])
			poly[i] = poly[i].Mod(poly[i], p)
			poly[i] = neg(poly[i], p)
		} else {
			poly[i] = poly[i].Mod(poly[i], p)
		}
	}

	return poly
}

func polyMult(poly1 []*big.Int, poly2 []*big.Int) []*big.Int {
	n := len(poly1) + len(poly2)
	result := make([]*big.Int, n)
	for k := 0; k < n; k++ {
		result[k] = big.NewInt(0)
	}

	for i, coefficient := range poly1 {
		for j, coefficient2 := range poly2 {
			result[i+j].Add(result[i+j], big.NewInt(0).Mul(coefficient, coefficient2))
		}
	}
	return result[0 : n-1]
}

func polyAdd(poly1 []*big.Int, poly2 []*big.Int) []*big.Int {
	len1 := len(poly1)
	len2 := len(poly2)

	result := make([]*big.Int, len1)

	if len1 >= len2 {
		for i := 0; i < len1-len2; i++ {
			result[i] = poly1[i]
		}

		k := 0
		for i := len1 - len2; i < len1; i++ {
			result[i] = big.NewInt(0).Add(poly1[i], poly2[k])
			k++
		}

	} else {
		result = polyAdd(poly2, poly1)
	}

	return result

}
