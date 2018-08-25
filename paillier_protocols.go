package hypocert

import (
	"errors"
	"hypocert/party"
	"math/big"
	"sync"

	"github.com/sachaservan/paillier"
)

var funcEXORCoefficientCache sync.Map

func (mpc *MPC) EMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {
	mask, val := mpc.ERandomMultShare(a)
	c := mpc.Pk.EAdd(b, mask)
	rev := mpc.RevealInt(c)
	res := mpc.Pk.ECMult(a, rev)
	res = mpc.Pk.ESub(res, val)
	return res
}

// ERandomMultShare returns a random encrypted integer and c*r
// in {1...Pk.N}, jointly generated by all parties
func (mpc *MPC) ERandomMultShare(c *paillier.Ciphertext) (*paillier.Ciphertext, *paillier.Ciphertext) {

	randomValues := make([]*paillier.Ciphertext, len(mpc.Parties))
	partialMult := make([]*paillier.Ciphertext, len(mpc.Parties))

	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cpy := &paillier.Ciphertext{C: big.NewInt(0).Set(c.C)}
			r, mult := mpc.Parties[i].GetRandomMultEnc(cpy)
			randomValues[i] = r
			partialMult[i] = mult
		}(i)
	}
	wg.Wait()

	randSum := mpc.Pk.EAdd(randomValues...)
	multSum := mpc.Pk.EAdd(partialMult...)

	return randSum, multSum
}
func (mpc *MPC) ECMultFP(ct *paillier.Ciphertext, fp *big.Float) *paillier.Ciphertext {
	e := mpc.Pk.EncodeFixedPoint(fp, mpc.FPPrecBits)
	c := mpc.Pk.ECMult(ct, e)
	return mpc.ETruncPR(c, mpc.K, mpc.FPPrecBits)
}

func (mpc *MPC) EFPMult(a, b *paillier.Ciphertext) *paillier.Ciphertext {
	res := mpc.EMult(a, b)
	res = mpc.ETruncPR(res, mpc.K, mpc.FPPrecBits)
	return res
}

// ETruncPR truncates a bitwise sharing where the last bit is
// probabilistically rounded up or down
func (mpc *MPC) ETruncPR(a *paillier.Ciphertext, k, m int) *paillier.Ciphertext {

	// get 2^k-1 + a
	b := mpc.Pk.Encrypt(big.NewInt(0).Exp(big2, big.NewInt(int64(k-1)), nil))
	b = mpc.Pk.EAdd(b, a)

	// 2^m
	big2m := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(m)), nil)
	big2mInv := big.NewInt(0).ModInverse(big2m, mpc.Pk.N)

	// get solved bits
	r := mpc.ERandom(big2m)

	exp := big.NewInt(0).Exp(big2, big.NewInt(int64(mpc.S+k-m)), nil)
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
func (mpc *MPC) ERandomAndShare(bound *big.Int) (*paillier.Ciphertext, *party.Share) {

	id := party.NewShareID()
	rand := make([]*paillier.Ciphertext, len(mpc.Parties))
	var randShare *party.Share

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

func (mpc *MPC) PaillierToShare(ct *paillier.Ciphertext) *party.Share {

	bound := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(mpc.S)), nil)
	r, rshare := mpc.ERandomAndShare(bound)
	val := mpc.RevealInt(mpc.Pk.EAdd(ct, r))
	share := mpc.CreateShares(val)
	res := mpc.Sub(share, rshare)

	return res
}

// RandomInvertibleShare returns a random encrypted integer
// in {1...Pk.T} and its inverse (mod Pk.N)
func (mpc *MPC) ERandomInvertibleShare() (*paillier.Ciphertext, *paillier.Ciphertext, error) {

	a := mpc.ERandom(mpc.Pk.N)
	b := mpc.ERandom(mpc.Pk.N)
	c := mpc.RevealInt(mpc.EMult(a, b))

	if c.Int64() == 0 {
		return nil, nil, errors.New("abort")
	}

	cInv := big.NewInt(0).ModInverse(c, mpc.Pk.N)
	aInv := mpc.Pk.ECMult(b, cInv)

	return a, aInv, nil
}

// ERandomBits returns a random bit vector from {0,1}^l
func (mpc *MPC) ERandomBits(m int) []*paillier.Ciphertext {

	vectors := make([][]*paillier.Ciphertext, len(mpc.Parties))

	var wg sync.WaitGroup

	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vec := mpc.Parties[i].GetRandomEncBitVector(m)
			vectors[i] = vec
		}(i)
	}

	wg.Wait()

	bits := make([]*paillier.Ciphertext, m)

	for i := 0; i < m; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			col := make([]*paillier.Ciphertext, len(mpc.Parties))
			for k := 0; k < len(mpc.Parties); k++ {
				col[k] = vectors[k][i]
			}

			bits[i] = mpc.EBitsXOR(col)

		}(i)
	}

	wg.Wait()

	return bits
}

// solvedBits returns a random bit string from {0,1}^m and the corresponding
func (mpc *MPC) ESolvedBits(m int) ([]*paillier.Ciphertext, *paillier.Ciphertext, error) {

	bits := mpc.ERandomBits(m)

	// convert bits to an encrypted integer
	val := mpc.EBitsToEInteger(bits)

	return bits, val, nil
}

// EFanInMULT efficiently computes [x,x^2,x^3...x^n] where n = len(elements)
// Note: can be used as a PrefixAND when elements are binary
func (mpc *MPC) EFanInMULT(elements []*paillier.Ciphertext) []*paillier.Ciphertext {

	n := len(elements)
	res := make([]*paillier.Ciphertext, n)
	res[0] = elements[0]

	if n == 1 {
		return res
	}

	shares := make([]*paillier.Ciphertext, n)
	sharesInv := make([]*paillier.Ciphertext, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			var err error
			shares[i], sharesInv[i], err = mpc.ERandomInvertibleShare()
			for err != nil {
				shares[i], sharesInv[i], err = mpc.ERandomInvertibleShare()
			}
		}(i)
	}

	wg.Wait()

	d := make([]*paillier.Ciphertext, n)
	d[0] = shares[0]
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d[i] = mpc.EMult(shares[i], sharesInv[i-1])
		}(i)

	}
	wg.Wait()

	c := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := mpc.EMult(d[i], elements[i])
			c[i] = mpc.RevealInt(q)
		}(i)
	}
	wg.Wait()

	acc := c[0]
	for i := 1; i < n; i++ {
		acc.Mul(acc, c[i])
		res[i] = mpc.Pk.ECMult(sharesInv[i], acc)
	}

	return res
}

func (mpc *MPC) RevealInt(ciphertext *paillier.Ciphertext) *big.Int {

	var val *big.Int
	var err error

	partialDecrypts := make([]*paillier.PartialDecryption, len(mpc.Parties))

	var wg sync.WaitGroup
	for i := 0; i < len(mpc.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			partialDecrypts[i] = mpc.Parties[i].PartialDecrypt(ciphertext)
		}(i)
	}
	wg.Wait()

	val, err = mpc.Party.Sk.CombinePartialDecryptions(partialDecrypts)
	if err != nil {
		panic(err)
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

//EBitsToEInteger returns the integer (in Zn) representation of an encrypted binary string
func (mpc *MPC) EBitsToEInteger(bits []*paillier.Ciphertext) *paillier.Ciphertext {

	acc := mpc.Pk.Encrypt(big.NewInt(0))
	base := big.NewInt(2)
	for i := len(bits) - 1; i >= 0; i-- {
		acc = mpc.Pk.ECMult(acc, base)
		acc = mpc.Pk.EAdd(acc, bits[i])
	}
	return acc
}

// EBitsXOR computes the XOR of all the bits
func (mpc *MPC) EBitsXOR(bits []*paillier.Ciphertext) *paillier.Ciphertext {
	return mpc.symmetricBooleanFunctionPaillier(bits, BooleanXOR)
}

func (mpc *MPC) symmetricBooleanFunctionPaillier(bits []*paillier.Ciphertext, f BooleanFunction) *paillier.Ciphertext {

	n := len(bits)

	sum := mpc.Pk.Encrypt(big.NewInt(1))
	for i := 0; i < n; i++ {
		sum = mpc.Pk.EAdd(sum, bits[i])
	}

	a := make([]*paillier.Ciphertext, n+1)
	for i := 0; i <= n; i++ {
		a[i] = sum
	}

	mul := mpc.EFanInMULT(a)

	var poly []*big.Int
	if f == BooleanOR {
		poly = funcORInterpolation(n, mpc.Pk.N)
	} else if f == BooleanXOR {
		poly = funcXORInterpolation(n, mpc.Pk.N)
	}

	res := mpc.Pk.Encrypt(poly[n])
	for i := 1; i <= n; i++ {
		c := mpc.Pk.ECMult(mul[i-1], poly[n-i])
		res = mpc.Pk.EAdd(res, c)
	}

	return res
}