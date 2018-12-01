package custodes

import (
	"math/big"
	"sync"
)

// store lagrange polynomials to avoid recalculations
var funcORCoefficientCache sync.Map
var funcXORCoefficientCache sync.Map

func neg(a *big.Int, modulus *big.Int) *big.Int {
	return big.NewInt(0).Sub(modulus, a)
}

func (mpc *MPC) computeBinaryFunctionCache(n int) {

	for i := 0; i < n; i++ {
		funcORInterpolation(i, mpc.P)
	}
}

// compute the lagrange interpolation of the function such that
// f(1) = 0, f(1) = f(2) = f(3).... = 1
func funcORInterpolation(n int, modulus *big.Int) []*big.Int {

	if value, found := funcORCoefficientCache.Load(n); found {
		if v, ok := value.([]*big.Int); ok {
			out := make([]*big.Int, n+1)
			for i := 0; i <= n; i++ {
				out[i] = big.NewInt(0).Set(v[i])
			}
			return out
		}
	}

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
				xj := big.NewInt(int64(-j - 1))

				if numerator == nil {
					numerator = []*big.Int{big.NewInt(1), xj}
				} else {
					numerator = polyMult(numerator, []*big.Int{big.NewInt(1), xj})
				}

				denom.Mul(denom, big.NewInt(0).Add(xi, xj))
			}
		}

		if big.NewInt(0).Abs(denom).Cmp(big.NewInt(1)) != 0 {
			denom = denom.ModInverse(denom, modulus)
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
			poly[i] = poly[i].Mod(poly[i], modulus)
			poly[i] = neg(poly[i], modulus)
		} else {
			poly[i] = poly[i].Mod(poly[i], modulus)
		}
	}

	funcORCoefficientCache.Store(n, poly)

	return poly
}

// compute the lagrange interpolation of the function such that
// f(1) = 1, f(2) = 0,  f(3) = 1,  f(4) = 0 ...
func funcXORInterpolation(n int, modulus *big.Int) []*big.Int {

	if value, found := funcXORCoefficientCache.Load(n); found {
		if v, ok := value.([]*big.Int); ok {
			out := make([]*big.Int, n+1)
			for i := 0; i <= n; i++ {
				out[i] = big.NewInt(0).Set(v[i])
			}
			return out
		}
	}

	var numerator []*big.Int
	var poly []*big.Int

	denom := big.NewInt(1)
	poly = make([]*big.Int, n)

	for k := 0; k < n; k++ {
		poly[k] = big.NewInt(0)
	}

	for i := 0; i <= n; i++ {
		if i%2 == 0 {
			continue
		}

		for j := 0; j <= n; j++ {

			if i != j {

				xi := big.NewInt(int64(i + 1))
				xj := big.NewInt(int64(-j - 1))

				if numerator == nil {
					numerator = []*big.Int{big.NewInt(1), xj}
				} else {
					numerator = polyMult(numerator, []*big.Int{big.NewInt(1), xj})
				}

				denom.Mul(denom, big.NewInt(0).Add(xi, xj))
			}
		}

		if big.NewInt(0).Abs(denom).Cmp(big.NewInt(1)) != 0 {
			denom = denom.ModInverse(denom, modulus)
		}

		for k := 0; k < len(numerator); k++ {
			numerator[k].Mul(numerator[k], denom)
		}

		poly = polyAdd(poly, numerator)

		// reset
		denom = big.NewInt(1)
		numerator = nil

	}

	for i := 0; i < len(poly); i++ {
		if poly[i].Cmp(big.NewInt(0)) < 0 {
			poly[i] = poly[i].Neg(poly[i])
			poly[i] = poly[i].Mod(poly[i], modulus)
			poly[i] = neg(poly[i], modulus)
		} else {
			poly[i] = poly[i].Mod(poly[i], modulus)
		}
	}

	funcXORCoefficientCache.Store(n, poly)

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
