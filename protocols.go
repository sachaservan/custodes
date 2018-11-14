package hypocert

// Constants
import (
	"crypto/rand"
	"errors"
	"hypocert/party"
	"math"
	"math/big"

	"time"

	"github.com/sachaservan/paillier"
)

var big2InvN *big.Int
var big2InvP *big.Int
var big2 *big.Int
var big1 *big.Int
var big0 *big.Int

type MPC struct {
	Party      *party.Party   // party initiating the requests
	Parties    []*party.Party // all other parties in the system
	Threshold  int
	Pk         *paillier.PublicKey
	K          int      // message space 2^K < N
	S          int      // security parameter for statistically secure protocols
	P          *big.Int // secret share prime modulus
	FPPrecBits int      // fixed point precision bits
}

type MPCKeyGenParams struct {
	NumParties      int
	Threshold       int // decryption threshold
	KeyBits         int // key size..at least 512 for Paillier
	SecurityBits    int // at least 40 bits
	MessageBits     int // message space bits
	FPPrecisionBits int
	NetworkLatency  time.Duration // for network latency testing
}

func NewMPCKeyGen(params *MPCKeyGenParams) (*MPC, error) {

	nu := int(math.Log2(float64(params.NumParties)))
	if int64(params.MessageBits+params.SecurityBits+params.FPPrecisionBits+nu+1) >= int64(2*params.KeyBits) {
		return nil, errors.New("modulus not big enough for given parameters")
	}

	//shareModulusBits := 4*params.MessageBits + params.FPPrecisionBits + params.SecurityBits + nu + 1
	secretSharePrime, err := rand.Prime(rand.Reader, params.KeyBits)

	tkh, err := paillier.GetThresholdKeyGenerator(params.KeyBits, params.NumParties, params.Threshold, rand.Reader)
	if err != nil {
		return nil, err
	}

	tpks, err := tkh.Generate()
	pk := &tpks[0].PublicKey

	if err != nil {
		return nil, err
	}

	// generate shamir polynomial
	parties := make([]*party.Party, params.NumParties)
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

		parties[i] = &party.Party{
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

	mpc := &MPC{parties[0], parties, params.Threshold, pk, params.MessageBits, params.SecurityBits, secretSharePrime, params.FPPrecisionBits}

	// init constants
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big2InvN = big.NewInt(0).ModInverse(big2, pk.N)
	big2InvP = big.NewInt(0).ModInverse(big2, secretSharePrime)

	return mpc, nil
}
