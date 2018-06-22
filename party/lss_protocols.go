package node

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/sachaservan/paillier"
)

var nextShareId = 0
var shareIdMutex sync.Mutex

type Party struct {
	ID             int
	Sk             *paillier.ThresholdPrivateKey
	Pk             *paillier.PublicKey
	P              *big.Int
	BetaT          *big.Int // value of this party used for share reconstruction of degree threshold poly
	BetaN          *big.Int // value of this party used for share reconstruction of degree N poly
	Threshold      int
	Parties        []*Party
	NetworkLatency time.Duration
	shares         sync.Map
}

type Share struct {
	PartyID int
	ID      int
}

type PartialDecrypt struct {
	Csks        []*paillier.Ciphertext
	Gsk         *paillier.Ciphertext
	Degree      int
	ScaleFactor int
}

type PartialDecryptElement struct {
	Csk *paillier.Ciphertext
	Gsk *paillier.Ciphertext
}

func (party *Party) RevealShare(share *Share) (*big.Int, error) {
	return party.getShare(share.ID)
}

// Store stores a share value
func (party *Party) Store(share *Share, value *big.Int) {
	party.shares.Store(share.ID, value)
}

func (party *Party) getShare(shareID int) (*big.Int, error) {
	// Checks if item exists
	if v, ok := party.shares.Load(shareID); ok {
		value := big.NewInt(0)
		value.Set(v.(*big.Int))
		return value, nil
	}

	return nil, errors.New("share not found")
}

func (party *Party) DeleteAllShares() {
	party.shares = sync.Map{}
	nextShareId = 0
}

func (party *Party) StoreAddShare(share *Share, value *big.Int) {
	local, err := party.getShare(share.ID)
	if err != nil {
		local = big.NewInt(0)
	}

	local.Add(local, value)
	party.shares.Store(share.ID, local)
}

func (party *Party) Mult(share1, share2 *Share, newId int) (*Share, error) {
	v1, err := party.getShare(share1.ID)
	if err != nil {
		return nil, err
	}
	v2, err := party.getShare(share2.ID)
	if err != nil {
		return nil, err
	}

	z := big.NewInt(0).Mul(v1, v2)
	z.Mul(z, party.BetaN)

	shares, values, _ := party.CreateShares(z, newId)
	party.DistributeMultShares(shares, values)

	return &Share{party.ID, newId}, nil
}

func (party *Party) Sub(share1, share2 *Share, newId int) (*Share, error) {
	v1, err := party.getShare(share1.ID)
	if err != nil {
		return nil, err
	}
	v2, err := party.getShare(share2.ID)
	if err != nil {
		return nil, err
	}

	val := big.NewInt(0).Sub(v1, v2)
	val.Mod(val, party.P)

	party.shares.Store(newId, val)

	return &Share{party.ID, newId}, nil
}

func (party *Party) Add(share1, share2 *Share, newId int) (*Share, error) {
	v1, err := party.getShare(share1.ID)
	if err != nil {
		return nil, err
	}
	v2, err := party.getShare(share2.ID)
	if err != nil {
		return nil, err
	}

	val := big.NewInt(0).Add(v1, v2)
	val.Mod(val, party.P)

	party.shares.Store(newId, val)
	return &Share{party.ID, newId}, nil
}

func (party *Party) MultC(share *Share, c *big.Int, newId int) (*Share, error) {
	val, err := party.getShare(share.ID)
	if err != nil {
		return nil, err
	}

	val.Mul(val, c)
	val.Mod(val, party.P)

	party.shares.Store(newId, val)

	return &Share{party.ID, newId}, nil
}

func (party *Party) CreateRandomShare(bound *big.Int, id int) *Share {
	r := Random(bound)
	shares, values, id := party.CreateShares(r, id)
	party.DistributeRandShares(shares, values)

	return shares[party.ID]
}

func (party *Party) CopyShare(share *Share, newId int) *Share {
	val, err := party.getShare(share.ID)
	if err != nil {
		return nil
	}
	party.shares.Store(newId, val)

	return &Share{party.ID, newId}
}

func NewShareID() int {
	shareIdMutex.Lock()
	defer shareIdMutex.Unlock()

	nextShareId++
	return nextShareId
}

func (party *Party) CreateShares(s *big.Int, id int) ([]*Share, []*big.Int, int) {

	shares := make([]*Share, len(party.Parties))
	values := make([]*big.Int, len(party.Parties))

	coeffs := make([]*big.Int, party.Threshold)
	coeffs[0] = big.NewInt(0)
	coeffs[0].Set(s)

	for i := 1; i < party.Threshold; i++ {
		coeffs[i] = paillier.CryptoRandom(party.P)
	}

	var wg sync.WaitGroup
	for i := 0; i < len(party.Parties); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// use Horner's method to eval the polynomial
			x := big.NewInt(int64(i + 1))
			acc := big.NewInt(0)
			for k := party.Threshold - 1; k >= 0; k-- {
				acc.Mul(acc, x)
				acc.Add(acc, coeffs[k])
			}

			values[i] = acc.Mod(acc, party.P)
			shares[i] = &Share{PartyID: party.Parties[i].ID, ID: id}

		}(i)
	}

	wg.Wait()

	return shares, values, id
}

func (party *Party) DistributeShares(shares []*Share, values []*big.Int) {
	for i := 0; i < len(party.Parties); i++ {
		party.Parties[i].Store(shares[i], values[i])
	}
}
func (party *Party) DistributeRandShares(shares []*Share, values []*big.Int) {
	for i := 0; i < len(party.Parties); i++ {
		party.Parties[shares[i].PartyID].StoreAddShare(shares[i], values[i])
	}
}

func (party *Party) DistributeMultShares(shares []*Share, values []*big.Int) {
	for i := 0; i < len(party.Parties); i++ {
		party.Parties[i].StoreAddShare(shares[i], values[i])
	}
}

// generates a new random number < max
func Random(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}
