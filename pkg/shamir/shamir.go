package shamir

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type SecretSplitter interface {
	Generate(totalShards int) (map[int]*big.Int, *big.Int, error)
}
type SecretIntegrater interface {
	Integrate() *big.Int
}

type ShamirSharer struct {
	Threshold int
	Bits      int
	Secret    *big.Int
	Prime     *big.Int
	coeffs    []*big.Int
}
type Integrater struct {
	Shards map[int]*big.Int
	Prime  *big.Int
}

func (s *ShamirSharer) init() error {
	s.coeffs = []*big.Int{s.Secret}
	var err error
	s.Prime, err = rand.Prime(rand.Reader, s.Bits)
	if err != nil {
		return fmt.Errorf("failed generating master prime: %w", err)
	}
	for i := 1; i < s.Threshold; i++ {
		p, err := rand.Int(rand.Reader, s.Prime)
		if err != nil {
			return fmt.Errorf("failed generating prime: %w", err)
		}
		s.coeffs = append(s.coeffs, p)
	}
	return nil
}

func (s *ShamirSharer) eval(x int64) *big.Int {
	result := big.NewInt(0)
	xBig := big.NewInt(x)
	for i, c := range s.coeffs {
		xPower := new(big.Int).Exp(xBig, big.NewInt(int64(i)), s.Prime)
		temp := new(big.Int).Mul(c, xPower)
		result.Add(result, temp)
		result.Mod(result, s.Prime)
	}
	return result
}

func (s *ShamirSharer) Generate(totalShards int) (map[int]*big.Int, *big.Int, error) {
	if len(s.coeffs) == 0 {
		if err := s.init(); err != nil {
			return nil, nil, err
		}
	}

	var shards = make(map[int]*big.Int)
	for x := 1; x <= totalShards; x++ {
		shards[x] = s.eval(int64(x))
	}
	return shards, s.Prime, nil
}

func (i *Integrater) calcWeights() map[int]*big.Int {
	weights := make(map[int]*big.Int)

	for x := range i.Shards {
		num := big.NewInt(1)
		den := big.NewInt(1)

		for y := range i.Shards {
			if x != y {
				yBig := big.NewInt(int64(-y))
				num.Mul(num, yBig)
				num.Mod(num, i.Prime)

				diff := big.NewInt(int64(x - y))
				den.Mul(den, diff)
				den.Mod(den, i.Prime)
			}
		}

		modInv := new(big.Int).ModInverse(den, i.Prime)
		weight := new(big.Int).Mul(num, modInv)
		weight.Mod(weight, i.Prime)

		weights[x] = weight
	}
	return weights
}

func (i *Integrater) Integrate() *big.Int {
	weights := i.calcWeights()
	result := big.NewInt(0)
	for x, weight := range weights {
		temp := new(big.Int).Mul(i.Shards[x], weight)
		temp.Mod(temp, i.Prime)
		result.Add(result, temp)
		result.Mod(result, i.Prime)
	}
	return result
}
