package encryption

import (
	"math/rand"
	"time"
)

// generatePrimes generates two different random primes in the range [lower, upper)
func generatePrimes(lower, upper uint64) (*BigInt, *BigInt) {
	p := nextPrime(fromInt(int64(rand.Uint64()%(upper-lower) + lower)))
	q := nextPrime(fromInt(int64(rand.Uint64()%(upper-lower) + lower)))
	if p == q {
		q = nextPrime(q)
	}
	return p, q
}

// generateKeys generates a private and public key from two primes
func generateKeys(p, q *BigInt) (PrivateKey, PublicKey) {
	n := p.mul(q)
	e := fromInt(65537)
	for {

		if gcd(p.prev(), e).compare(fromInt(1)) == 0 && gcd(q.prev(), e).compare(fromInt(1)) == 0 {
			break
		}
		e = e.next().next()
	}
	d := modularInverse(e, p.prev().mul(q.prev()))
	return PrivateKey{n, d}, PublicKey{n, e}
}

// GenerateKeyPair generates a public and private key pair
func GenerateKeyPair() (PublicKey, PrivateKey) {
	rand.Seed(time.Now().Unix())
	bound := uint64(1 << 20)
	p, q := generatePrimes(bound, bound*2)
	priv, pub := generateKeys(p, q)
	return pub, priv
}
