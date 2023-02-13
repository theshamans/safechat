package encryption

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type PrivateKey struct {
	n, d *BigInt
}

type PublicKey struct {
	n, e *BigInt
}

// encrypt encrypts a single bigint using the public key
func (p *PublicKey) encrypt(m *BigInt) *BigInt {
	return pow(m, p.e, p.n)
}

// EncryptString encrypts a byte array using the public key by encrypting each byte (i.e. each character) individually
func (p *PublicKey) EncryptString(a []byte) string {
	encryptedString := make([]byte, 0)
	for i := 0; i < len(a); i++ {
		currentPart := p.encrypt(fromInt(int64(a[i])))
		encryptedString = append(encryptedString, []byte(currentPart.String())...)
		if i != len(a)-1 {
			encryptedString = append(encryptedString, []byte(",")...)
		}
	}
	return base64.StdEncoding.EncodeToString(encryptedString)
}

// String returns a human-readable string representation of the public key
func (p *PublicKey) String() string {
	return fmt.Sprintf("<%s, %s>", p.n.String(), p.e.String())
}

// Marshal returns a byte array representation of the public key to be used for serialization
func (p *PublicKey) Marshal() []byte {
	return []byte(fmt.Sprintf("%s,%s", p.n.String(), p.e.String()))
}

// Unmarshal takes a byte array representation of the public key and sets the public key to the values in the byte array
func (p *PublicKey) Unmarshal(a []byte) error {
	l := strings.Split(string(a), ",")
	p.n = fromString(l[0])
	p.e = fromString(l[1])
	return nil
}

// decrypt decrypts a single bigint using the private key
func (p *PrivateKey) decrypt(c *BigInt) *BigInt {
	return pow(c, p.d, p.n)
}

// DecryptString decrypts a byte array using the private key by decrypting each byte (i.e. each character) individually
func (p *PrivateKey) DecryptString(a string) []byte {
	encryptedArray, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		panic(err)
	}
	splitStr := strings.Split(string(encryptedArray), ",")
	decryptedString := make([]byte, 0)
	for i := 0; i < len(splitStr); i++ {
		currentPart := p.decrypt(fromString(splitStr[i]))
		decryptedString = append(decryptedString, byte(currentPart.toInt()))
	}
	return decryptedString
}

// String returns a human-readable string representation of the private key
func (p *PrivateKey) String() string {
	return fmt.Sprintf("<%s, %s>", p.n.String(), p.d.String())
}

// Marshal returns a byte array representation of the private key to be used for serialization
func (p *PrivateKey) Marshal() []byte {
	return []byte(fmt.Sprintf("%s,%s", p.n.String(), p.d.String()))
}

// Unmarshal takes a byte array representation of the private key and sets the private key to the values in the byte array
func (p *PrivateKey) Unmarshal(a []byte) error {
	l := strings.Split(string(a), ",")
	p.n = fromString(l[0])
	p.d = fromString(l[1])
	return nil
}
