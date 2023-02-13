package encryption

import (
	"strconv"
)

const base = 10

// BigInt simulates basic arithmetic operations on unsigned big integers.
// It stores the digits in base 10 in little endian and the last element
// of the digits slice is never 0 (i.e. it never has leading zeros).
type BigInt struct {
	digits []int8
}

// zero returns a BigInt with value 0. The digits slice is empty because of the "no leading zeros" rule.
// However, when returning the string representation of a BigInt, we need to return "0" instead of "".
func zero() *BigInt {
	return &BigInt{
		digits: []int8{},
	}
}

func fromString(n string) *BigInt {
	res := &BigInt{
		digits: make([]int8, len(n)),
	}
	for i, c := range n {
		res.digits[len(n)-i-1] = int8(c - '0')
	}
	res.normalize()
	return res
}

func fromInt(n int64) *BigInt {
	return fromString(strconv.FormatInt(n, base))
}

func (a *BigInt) toInt() int64 {
	x := int64(0)
	for i := len(a.digits) - 1; i >= 0; i-- {
		x *= base
		x += int64(a.digits[i])
	}
	return x
}

func (a *BigInt) String() string {
	result := ""
	for i := len(a.digits) - 1; i >= 0; i-- {
		result += strconv.Itoa(int(a.digits[i]))
	}
	if result == "" {
		result = "0"
	}
	return result
}

func (a *BigInt) isEven() bool {
	return a.digits[0]%2 == 0
}

// normalize removes leading zeros from the digits slice.
func (a *BigInt) normalize() {
	for len(a.digits) > 0 && a.digits[len(a.digits)-1] == 0 {
		a.digits = a.digits[:len(a.digits)-1]
	}
}

// copy returns a copy of the BigInt to avoid modifying the original.
func (a *BigInt) copy() *BigInt {
	res := &BigInt{
		digits: make([]int8, len(a.digits)),
	}
	copy(res.digits, a.digits)
	return res
}

// prev returns the BigInt that is one less than the original.
func (a *BigInt) prev() (result *BigInt) {
	result = a.copy()

	carry := int8(1)
	for i := 0; i < len(result.digits); i++ {
		result.digits[i] = (a.digits[i] - carry + base) % base
		if a.digits[i]-carry < 0 {
			carry = 1
		} else {
			carry = 0
		}
	}
	if carry == 1 {
		panic("underflow")
	}

	result.normalize()

	return
}

// next returns the BigInt that is one more than the original.
func (a *BigInt) next() (result *BigInt) {
	result = a.copy()

	carry := int8(1)
	for i := 0; i < len(result.digits); i++ {
		result.digits[i] = (a.digits[i] + carry) % base
		carry = (a.digits[i] + carry) / base
	}
	if carry == 1 {
		result.digits = append(result.digits, 1)
	}

	result.normalize()

	return
}

// half returns the BigInt that is half of the original, rounded down.
func (a *BigInt) half() *BigInt {
	result := &BigInt{
		digits: make([]int8, len(a.digits)),
	}

	carry := int8(0)
	for i := len(a.digits) - 1; i >= 0; i-- {
		result.digits[i] = (a.digits[i] + carry*base) / 2
		carry = (a.digits[i] + carry*base) % 2
	}

	result.normalize()

	return result
}

// compare returns 1 if a > b, -1 if a < b, and 0 if a == b.
func (a *BigInt) compare(b *BigInt) int {
	if len(a.digits) > len(b.digits) {
		return 1
	}
	if len(a.digits) < len(b.digits) {
		return -1
	}
	for i := len(a.digits) - 1; i >= 0; i-- {
		if a.digits[i] > b.digits[i] {
			return 1
		}
		if a.digits[i] < b.digits[i] {
			return -1
		}
	}
	return 0
}

// add returns the BigInt that is the sum of the two BigInts.
func (a *BigInt) add(b *BigInt) (result *BigInt) {
	result = &BigInt{
		digits: make([]int8, 0),
	}

	carry := int8(0)
	for i := 0; i < len(a.digits) && i < len(b.digits); i++ {
		result.digits = append(result.digits, (a.digits[i]+b.digits[i]+carry)%base)
		carry = (a.digits[i] + b.digits[i] + carry) / base
	}
	for i := len(a.digits); i < len(b.digits); i++ {
		result.digits = append(result.digits, (b.digits[i]+carry)%base)
		carry = (b.digits[i] + carry) / base
	}
	for i := len(b.digits); i < len(a.digits); i++ {
		result.digits = append(result.digits, (a.digits[i]+carry)%base)
		carry = (a.digits[i] + carry) / base
	}
	if carry != 0 {
		result.digits = append(result.digits, carry)
	}

	return
}

// sub returns the BigInt that is the difference of the two BigInts.
func (a *BigInt) sub(b *BigInt) (result *BigInt) {
	result = &BigInt{
		digits: make([]int8, 0),
	}

	carry := int8(0)
	for i := 0; i < len(b.digits); i++ {
		result.digits = append(result.digits, (a.digits[i]-b.digits[i]-carry+base)%base)
		if a.digits[i]-b.digits[i]-carry < 0 {
			carry = 1
		} else {
			carry = 0
		}
	}
	for i := len(b.digits); i < len(a.digits); i++ {
		result.digits = append(result.digits, (a.digits[i]-carry+base)%base)
		if a.digits[i]-carry < 0 {
			carry = 1
		} else {
			carry = 0
		}
	}
	if carry == 1 {
		panic("underflow")
	}

	result.normalize()

	return
}

// mul returns the BigInt that is the product of the two BigInts.
func (a *BigInt) mul(b *BigInt) (result *BigInt) {
	if len(a.digits) == 0 || len(b.digits) == 0 {
		return zero()
	}
	result = &BigInt{
		digits: make([]int8, len(a.digits)+len(b.digits)-1),
	}

	for i := 0; i < len(a.digits); i++ {
		carry := int8(0)
		for j := 0; j < len(b.digits); j++ {
			result.digits[i+j] += a.digits[i]*b.digits[j] + carry
			carry = result.digits[i+j] / base
			result.digits[i+j] %= base
		}
		if carry != 0 {
			i2 := i + len(b.digits)
			if i2 >= len(result.digits) {
				result.digits = append(result.digits, 0)
			}
			result.digits[i2] += carry
			for result.digits[i2] >= base {
				result.digits[i2] += carry
				carry = result.digits[i2] / base
				result.digits[i2] %= base
				i2++
			}
		}
	}

	return
}

// div returns the quotient and remainder of the division between the two BigInts.
func (a *BigInt) div(b *BigInt) (q, r *BigInt) {
	if a.compare(b) < 0 {
		return zero(), a
	}

	l, r := zero(), a
	ans := l.copy()
	for l.compare(r) <= 0 {
		temp := l.add(r)
		m := temp.half()
		if m.mul(b).compare(a) <= 0 {
			ans = m.copy()
			l = m.next()
		} else {
			r = m.prev()
		}
	}

	return ans, a.sub(ans.mul(b))
}
