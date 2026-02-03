// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package pallas

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/field"
)

var (
	// Pallas curve parameter b = 5
	curveB = big.NewInt(5)

	// Generator point coordinates
	// Gx = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000
	// Gy = 0x02
	generatorX, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc094cf91b992d30ed00000000", 16)
	generatorY    = big.NewInt(2)
)

// Element implements the Element interface for the Pallas group element.
// Points are stored in Jacobian coordinates (X, Y, Z) where the affine point is (X/Z², Y/Z³).
type Element struct {
	field *field.Field
	x, y, z big.Int
}

func newElement(f *field.Field) *Element {
	e := &Element{field: f}
	// Initialize as identity (point at infinity)
	e.x.SetInt64(0)
	e.y.SetInt64(1)
	e.z.SetInt64(0)
	return e
}

func assertElement(element internal.Element, f *field.Field) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	if !f.IsEqual(ec.field) {
		panic(internal.ErrWrongField)
	}

	return ec
}

// Group returns the group's Identifier.
func (e *Element) Group() byte {
	return Identifier
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() internal.Element {
	e.x.Set(generatorX)
	e.y.Set(generatorY)
	e.z.SetInt64(1)
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	e.x.SetInt64(0)
	e.y.SetInt64(1)
	e.z.SetInt64(0)
	return e
}

// isIdentity returns whether this is the point at infinity.
func (e *Element) isIdentityInternal() bool {
	return e.z.Sign() == 0
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
// Uses complete addition formula for short Weierstrass curves with a=0.
func (e *Element) Add(element internal.Element) internal.Element {
	q := assertElement(element, e.field)
	
	if e.isIdentityInternal() {
		e.x.Set(&q.x)
		e.y.Set(&q.y)
		e.z.Set(&q.z)
		return e
	}
	
	if q.isIdentityInternal() {
		return e
	}

	// Using Jacobian coordinates addition
	// http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	p := e.field.Order()

	z1z1 := new(big.Int).Mul(&e.z, &e.z)
	z1z1.Mod(z1z1, p)

	z2z2 := new(big.Int).Mul(&q.z, &q.z)
	z2z2.Mod(z2z2, p)

	u1 := new(big.Int).Mul(&e.x, z2z2)
	u1.Mod(u1, p)

	u2 := new(big.Int).Mul(&q.x, z1z1)
	u2.Mod(u2, p)

	s1 := new(big.Int).Mul(&e.y, &q.z)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, p)

	s2 := new(big.Int).Mul(&q.y, &e.z)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, p)

	h := new(big.Int).Sub(u2, u1)
	h.Mod(h, p)

	// Check if points are the same (h == 0)
	if h.Sign() == 0 {
		if new(big.Int).Sub(s1, s2).Mod(new(big.Int).Sub(s1, s2), p).Sign() == 0 {
			// Points are equal, use doubling
			return e.Double()
		}
		// Points are inverses, return identity
		return e.Identity()
	}

	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	i.Mod(i, p)

	j := new(big.Int).Mul(h, i)
	j.Mod(j, p)

	r := new(big.Int).Sub(s2, s1)
	r.Mod(r, p)
	r.Lsh(r, 1)
	r.Mod(r, p)

	v := new(big.Int).Mul(u1, i)
	v.Mod(v, p)

	// X3 = r² - J - 2*V
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, p)

	// Y3 = r*(V - X3) - 2*S1*J
	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, r)
	tmp := new(big.Int).Mul(s1, j)
	tmp.Lsh(tmp, 1)
	y3.Sub(y3, tmp)
	y3.Mod(y3, p)

	// Z3 = ((Z1 + Z2)² - Z1Z1 - Z2Z2) * H
	z3 := new(big.Int).Add(&e.z, &q.z)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, p)

	e.x.Set(x3)
	e.y.Set(y3)
	e.z.Set(z3)

	return e
}

// Double sets the receiver to its double, and returns it.
// Uses doubling formula for short Weierstrass curves with a=0.
func (e *Element) Double() internal.Element {
	if e.isIdentityInternal() {
		return e
	}

	// http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	p := e.field.Order()

	a := new(big.Int).Mul(&e.x, &e.x)
	a.Mod(a, p)

	b := new(big.Int).Mul(&e.y, &e.y)
	b.Mod(b, p)

	c := new(big.Int).Mul(b, b)
	c.Mod(c, p)

	d := new(big.Int).Add(&e.x, b)
	d.Mul(d, d)
	d.Sub(d, a)
	d.Sub(d, c)
	d.Lsh(d, 1)
	d.Mod(d, p)

	ee := new(big.Int).Lsh(a, 1)
	ee.Add(ee, a)
	ee.Mod(ee, p)

	f := new(big.Int).Mul(ee, ee)
	f.Mod(f, p)

	// X3 = F - 2*D
	x3 := new(big.Int).Sub(f, d)
	x3.Sub(x3, d)
	x3.Mod(x3, p)

	// Y3 = E*(D - X3) - 8*C
	y3 := new(big.Int).Sub(d, x3)
	y3.Mul(y3, ee)
	tmp := new(big.Int).Lsh(c, 3)
	y3.Sub(y3, tmp)
	y3.Mod(y3, p)

	// Z3 = 2*Y1*Z1
	z3 := new(big.Int).Mul(&e.y, &e.z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, p)

	e.x.Set(x3)
	e.y.Set(y3)
	e.z.Set(z3)

	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() internal.Element {
	if !e.isIdentityInternal() {
		e.y.Neg(&e.y)
		e.y.Mod(&e.y, e.field.Order())
	}
	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	q := assertElement(element, e.field)
	neg := &Element{field: e.field}
	neg.x.Set(&q.x)
	neg.y.Set(&q.y)
	neg.z.Set(&q.z)
	neg.Negate()
	return e.Add(neg)
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
// Uses double-and-add algorithm.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	if scalar == nil || scalar.IsZero() {
		return e.Identity()
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	// Double-and-add
	result := newElement(e.field)
	result.Identity()

	base := &Element{field: e.field}
	base.x.Set(&e.x)
	base.y.Set(&e.y)
	base.z.Set(&e.z)

	scalarBytes := sc.scalar.Bytes()
	for i := len(scalarBytes) - 1; i >= 0; i-- {
		b := scalarBytes[i]
		for j := 0; j < 8; j++ {
			if b&1 == 1 {
				result.Add(base)
			}
			base.Double()
			b >>= 1
		}
	}

	e.x.Set(&result.x)
	e.y.Set(&result.y)
	e.z.Set(&result.z)

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element internal.Element) int {
	q := assertElement(element, e.field)

	// Convert both to affine and compare
	return subtle.ConstantTimeCompare(e.Encode(), q.Encode())
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.isIdentityInternal()
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.Identity()
	}

	q := assertElement(element, e.field)
	e.x.Set(&q.x)
	e.y.Set(&q.y)
	e.z.Set(&q.z)

	return e
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() internal.Element {
	cpy := &Element{field: e.field}
	cpy.x.Set(&e.x)
	cpy.y.Set(&e.y)
	cpy.z.Set(&e.z)
	return cpy
}

// toAffine converts from Jacobian to affine coordinates.
func (e *Element) toAffine() (x, y *big.Int) {
	if e.isIdentityInternal() {
		return big.NewInt(0), big.NewInt(0)
	}

	p := e.field.Order()

	// z^-1
	zinv := new(big.Int).ModInverse(&e.z, p)
	
	// z^-2
	zinv2 := new(big.Int).Mul(zinv, zinv)
	zinv2.Mod(zinv2, p)

	// z^-3
	zinv3 := new(big.Int).Mul(zinv2, zinv)
	zinv3.Mod(zinv3, p)

	// x = X * z^-2
	x = new(big.Int).Mul(&e.x, zinv2)
	x.Mod(x, p)

	// y = Y * z^-3
	y = new(big.Int).Mul(&e.y, zinv3)
	y.Mod(y, p)

	return x, y
}

// Encode returns the compressed byte encoding of the element.
// Format: 0x00 for identity, 0x02/0x03 + x-coordinate (33 bytes total)
func (e *Element) Encode() []byte {
	if e.isIdentityInternal() {
		return make([]byte, elementLength)
	}

	x, y := e.toAffine()

	enc := make([]byte, elementLength)
	
	// Determine sign of y
	if y.Bit(0) == 0 {
		enc[0] = 0x02
	} else {
		enc[0] = 0x03
	}

	xBytes := x.Bytes()
	copy(enc[elementLength-len(xBytes):], xBytes)

	return enc
}

// XCoordinate returns the encoded x coordinate of the element.
func (e *Element) XCoordinate() []byte {
	if e.isIdentityInternal() {
		return make([]byte, scalarLength)
	}

	x, _ := e.toAffine()
	out := make([]byte, scalarLength)
	return x.FillBytes(out)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	if len(data) != elementLength {
		return internal.ErrParamInvalidPointEncoding
	}

	// Check for identity
	isZero := true
	for _, b := range data {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		e.Identity()
		return nil
	}

	// Check header
	if data[0] != 0x02 && data[0] != 0x03 {
		return internal.ErrParamInvalidPointEncoding
	}

	p := e.field.Order()

	// Extract x coordinate
	x := new(big.Int).SetBytes(data[1:])
	
	if x.Cmp(p) >= 0 {
		return internal.ErrParamInvalidPointEncoding
	}

	// Compute y² = x³ + b (for Pallas, a=0, b=5)
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	y2.Add(y2, curveB)
	y2.Mod(y2, p)

	// Compute y = sqrt(y²) using Tonelli-Shanks
	y := e.sqrt(y2, p)
	if y == nil {
		return internal.ErrParamInvalidPointEncoding
	}

	// Select the correct root based on parity
	if (data[0] == 0x02) != (y.Bit(0) == 0) {
		y.Sub(p, y)
	}

	// Set the point in Jacobian coordinates (affine: Z=1)
	e.x.Set(x)
	e.y.Set(y)
	e.z.SetInt64(1)

	return nil
}

// sqrt computes the modular square root using the Tonelli-Shanks algorithm.
// Returns nil if n is not a quadratic residue mod p.
func (e *Element) sqrt(n, p *big.Int) *big.Int {
	// For Pallas, p ≡ 1 (mod 4), so we can use the simpler formula
	// when p ≡ 3 (mod 4): sqrt = n^((p+1)/4)
	// But Pallas p ≡ 1 (mod 4), so we need Tonelli-Shanks

	// Check if n is a quadratic residue
	legendre := new(big.Int).Exp(n, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p)
	if legendre.Cmp(big.NewInt(1)) != 0 {
		return nil // Not a quadratic residue
	}

	// Factor out powers of 2 from p - 1
	// p - 1 = Q * 2^S
	q := new(big.Int).Sub(p, big.NewInt(1))
	s := uint(0)
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}

	// Find a non-residue z
	z := big.NewInt(2)
	for new(big.Int).Exp(z, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p).Cmp(new(big.Int).Sub(p, big.NewInt(1))) != 0 {
		z.Add(z, big.NewInt(1))
	}

	m := s
	c := new(big.Int).Exp(z, q, p)
	t := new(big.Int).Exp(n, q, p)
	r := new(big.Int).Exp(n, new(big.Int).Add(new(big.Int).Rsh(q, 0), big.NewInt(1)).Rsh(new(big.Int).Add(q, big.NewInt(1)), 1), p)

	for {
		if t.Cmp(big.NewInt(1)) == 0 {
			return r
		}

		// Find the least i such that t^(2^i) = 1
		i := uint(1)
		tmp := new(big.Int).Mul(t, t)
		tmp.Mod(tmp, p)
		for tmp.Cmp(big.NewInt(1)) != 0 {
			tmp.Mul(tmp, tmp)
			tmp.Mod(tmp, p)
			i++
		}

		// b = c^(2^(m-i-1))
		b := new(big.Int).Set(c)
		for j := uint(0); j < m-i-1; j++ {
			b.Mul(b, b)
			b.Mod(b, p)
		}

		m = i
		c.Mul(b, b)
		c.Mod(c, p)
		t.Mul(t, c)
		t.Mod(t, p)
		r.Mul(r, b)
		r.Mod(r, p)
	}
}

// Hex returns the fixed-sized hexadecimal encoding of e.
func (e *Element) Hex() string {
	return hex.EncodeToString(e.Encode())
}

// DecodeHex sets e to the decoding of the hex encoded element.
func (e *Element) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return e.Decode(b)
}
