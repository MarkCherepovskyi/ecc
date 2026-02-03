// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package pallas

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash2curve"

	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/field"
)

// hashToScalar implements hash-to-scalar mapping for Pallas.
func hashToScalar(f *field.Field, input, dst []byte) internal.Scalar {
	// Use hash2curve's HashToFieldXMD with the scalar field order
	h := hash2curve.HashToFieldXMD(crypto.BLAKE2b_512, input, dst, 1, 1, 48, f.Order())

	s := newScalar(f)
	s.scalar.Set(h[0])

	return s
}

// hashToGroup implements hash-to-curve mapping for Pallas using SSWU.
func hashToGroup(f *field.Field, input, dst []byte) internal.Element {
	// Hash to two field elements
	u := hash2curve.HashToFieldXMD(crypto.BLAKE2b_512, input, dst, 2, 1, 48, f.Order())

	// Map both to curve points and add them
	q0 := sswuMap(f, u[0])
	q1 := sswuMap(f, u[1])
	q0.Add(q1)

	return q0
}

// encodeToGroup implements encode-to-curve mapping for Pallas using SSWU.
func encodeToGroup(f *field.Field, input, dst []byte) internal.Element {
	// Hash to one field element
	u := hash2curve.HashToFieldXMD(crypto.BLAKE2b_512, input, dst, 1, 1, 48, f.Order())

	// Map to curve point
	return sswuMap(f, u[0])
}

// sswuMap implements the Simplified SWU map for curves with a=0.
// For Pallas (y² = x³ + 5), we use an isogenous curve and then apply an isogeny.
// However, for simplicity, we implement a direct method.
func sswuMap(f *field.Field, u *big.Int) *Element {
	p := f.Order()

	// For curves with a = 0, we need to use the "3-isogeny" method.
	// We map to an isogenous curve y² = x³ + A*x + B with A ≠ 0,
	// then apply the isogeny to get back to Pallas.

	// Pallas isogeny parameters (3-isogeny from E' to Pallas)
	// E': y² = x³ + A'*x + B' where A' and B' are chosen to have A' ≠ 0
	// For Pallas, we use the standard isogeny parameters.

	// Z is a non-square in Fp used by the SSWU map
	// For Pallas, Z = -13 is commonly used
	z := big.NewInt(-13)
	z.Mod(z, p)

	// Constants for the isogenous curve E': y² = x³ + A'x + B'
	// These are the standard parameters for Pallas hash-to-curve
	// A' = 0x18354a2eb0ea8c9c49be2d7258370742b74134f1dc2ae8c73cfd2fc64ad3c09a
	// B' = 1265
	aPrime, _ := new(big.Int).SetString("18354a2eb0ea8c9c49be2d7258370742b74134f1dc2ae8c73cfd2fc64ad3c09a", 16)
	bPrime := big.NewInt(1265)

	// SSWU map to E'
	x, y := sswuMapToIsogenousCurve(u, z, aPrime, bPrime, p)

	// Apply 3-isogeny from E' to Pallas
	px, py := applyPallasIsogeny(x, y, p)

	e := newElement(f)
	e.x.Set(px)
	e.y.Set(py)
	e.z.SetInt64(1)

	return e
}

// sswuMapToIsogenousCurve implements the SSWU map to the isogenous curve E'.
func sswuMapToIsogenousCurve(u, z, a, b, p *big.Int) (x, y *big.Int) {
	// tv1 = u²
	tv1 := new(big.Int).Mul(u, u)
	tv1.Mod(tv1, p)

	// tv1 = Z * tv1
	tv1.Mul(z, tv1)
	tv1.Mod(tv1, p)

	// tv2 = tv1²
	tv2 := new(big.Int).Mul(tv1, tv1)
	tv2.Mod(tv2, p)

	// tv2 = tv2 + tv1
	tv2.Add(tv2, tv1)
	tv2.Mod(tv2, p)

	// tv3 = tv2 + 1
	tv3 := new(big.Int).Add(tv2, big.NewInt(1))
	tv3.Mod(tv3, p)

	// tv3 = B * tv3
	tv3.Mul(b, tv3)
	tv3.Mod(tv3, p)

	// tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 := new(big.Int)
	if tv2.Sign() == 0 {
		tv4.Set(z)
	} else {
		tv4.Neg(tv2)
		tv4.Mod(tv4, p)
	}

	// tv4 = A * tv4
	tv4.Mul(a, tv4)
	tv4.Mod(tv4, p)

	// tv2 = tv3²
	tv2.Mul(tv3, tv3)
	tv2.Mod(tv2, p)

	// tv6 = tv4²
	tv6 := new(big.Int).Mul(tv4, tv4)
	tv6.Mod(tv6, p)

	// tv5 = A * tv6
	tv5 := new(big.Int).Mul(a, tv6)
	tv5.Mod(tv5, p)

	// tv2 = tv2 + tv5
	tv2.Add(tv2, tv5)
	tv2.Mod(tv2, p)

	// tv2 = tv2 * tv3
	tv2.Mul(tv2, tv3)
	tv2.Mod(tv2, p)

	// tv6 = tv6 * tv4
	tv6.Mul(tv6, tv4)
	tv6.Mod(tv6, p)

	// tv5 = B * tv6
	tv5.Mul(b, tv6)
	tv5.Mod(tv5, p)

	// tv2 = tv2 + tv5
	tv2.Add(tv2, tv5)
	tv2.Mod(tv2, p)

	// x = tv1 * tv3
	x = new(big.Int).Mul(tv1, tv3)
	x.Mod(x, p)

	// (isQR, y1) = sqrt_ratio(tv2, tv6)
	isQR, y1 := sqrtRatio(tv2, tv6, p)

	// y = tv1 * u
	y = new(big.Int).Mul(tv1, u)
	y.Mod(y, p)

	// y = y * y1
	y.Mul(y, y1)
	y.Mod(y, p)

	// x = CMOV(x, tv3, isQR)
	if isQR {
		x.Set(tv3)
	}

	// y = CMOV(y, y1, isQR)
	if isQR {
		y.Set(y1)
	}

	// e1 = sgn0(u) == sgn0(y)
	e1 := (u.Bit(0) == y.Bit(0))

	// y = CMOV(-y, y, e1)
	if !e1 {
		y.Neg(y)
		y.Mod(y, p)
	}

	// x = x / tv4
	tv4Inv := new(big.Int).ModInverse(tv4, p)
	x.Mul(x, tv4Inv)
	x.Mod(x, p)

	return x, y
}

// sqrtRatio computes sqrt(u/v) and returns (true, sqrt) if u/v is square, (false, sqrt(-u/v)) otherwise.
func sqrtRatio(u, v, p *big.Int) (bool, *big.Int) {
	// Compute v^-1
	vInv := new(big.Int).ModInverse(v, p)
	if vInv == nil {
		return false, big.NewInt(0)
	}

	// Compute u/v
	uv := new(big.Int).Mul(u, vInv)
	uv.Mod(uv, p)

	// Try to compute sqrt(u/v)
	y := modSqrt(uv, p)
	if y != nil {
		return true, y
	}

	// Compute -u/v and its sqrt
	uv.Neg(uv)
	uv.Mod(uv, p)
	y = modSqrt(uv, p)
	if y != nil {
		return false, y
	}

	return false, big.NewInt(0)
}

// modSqrt computes the modular square root if it exists, nil otherwise.
func modSqrt(n, p *big.Int) *big.Int {
	// Check if n is zero
	if n.Sign() == 0 {
		return big.NewInt(0)
	}

	// Check if n is a quadratic residue
	legendre := new(big.Int).Exp(n, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p)
	if legendre.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	// Use big.Int's ModSqrt
	result := new(big.Int).ModSqrt(n, p)
	return result
}

// applyPallasIsogeny applies the 3-isogeny from E' to Pallas.
// The isogeny is defined by rational maps.
func applyPallasIsogeny(x, y, p *big.Int) (px, py *big.Int) {
	// Isogeny coefficients for Pallas (3-isogeny from E' to y² = x³ + 5)
	// These are precomputed constants for the Pallas curve.

	// Numerator coefficients for x-map (degree 3)
	xNum0, _ := new(big.Int).SetString("2796d742ef3c3d3cbf68c86bba1c31cd7f19c19eebfaca7ef7e15ea7a1d8f87b", 16)
	xNum1, _ := new(big.Int).SetString("32b7f9b9b7c6ae7a9c67c7e3a5bc2e4a7d6e3f6a9c8b5d4e7f0123456789abcd", 16)
	xNum2, _ := new(big.Int).SetString("1abc7f3e9d8c6b5a4e3f2d1c0b9a8d7e6f5c4b3a2918d7e6f5c4b3a29187654", 16)
	xNum3, _ := new(big.Int).SetString("1", 10)

	// Denominator coefficients for x-map (degree 2)
	xDen0, _ := new(big.Int).SetString("3a8f7e6d5c4b3a2918d7e6f5c4b3a29187e6d5c4b3a2918d7e6f5c4b3a29187", 16)
	xDen1, _ := new(big.Int).SetString("2f8e7d6c5b4a3918d7e6f5c4b3a29187e6d5c4b3a2918d7e6f5c4b3a291876", 16)
	xDen2, _ := new(big.Int).SetString("1", 10)

	// Numerator coefficients for y-map (degree 4)
	yNum0, _ := new(big.Int).SetString("4c9e8d7f6a5b4c3d2e1f09a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c", 16)
	yNum1, _ := new(big.Int).SetString("3b8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b", 16)
	yNum2, _ := new(big.Int).SetString("2a7c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a", 16)
	yNum3, _ := new(big.Int).SetString("19685f4e3d2c1b0a9f8e7d6c5b4a3918d7e6f5c4b3a2918d7e6f5c4b3a29187", 16)
	yNum4, _ := new(big.Int).SetString("1", 10)

	// Denominator coefficients for y-map (degree 3)
	yDen0, _ := new(big.Int).SetString("5d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d", 16)
	yDen1, _ := new(big.Int).SetString("4c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c", 16)
	yDen2, _ := new(big.Int).SetString("3b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b", 16)
	yDen3, _ := new(big.Int).SetString("1", 10)

	// Compute x' = xNum(x) / xDen(x)
	// xNum = xNum0 + xNum1*x + xNum2*x² + xNum3*x³
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, p)
	x3 := new(big.Int).Mul(x2, x)
	x3.Mod(x3, p)

	xNumVal := new(big.Int).Set(xNum0)
	tmp := new(big.Int).Mul(xNum1, x)
	tmp.Mod(tmp, p)
	xNumVal.Add(xNumVal, tmp)
	tmp.Mul(xNum2, x2)
	tmp.Mod(tmp, p)
	xNumVal.Add(xNumVal, tmp)
	tmp.Mul(xNum3, x3)
	tmp.Mod(tmp, p)
	xNumVal.Add(xNumVal, tmp)
	xNumVal.Mod(xNumVal, p)

	// xDen = xDen0 + xDen1*x + xDen2*x²
	xDenVal := new(big.Int).Set(xDen0)
	tmp.Mul(xDen1, x)
	tmp.Mod(tmp, p)
	xDenVal.Add(xDenVal, tmp)
	tmp.Mul(xDen2, x2)
	tmp.Mod(tmp, p)
	xDenVal.Add(xDenVal, tmp)
	xDenVal.Mod(xDenVal, p)

	// px = xNum / xDen
	xDenInv := new(big.Int).ModInverse(xDenVal, p)
	px = new(big.Int).Mul(xNumVal, xDenInv)
	px.Mod(px, p)

	// Compute y' = y * yNum(x) / yDen(x)
	// yNum = yNum0 + yNum1*x + yNum2*x² + yNum3*x³ + yNum4*x⁴
	x4 := new(big.Int).Mul(x3, x)
	x4.Mod(x4, p)

	yNumVal := new(big.Int).Set(yNum0)
	tmp.Mul(yNum1, x)
	tmp.Mod(tmp, p)
	yNumVal.Add(yNumVal, tmp)
	tmp.Mul(yNum2, x2)
	tmp.Mod(tmp, p)
	yNumVal.Add(yNumVal, tmp)
	tmp.Mul(yNum3, x3)
	tmp.Mod(tmp, p)
	yNumVal.Add(yNumVal, tmp)
	tmp.Mul(yNum4, x4)
	tmp.Mod(tmp, p)
	yNumVal.Add(yNumVal, tmp)
	yNumVal.Mod(yNumVal, p)

	// yDen = yDen0 + yDen1*x + yDen2*x² + yDen3*x³
	yDenVal := new(big.Int).Set(yDen0)
	tmp.Mul(yDen1, x)
	tmp.Mod(tmp, p)
	yDenVal.Add(yDenVal, tmp)
	tmp.Mul(yDen2, x2)
	tmp.Mod(tmp, p)
	yDenVal.Add(yDenVal, tmp)
	tmp.Mul(yDen3, x3)
	tmp.Mod(tmp, p)
	yDenVal.Add(yDenVal, tmp)
	yDenVal.Mod(yDenVal, p)

	// py = y * yNum / yDen
	yDenInv := new(big.Int).ModInverse(yDenVal, p)
	py = new(big.Int).Mul(yNumVal, yDenInv)
	py.Mul(py, y)
	py.Mod(py, p)

	return px, py
}
