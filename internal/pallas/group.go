// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package pallas allows simple and abstracted operations in the Pallas group.
package pallas

import (
	"crypto"
	"sync"

	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/field"
)

const (
	// Identifier distinguishes this group from the others by a byte representation.
	Identifier = byte(8)

	// H2CPallas represents the hash-to-curve string identifier for Pallas.
	H2CPallas = "pallas_XMD:BLAKE2b-256_SSWU_RO_"

	// E2CPallas represents the encode-to-curve string identifier for Pallas.
	E2CPallas = "pallas_XMD:BLAKE2b-256_SSWU_NU_"

	// scalarLength is the byte size of encoded scalars.
	scalarLength = 32

	// elementLength is the byte size of compressed encoded elements.
	elementLength = 33

	// Pallas curve parameters
	// p is the field modulus: 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
	// n is the group order: 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
	// a = 0, b = 5 (curve equation: y² = x³ + 5)
	// h = 1 (cofactor)

	pallasFieldOrder = "0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001"
	pallasGroupOrder = "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
)

var (
	initOnce    sync.Once
	groupPallas *Group
)

// Group represents the Pallas group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct {
	scalarField field.Field
	baseField   field.Field
}

// New returns a new instantiation of the Pallas Group.
func New() internal.Group {
	initOnce.Do(initPallas)
	return groupPallas
}

func initPallas() {
	scalarOrder := field.String2Int(pallasGroupOrder)
	fieldOrder := field.String2Int(pallasFieldOrder)

	groupPallas = &Group{
		scalarField: field.NewField(&scalarOrder),
		baseField:   field.NewField(&fieldOrder),
	}
}

// NewScalar returns a new scalar set to 0.
func (g *Group) NewScalar() internal.Scalar {
	return newScalar(&g.scalarField)
}

// NewElement returns the identity element (point at infinity).
func (g *Group) NewElement() internal.Element {
	return newElement(&g.baseField)
}

// Base returns the group's base point a.k.a. canonical generator.
func (g *Group) Base() internal.Element {
	e := newElement(&g.baseField)
	e.Base()
	return e
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g *Group) HashFunc() crypto.Hash {
	return crypto.BLAKE2b_512
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) HashToScalar(input, dst []byte) internal.Scalar {
	return hashToScalar(&g.scalarField, input, dst)
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) HashToGroup(input, dst []byte) internal.Element {
	return hashToGroup(&g.baseField, input, dst)
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) EncodeToGroup(input, dst []byte) internal.Element {
	return encodeToGroup(&g.baseField, input, dst)
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g *Group) Ciphersuite() string {
	return H2CPallas
}

// ScalarLength returns the byte size of an encoded scalar.
func (g *Group) ScalarLength() int {
	return scalarLength
}

// ElementLength returns the byte size of an encoded element.
func (g *Group) ElementLength() int {
	return elementLength
}

// Order returns the order of the canonical group of scalars.
func (g *Group) Order() []byte {
	out := make([]byte, scalarLength)
	return g.scalarField.Order().FillBytes(out)
}
