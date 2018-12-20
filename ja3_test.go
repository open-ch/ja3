// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package ja3

import (
	"testing"
)

type testContainer struct {
	testPayload  []byte
	testJA3      JA3
	expJA3String string
	expJA3Hash   string
	expSNI       string
	expErr       error
}

func TestComputeJA3FromSegment(t *testing.T) {
	/*
		Build container with testing data

		Check the correct functionality with a few real and dummy segments, including a few important corner cases.
	*/
	var computeJA3FromSegmentTestSet = []testContainer{
		{ // Sanity check
			testPayload:  []byte{22, 3, 1, 0, 201, 1, 0, 0, 197, 3, 3, 82, 50, 235, 232, 231, 181, 243, 122, 13, 113, 213, 238, 184, 242, 230, 164, 189, 148, 5, 55, 17, 170, 189, 193, 212, 189, 211, 11, 239, 192, 39, 240, 0, 0, 36, 192, 48, 192, 44, 192, 47, 192, 43, 192, 20, 192, 10, 192, 19, 192, 9, 0, 159, 0, 158, 0, 57, 0, 51, 0, 157, 0, 156, 0, 53, 0, 47, 0, 10, 0, 255, 1, 0, 0, 120, 0, 0, 0, 18, 0, 16, 0, 0, 13, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 104, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 28, 0, 26, 0, 23, 0, 25, 0, 28, 0, 27, 0, 24, 0, 26, 0, 22, 0, 14, 0, 13, 0, 11, 0, 12, 0, 9, 0, 10, 0, 35, 0, 0, 0, 13, 0, 32, 0, 30, 6, 1, 6, 2, 6, 3, 5, 1, 5, 2, 5, 3, 4, 1, 4, 2, 4, 3, 3, 1, 3, 2, 3, 3, 2, 1, 2, 2, 2, 3, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 15, 0, 1, 1, 51, 116, 0, 0},
			expJA3String: "771,49200-49196-49199-49195-49172-49162-49171-49161-159-158-57-51-157-156-53-47-10-255,0-11-10-35-13-5-15-13172,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2",
			expJA3Hash:   "5e647d60a56d199388ae462b75b3cdad",
			expSNI:       "www.google.ch",
		},
		{ // Dummy segment (no elliptic curves, ECPF fields)
			testPayload:  []byte{22, 3, 0, 0, 57, 1, 0, 0, 53, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 21, 21, 0, 0, 11, 0, 0, 0, 7, 42, 42, 0, 0, 2, 52, 50},
			expJA3String: "768,5397,0,,",
			expJA3Hash:   "7b871a8d50bdac2c9186af16af86a0f4",
			expSNI:       "42",
		},
		{ // Dummy segment (with GREASE cipher and no elliptic curves, ECPF fields)
			testPayload:  []byte{22, 3, 0, 0, 57, 1, 0, 0, 53, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 11, 0, 0, 0, 7, 42, 42, 0, 0, 2, 52, 50},
			expJA3String: "768,,0,,",
			expJA3Hash:   "633682cdbaaa3594417b8a6514f56ac7",
			expSNI:       "42",
		},
		{ // Dummy segment (no extensions)
			testPayload:  []byte{22, 3, 0, 0, 44, 1, 0, 0, 40, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 21, 21, 0},
			expJA3String: "768,5397,,,",
			expJA3Hash:   "185477c6143146afd64ba7bc72210566",
			expSNI:       "",
		},
	}

	// Run through all test cases
	for _, test := range computeJA3FromSegmentTestSet {
		ja3, err := ComputeJA3FromSegment(test.testPayload)
		if err != nil {
			t.Errorf("Expected: %v but got: %v\n", test.expErr, err)
		}
		if ja3.GetJA3String() != test.expJA3String || ja3.GetJA3Hash() != test.expJA3Hash || ja3.GetSNI() != test.expSNI {
			t.Errorf("Expected: %v, %v, %v but got: %v, %v, %v\n",
				test.expJA3String,
				test.expJA3Hash,
				test.expSNI,
				ja3.GetJA3String(),
				ja3.GetJA3Hash(),
				ja3.GetSNI())
		}
	}
}

func TestGetJA3ByteString(t *testing.T) {
	/*
		Build container with testing data

		For testing the getter functions, we try to get the values of an imaginary Client Hello inside a JA3 object and
		compare it against the expected values.
	*/
	var getterTestContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
		expJA3String: "42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42",
	}

	ja3String := getterTestContainer.testJA3.GetJA3ByteString()
	if string(ja3String) != getterTestContainer.expJA3String {
		t.Errorf("Expected: %v but got: %v\n", getterTestContainer.expJA3String, string(ja3String))
	}
}

func TestGetJA3String(t *testing.T) {
	/*
		Build container with testing data

		For testing the getter functions, we try to get the values of an imaginary Client Hello inside a JA3 object and
		compare it against the expected values.
	*/
	var getterTestContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
		expJA3String: "42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42",
	}

	ja3String := getterTestContainer.testJA3.GetJA3String()
	if ja3String != getterTestContainer.expJA3String {
		t.Errorf("Expected: %v but got: %v\n", getterTestContainer.expJA3String, ja3String)
	}
}

func TestGetJA3Hash(t *testing.T) {
	/*
		Build container with testing data

		For testing the getter functions, we try to get the values of an imaginary Client Hello inside a JA3 object and
		compare it against the expected values.
	*/
	var getterTestContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
		expJA3Hash: "51b238d92972b9f5b232922107e05b9a",
	}

	ja3Hash := getterTestContainer.testJA3.GetJA3Hash()
	if ja3Hash != getterTestContainer.expJA3Hash {
		t.Errorf("Expected: %v but got: %v\n", getterTestContainer.expJA3Hash, ja3Hash)
	}
}

func TestGetSNI(t *testing.T) {
	/*
		Build container with testing data

		For testing the getter functions, we try to get the values of an imaginary Client Hello inside a JA3 object and
		compare it against the expected values.
	*/
	var getterTestContainer = testContainer{
		testJA3: JA3{
			sni: []byte("42"),
		},
		expSNI: "42",
	}

	sni := getterTestContainer.testJA3.GetSNI()
	if sni != getterTestContainer.expSNI {
		t.Errorf("Expected: %v but got: %v\n", getterTestContainer.expSNI, sni)
	}
}

func TestParseSegment(t *testing.T) {
	/*
		Build container with testing data

		For testing the parsing we build imaginary segments to get full coverage

		Abbreviations:
		- CT  = Content Type
		- Ver = Version
		- Len = Length
	*/
	var parseSegmentTestSet = []testContainer{
		{ //					CT
			testPayload: []byte{42},
			expErr:      &ParseError{LengthErr, 1},
		},
		{ //					CT  Ver---  Len---
			testPayload: []byte{42, 42, 42, 42, 42},
			expErr:      &ParseError{errType: ContentTypeErr},
		},
		{ //					CT  Ver---  Len---
			testPayload: []byte{22, 42, 42, 42, 42},
			expErr:      &ParseError{VersionErr, 1},
		},
	}

	// Run through all test cases
	for _, test := range parseSegmentTestSet {
		ja3 := JA3{}
		err := ja3.parseSegment(test.testPayload)
		if err.Error() != test.expErr.Error() {
			t.Errorf("Expected: %v but got: %v\n", test.expErr, err)
		}
	}
}

func TestParseTLSHandshake(t *testing.T) {
	/*
		Build container with testing data

		For testing the parsing we build imaginary TLS Handshakes to get full coverage

		Abbreviations:
		- CT  = Content Type
		- Ver = Version
		- Len = Length
		- HT  = Handshake Type
		- Ran = Random
		- SI  = Session ID Length
		- CL  = Cipher Suites Length
		- CS  = Cipher Suites
		- ML  = Compression Methods Length
	*/
	var parseTLSHandshakeTestSet = []testContainer{
		{ //					CT  Ver-  Len---
			testPayload: []byte{22, 3, 0, 42, 42},
			expErr:      &ParseError{LengthErr, 2},
		},
		{ //					CT  Ver-  Len-
			testPayload: []byte{22, 3, 0, 0, 0},
			expErr:      &ParseError{LengthErr, 3},
		},
		{ //					CT  Ver-  Len--  HT  Len-------  Ver---  Ran---------------------------------------------------------------------------------------------------------------------------  SI
			testPayload: []byte{22, 3, 0, 0, 39, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42},
			expErr:      &ParseError{errType: HandshakeTypeErr},
		},
		{ //					CT  Ver-  Len--  HT Len-------  Ver---  Ran---------------------------------------------------------------------------------------------------------------------------  SI
			testPayload: []byte{22, 3, 0, 0, 39, 1, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42},
			expErr:      &ParseError{LengthErr, 4},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver---  Ran---------------------------------------------------------------------------------------------------------------------------  SI
			testPayload: []byte{22, 3, 0, 0, 39, 1, 0, 0, 35, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42},
			expErr:      &ParseError{VersionErr, 2},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI
			testPayload: []byte{22, 3, 0, 0, 39, 1, 0, 0, 35, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42},
			expErr:      &ParseError{LengthErr, 5},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI
			testPayload: []byte{22, 3, 0, 0, 39, 1, 0, 0, 35, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0},
			expErr:      &ParseError{LengthErr, 6},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL----
			testPayload: []byte{22, 3, 0, 0, 41, 1, 0, 0, 37, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 42, 42},
			expErr:      &ParseError{LengthErr, 7},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML
			testPayload: []byte{22, 3, 0, 0, 44, 1, 0, 0, 40, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 42},
			expErr:      &ParseError{LengthErr, 8},
		},
	}

	// Run through all test cases
	for _, test := range parseTLSHandshakeTestSet {
		ja3 := JA3{}
		err := ja3.parseSegment(test.testPayload)
		if err.Error() != test.expErr.Error() {
			t.Errorf("Expected: %v but got: %v\n", test.expErr, err)
		}
	}
}

func TestParseExtensions(t *testing.T) {
	/*
		Build container with testing data

		For testing the parsing we build imaginary TLS Handshakes to get full coverage

		Abbreviations:
		- CT  = Content Type
		- Ver = Version
		- Len = Length
		- HT  = Handshake Type
		- Ran = Random
		- SI  = Session ID Length
		- CL  = Cipher Suites Length
		- CS  = Cipher Suites
		- ML  = Compression Methods Length
		- EL  = Extensions Length
		- ET  = Extension Type
		- ExL = Extension Length
		- SN  = Server Name List Length (unused in the parser)
		- ST  = Server Name Type
		- SL  = Server Name Length
		- EC  = Supported Groups List Length (called "Elliptic Curves" in the parser)
		- FL  = ECPF Length
	*/
	var parseTLSHandshakeTestSet = []testContainer{
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL
			testPayload: []byte{22, 3, 0, 0, 45, 1, 0, 0, 41, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 42},
			expErr:      &ParseError{LengthErr, 9},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL----
			testPayload: []byte{22, 3, 0, 0, 46, 1, 0, 0, 42, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 42, 42},
			expErr:      &ParseError{LengthErr, 10},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET
			testPayload: []byte{22, 3, 0, 0, 47, 1, 0, 0, 43, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 1, 42},
			expErr:      &ParseError{LengthErr, 11},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET----  ExL---
			testPayload: []byte{22, 3, 0, 0, 50, 1, 0, 0, 46, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 4, 42, 42, 42, 42},
			expErr:      &ParseError{LengthErr, 12},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET--  ExL-
			testPayload: []byte{22, 3, 0, 0, 50, 1, 0, 0, 46, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 4, 0, 0, 0, 0},
			expErr:      &ParseError{LengthErr, 13},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET--  ExL-  SN----  ST  SL----
			testPayload: []byte{22, 3, 0, 0, 55, 1, 0, 0, 51, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 9, 0, 0, 0, 5, 42, 42, 42, 42, 42},
			expErr:      &ParseError{LengthErr, 14},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET--  ExL-  SN----  ST  SL--
			testPayload: []byte{22, 3, 0, 0, 55, 1, 0, 0, 51, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 9, 0, 0, 0, 5, 42, 42, 42, 0, 0},
			expErr:      &ParseError{errType: SNITypeErr},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET---  ExL-
			testPayload: []byte{22, 3, 0, 0, 50, 1, 0, 0, 46, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 4, 0, 10, 0, 0},
			expErr:      &ParseError{LengthErr, 15},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET---  ExL-  EC----
			testPayload: []byte{22, 3, 0, 0, 52, 1, 0, 0, 48, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 6, 0, 10, 0, 2, 42, 42},
			expErr:      &ParseError{LengthErr, 16},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET---  ExL-
			testPayload: []byte{22, 3, 0, 0, 50, 1, 0, 0, 46, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 4, 0, 11, 0, 0},
			expErr:      &ParseError{LengthErr, 17},
		},
		{ //					CT  Ver-  Len--  HT Len-----  Ver-  Ran---------------------------------------------------------------------------------------------------------------------------  SI CL--  CS----  ML EL--  ET---  ExL-  FL
			testPayload: []byte{22, 3, 0, 0, 51, 1, 0, 0, 47, 3, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 2, 42, 42, 0, 0, 5, 0, 11, 0, 1, 42},
			expErr:      &ParseError{LengthErr, 18},
		},
	}

	// Run through all test cases
	for _, test := range parseTLSHandshakeTestSet {
		ja3 := JA3{}
		err := ja3.parseSegment(test.testPayload)
		if err.Error() != test.expErr.Error() {
			t.Errorf("Expected: %v but got: %v\n", test.expErr, err)
		}
	}
}

func TestMarshalJA3(t *testing.T) {
	/*
		Build container with testing data

		For testing the string marshalling function, we try to build strings from imaginary JA3 objects and compare them
		with the expected output.
	*/
	var marshalJA3TestSet = []testContainer{
		{ // Sanity check
			testJA3: JA3{
				version:         uint16(42),
				cipherSuites:    []uint16{42, 42, 42, 42, 42},
				extensions:      []uint16{42, 42, 42, 42, 42},
				ellipticCurves:  []uint16{42, 42, 42, 42, 42},
				ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
			},
			expJA3String: "42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42,42-42-42-42-42",
		},
		{ // Minimal valid Client Hello
			testJA3: JA3{
				version: uint16(42),
			},
			expJA3String: "42,,,,",
		},
		{ // Unpopulated JA3
			testJA3:      JA3{},
			expJA3String: "0,,,,",
		},
	}

	// Run through all test cases
	for _, test := range marshalJA3TestSet {
		test.testJA3.marshalJA3()
		if string(test.testJA3.ja3ByteString) != test.expJA3String {
			t.Errorf("Expected: %v but got: %v\n", test.expJA3String, string(test.testJA3.ja3ByteString))
		}
	}
}

func BenchmarkComputeJA3FromSegment(b *testing.B) {
	/*
		Build container with benchmarking data
	*/
	var googleBenchmarkContainer = testContainer{
		testPayload: []byte{22, 3, 1, 0, 201, 1, 0, 0, 197, 3, 3, 82, 50, 235, 232, 231, 181, 243, 122, 13, 113, 213, 238, 184, 242, 230, 164, 189, 148, 5, 55, 17, 170, 189, 193, 212, 189, 211, 11, 239, 192, 39, 240, 0, 0, 36, 192, 48, 192, 44, 192, 47, 192, 43, 192, 20, 192, 10, 192, 19, 192, 9, 0, 159, 0, 158, 0, 57, 0, 51, 0, 157, 0, 156, 0, 53, 0, 47, 0, 10, 0, 255, 1, 0, 0, 120, 0, 0, 0, 18, 0, 16, 0, 0, 13, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 104, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 28, 0, 26, 0, 23, 0, 25, 0, 28, 0, 27, 0, 24, 0, 26, 0, 22, 0, 14, 0, 13, 0, 11, 0, 12, 0, 9, 0, 10, 0, 35, 0, 0, 0, 13, 0, 32, 0, 30, 6, 1, 6, 2, 6, 3, 5, 1, 5, 2, 5, 3, 4, 1, 4, 2, 4, 3, 3, 1, 3, 2, 3, 3, 2, 1, 2, 2, 2, 3, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 15, 0, 1, 1, 51, 116, 0, 0},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ComputeJA3FromSegment(googleBenchmarkContainer.testPayload)
	}
}

func BenchmarkGetJA3ByteString(b *testing.B) {
	/*
		Build container with benchmarking data
	*/
	var getterBenchmarkContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		getterBenchmarkContainer.testJA3.GetJA3ByteString()
	}
}

func BenchmarkGetJA3String(b *testing.B) {
	/*
		Build container with benchmarking data
	*/
	var getterBenchmarkContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		getterBenchmarkContainer.testJA3.GetJA3String()
	}
}

func BenchmarkGetJA3Hash(b *testing.B) {
	/*
		Build container with benchmarking data
	*/
	var getterBenchmarkContainer = testContainer{
		testJA3: JA3{
			version:         uint16(42),
			cipherSuites:    []uint16{42, 42, 42, 42, 42},
			extensions:      []uint16{42, 42, 42, 42, 42},
			ellipticCurves:  []uint16{42, 42, 42, 42, 42},
			ellipticCurvePF: []uint8{42, 42, 42, 42, 42},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		getterBenchmarkContainer.testJA3.GetJA3Hash()
	}
}

func BenchmarkGetSNI(b *testing.B) {
	/*
		Build container with benchmarking data
	*/
	var getterBenchmarkContainer = testContainer{
		testJA3: JA3{
			sni: []byte("42"),
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		getterBenchmarkContainer.testJA3.GetSNI()
	}
}
