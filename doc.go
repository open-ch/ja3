// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
Package ja3 provides JA3 Client Fingerprinting for the Go language by looking at the
TLS Client Hello packets.

Basic Usage
ja3 takes in TCP payload data as a []byte and computes the corresponding JA3
string and digest.

  j, err := ja3.ComputeJA3FromSegment(tcpPayload)
  if err != nil {
  // If the packet is no Client Hello an error is thrown as soon as the parsing fails
  panic(err)
  }

  // Get the JA3 digest, string and SNI of the parsed Client Hello
  ja3Hash := j.GetJA3Hash()
  ja3String := j.GetJA3String()
  sni := j.GetSNI()
  fmt.Printf("JA3Hash: %v, JA3String: %v, SNI: %v\n", ja3Hash, ja3String, sni)

  // Get the JA3 string as a byte array for more efficient handling
  ja3String := j.GetJA3ByteString()
  anyWriterClass.Write(ja3String)

*/
package ja3
