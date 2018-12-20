// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\nCreates JA3 digests for TLS client fingerprinting.\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n\nExample:\n\n[host:]# ./ja3exporter -pcap=\"/path/to/file\"\n{\"destination_ip\":\"172.217.168.67\",\"destination_port\":443,\"ja3\":\"771,49200-49196-49199-49195-49172-49162-49171-49161-159-158-57-51-157-156-53-47-10-255,0-11-10-35-13-5-15-13172,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2\",\"ja3_digest\":\"5e647d60a56d199388ae462b75b3cdad\",\"source_ip\":\"213.156.236.180\",\"source_port\":34577,\"sni\":\"www.google.ch\",\"timestamp\":1537516825571014000}\n\n")
	}
	pcap := flag.String("pcap", "", "Path to pcap file to be read")
	pcapng := flag.String("pcapng", "", "Path to pcapng file to be read")
	device := flag.String("interface", "", "Name of interface to be read (e.g. eth0)")
	compat := flag.Bool("c", false, "Activates compatibility mode (use this if packet does not consist of a pure ETH/IP/TCP stack)")
	flag.Parse()

	if *pcap != "" {
		// Read pcap file
		f, err := os.Open(*pcap)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		r, err := ReadPcapFile(f)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else if *pcapng != "" {
		// Read pcapng file
		f, err := os.Open(*pcapng)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		r, err := ReadPcapngFile(f)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else if *device != "" {
		// Read from interface
		r, err := ReadFromInterface(*device)
		if err != nil {
			panic(err)
		}

		// Compute JA3 digests and output to os.Stdout
		if *compat {
			err = ComputeJA3FromReader(r, os.Stdout)
		} else {
			err = CompatComputeJA3FromReader(r, os.Stdout)
		}
		if err != nil {
			panic(err)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
}
