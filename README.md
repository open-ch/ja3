# JA3 - High Performance Go Implementation [![GoDoc](https://godoc.org/github.com/open-ch/ja3?status.svg)](https://godoc.org/github.com/open-ch/ja3) [![Go Report Card](https://goreportcard.com/badge/github.com/open-ch/ja3)](https://goreportcard.com/report/github.com/open-ch/ja3)

"JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence." - John B. Althouse

The algorithm originates from Salesforce and the official Python and Bro implementations can be found [here](https://github.com/salesforce/ja3). For information about what JA3 is and how it works check out their repository or their blog [post](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41).

This package includes a go library with an implementation of the algorithm and a command line tool which allows reading packets from pcap and pcapng files as well as from an interface.

## Usage

###Library
```
import "github.com/open-ch/ja3"
```
See the following example to get an idea of the exposed API. For more information look in the [godoc](https://godoc.org/github.com/open-ch/ja3).

```
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
```

###CLI
```
[host:]# go build ja3exporter.go engine.go

[host:]# ./ja3exporter -pcap="/path/to/file"
{"destination_ip":"172.217.168.67","destination_port":443,"ja3":"771,49200-49196-49199-49195-49172-49162-49171-49161-159-158-57-51-157-156-53-47-10-255,0-11-10-35-13-5-15-13172,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2","ja3_digest":"5e647d60a56d199388ae462b75b3cdad","source_ip":"213.156.236.180","source_port":34577,"sni":"www.google.ch","timestamp":1537516825571014000}
```

## Tests and Benchmarks
As the TLS parser is custom built and highly optimized for the JA3 digest, a full coverage testing suite is put in place.
Our Go implementation is more than an order of magnitude faster than the python implementation.

```
// JA3Exporter
time ja3exporter -pcap="/Users/enm/Documents/pcaps/DEF CON 23 ICS Village.pcap" > /dev/null
0.46s user
0.05s system
113% cpu
0.453 total

// Official Python Implmentation
time ja3 ~/Documents/pcaps/DEF\ CON\ 23\ ICS\ Village.pcap > /dev/null
23.10s user
0.40s system
98% cpu
23.874 total

// Dreadl0cks Go Implementation
time ./cmd -read=/Users/enm/Documents/pcaps/DEF\ CON\ 23\ ICS\ Village.pcap > /dev/null
2.47s user
0.11s system
164% cpu
1.565 total
```

The pcap file used for the above tests can be found [here](https://www.defcon.org/html/defcon-23/dc-23-index.html)

Benchmarks of the Library functions on initial call:
```
goos: darwin
goarch: amd64
BenchmarkComputeJA3FromSegment-4   	 3000000	       367 ns/op	     304 B/op	       6 allocs/op
BenchmarkGetJA3ByteString-4        	10000000	       216 ns/op	     128 B/op	       1 allocs/op
BenchmarkGetJA3String-4            	 5000000	       253 ns/op	     192 B/op	       2 allocs/op
BenchmarkGetJA3Hash-4              	 3000000	       557 ns/op	     192 B/op	       3 allocs/op
BenchmarkGetSNI-4                  	300000000	         5.60 ns/op	       0 B/op	       0 allocs/op
```
The getter functions are setup to cache their results so any further access to these values perform as follows:
```
goos: darwin
goarch: amd64
BenchmarkGetJA3ByteString-4        	1000000000	         2.73 ns/op	       0 B/op	       0 allocs/op
BenchmarkGetJA3String-4            	1000000000	         2.44 ns/op	       0 B/op	       0 allocs/op
BenchmarkGetJA3Hash-4              	1000000000	         2.72 ns/op	       0 B/op	       0 allocs/op
BenchmarkGetSNI-4                  	300000000	         5.61 ns/op	       0 B/op	       0 allocs/op
```
