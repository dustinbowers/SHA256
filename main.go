package main

import (
"bufio"
"encoding/binary"
"fmt"
	"io"
	"log"
"math"
"math/bits"
"os"
)

func getK() []uint32 {
	return []uint32 {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
}

func getH() []uint32 {
	return []uint32 {
		0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
		0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
	}
}

func openFile(filePath string) (*os.File, uint64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error reading file [%v]: %v\n", filePath, err.Error())
	}

	fi, err := f.Stat()
	if err != nil {
		log.Fatalf("Error getting file size\n")
	}
	return f, uint64(fi.Size()), nil
}

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Incorrect arguments.\nUsage: sha255 <filename>")
		return
	}

	filePath := os.Args[1]
	f, numBytes, err := openFile(filePath)
	if err != nil {
		log.Fatalf("Error opening file. %v\n", err)
	}
	defer f.Close()

	numChunks := (numBytes * 8) / 512 + 1
	if numBytes % 64 > 54 {
		numChunks = numChunks + 1
	}

	hash := getH()
	k := getK()

	r := bufio.NewReader(f)
	buf := make([]byte, 64)
	bytesRead := uint64(0)
	oneAdded := false
	// Process the message in successive 512-bit chunks:
	for n := uint64(0); n < numChunks; n ++ {
		for j := 0; j < 64; j++ {
			buf[j] = 0
		}
		n, err := r.Read(buf[0:cap(buf)])
		bytesRead = bytesRead + uint64(n)
		if err != nil && err != io.EOF {
			fmt.Println("Error reading file: ", err)
			break
		}

		w := make([]uint32, 64)

		// Copy chunk into first 16 words of message array
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(buf[i*4:i*4+4])
		}

		if oneAdded == false && bytesRead == numBytes {
			oneAdded = true
			// Pad the last 512-bit chunk with SHA256 magic
			// Last chunk takes the bit form: <read bits> 1 <zeros> <numBytes as 64-bit int)

			// Super ugly way of injecting a 1 bit with trailing zeros...
			wordInd := uint64(math.Floor(float64(n) / 4))
			byteInd := n % 4
			oneBits := uint32(1)

			switch byteInd {
			case 0:
				oneBits = oneBits << 31
			case 1:
				oneBits = oneBits << 23
			case 2:
				oneBits = oneBits << 15
			case 3:
				oneBits = oneBits << 7
			}
			w[wordInd] = w[wordInd] | oneBits
		}

		if n < 54 {
			numBits := numBytes * 8
			w[14] = uint32(numBits >> 32)
			w[15] = uint32(numBits)
		}

		// Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
		for i := 16; i < 64; i++ {
			s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
			s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		// Initialize working variables to current hash value:
		a := hash[0]
		b := hash[1]
		c := hash[2]
		d := hash[3]
		e := hash[4]
		f := hash[5]
		g := hash[6]
		h := hash[7]

		// Compression function main loop:
		for i := 0; i < 64; i++ {
			S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + S1 + ch + k[i] + w[i]
			S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		// Add the compressed chunk to the current hash value:
		hash[0] = hash[0] + a
		hash[1] = hash[1] + b
		hash[2] = hash[2] + c
		hash[3] = hash[3] + d
		hash[4] = hash[4] + e
		hash[5] = hash[5] + f
		hash[6] = hash[6] + g
		hash[7] = hash[7] + h
	}

	digest := fmt.Sprintf("%08x%08x%08x%08x%08x%08x%08x%08x", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7])
	fmt.Printf("%s  %s\n", digest, filePath)
}
