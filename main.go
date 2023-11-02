package main

import (
	"SHA256/hash"
	"bufio"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 1 || len(os.Args) > 2 {
		fmt.Println("Usage: SHA256 <filename>")
		os.Exit(1)
		return
	}
	inputFile := os.Args[1]

	f, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error reading file [%v]: %v\n", inputFile, err.Error())
		os.Exit(1)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	h := hash.NewSHA256()
	digest, err := h.Sum(r)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%x  %s\n", digest, inputFile)
}
