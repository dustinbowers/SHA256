package main

import (
	"SHA256/hash"
	"bufio"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Incorrect arguments.\nUsage: sha255 <filename>")
		return
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Error reading file [%v]: %v\n", os.Args[1], err.Error())
	}

	h := hash.NewSHA256()
	digest, err := h.Sum(bufio.NewReader(f))
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%x  %s\n", digest, os.Args[1])
}
