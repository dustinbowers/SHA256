package main

import (
	"SHA256/hash"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Incorrect arguments.\nUsage: sha255 <filename>")
		return
	}

	h := hash.NewSHA256()
	digest, err := h.Sum(os.Args[1])
	if err != nil {
		log.Fatalf("%s", err)
	}

	fmt.Printf("%x  %s\n", digest, os.Args[1])
}
