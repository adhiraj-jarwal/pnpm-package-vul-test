package main

import (
	"fmt"
	
	// Importing vulnerable packages to trigger govulncheck
	_ "golang.org/x/crypto/salsa20/salsa"
	_ "golang.org/x/text/language"
)

func main() {
	fmt.Println("Test application for vulnerability scanning")
}
