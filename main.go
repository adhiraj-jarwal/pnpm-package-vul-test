package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/language"
)

func main() {
	// Using vulnerable crypto package
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	fmt.Println("Hash:", string(hash))
	
	// Using vulnerable text package
	tag := language.English
	fmt.Println("Language:", tag)
}

