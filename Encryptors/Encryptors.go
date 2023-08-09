package Encryptors

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"strings"
)

func GenerateRandomXORKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		panic("Failed to generate random key")
	}
	return key
}

// DetectEncryption function
func DetectEncryption(cipher string, shellcode string) {
	logger := log.New(os.Stderr, "[!] ", 0)
	cipher = strings.ToLower(cipher)
	keyLength := 1 // Specify the desired key length in bytes
	xorKey := GenerateRandomXORKey(keyLength)

	fmt.Printf("Generated XOR key: ")
	for _, b := range xorKey {
		fmt.Printf("byte(0x%02x), ", b)
	}

	nikos := byte(xorKey[0])
	kostas := byte(0x55)
	fmt.Println(nikos)
	fmt.Println(kostas)

	switch cipher {
	case "xor":
		shellcodeInBytes := []byte(shellcode)
		encryptedShellcode := XOREncryption(shellcodeInBytes, xorKey[0])

		// Convert Encrypted shellcode to formatted string
		var formattedShellcode []string
		for _, b := range encryptedShellcode {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("0x%02x", b))
		}

		// Combine formatted shellcode with commas
		shellcodeFormatted := strings.Join(formattedShellcode, ", ")

		// Print the formatted Encrypted shellcode
		fmt.Println("Encrypted Shellcode:", shellcodeFormatted)
		fmt.Println("Encrypted Shellcode Length:", len(encryptedShellcode))

	case "aes":
		fmt.Println("Hello2")
	case "rc4":
		fmt.Println("Hello 3")
	default:
		logger.Fatal("Unsupported encryption cipher")
	}
}

// XOREncryption function performs XOR encryption on input shellcode using a key.
func XOREncryption(shellcode []byte, key byte) []byte {
	fmt.Println(key)
	encoded := make([]byte, len(shellcode))
	for i := 0; i < len(shellcode); i++ {
		encoded[i] = shellcode[i] ^ key
	}
	return encoded
}
