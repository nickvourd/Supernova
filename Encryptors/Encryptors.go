package Encryptors

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

const (
	chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]"
)

// GenerateRandomXORKey function
func GenerateRandomXORKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		panic("[!] Failed to generate random key.")
	}
	return key
}

// GenerateRandomPassphrase function
func GenerateRandomPassphrase(length int) string {

	charSetLength := big.NewInt(int64(len(chars)))
	passphrase := make([]byte, length)

	for i := range passphrase {
		randomIndex, err := rand.Int(rand.Reader, charSetLength)
		if err != nil {
			fmt.Println("Error generating random number:", err)
			return ""
		}
		passphrase[i] = chars[randomIndex.Int64()]
	}

	return string(passphrase)
}

// XOREncryption function performs XOR encryption on input shellcode using a multi xor key.
func XOREncryption(shellcode []byte, key []byte) []byte {
	encoded := make([]byte, len(shellcode))
	keyLen := len(key)

	for i := 0; i < len(shellcode); i++ {
		encoded[i] = shellcode[i] ^ key[i%keyLen]
	}

	return encoded
}

// DetectEncryption function
func DetectEncryption(cipher string, shellcode string, key int) (string, []byte) {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)

	// Set cipher to lower
	cipher = strings.ToLower(cipher)

	// Set key size
	keyLength := key

	switch cipher {
	case "xor":
		// Call function named GenerateRandomXORKey
		xorKey := GenerateRandomXORKey(keyLength)

		// Print generated XOR key
		fmt.Printf("[+] Generated XOR key: ")
		for i, b := range xorKey {
			decimalValue := int(b)
			hexValue := fmt.Sprintf("%02x", b)
			fmt.Printf("byte(0x%s) => %d", hexValue, decimalValue)
			if i < len(xorKey)-1 {
				fmt.Printf(", ")
			}
		}

		fmt.Printf("\n\n")

		shellcodeInBytes := []byte(shellcode)
		// fmt.Println(shellcodeInBytes)
		encryptedShellcode := XOREncryption(shellcodeInBytes, xorKey)
		// fmt.Println(encryptedShellcode)

		// Convert Encrypted shellcode to formatted string
		var formattedShellcode []string
		for _, b := range encryptedShellcode {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("0x%02x", b))
		}

		// Combine formatted shellcode with commas
		shellcodeFormatted := strings.Join(formattedShellcode, ", ")

		// Print the formatted Encrypted shellcode
		//fmt.Println("Encrypted Shellcode:", shellcodeFormatted)
		//fmt.Println("Encrypted Shellcode Length:", len(encryptedShellcode))
		return shellcodeFormatted, xorKey
	case "aes":
		fmt.Println("Hello2")
		return "", nil
	case "rc4":
		// Call function named GenerateRandomPassphrase
		randomPassphrase := GenerateRandomPassphrase(key)
		fmt.Printf("[+] Random passphrase: %s\n\n", randomPassphrase)
		return "", nil
	default:
		logger.Fatal("Unsupported encryption cipher")
		return "", nil
	}
}
