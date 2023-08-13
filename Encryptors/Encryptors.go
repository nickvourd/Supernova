package Encryptors

import (
	"Supernova/Converters"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

type Rc4Context struct {
	i uint32
	j uint32
	s [256]uint8
}

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
	encrypted := make([]byte, len(shellcode))
	keyLen := len(key)

	for i := 0; i < len(shellcode); i++ {
		encrypted[i] = shellcode[i] ^ key[i%keyLen]
	}

	return encrypted
}

// RC4Encryption function implements the RC4 encryption algorithm
func RC4Encryption(data []byte, key []byte) []byte {
	var s [256]byte

	// Initialize the S array with values from 0 to 255
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}

	j := 0
	// KSA (Key Scheduling Algorithm) - Initial permutation of S array based on the key
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}

	encrypted := make([]byte, len(data))
	i, j := 0, 0
	// PRGA (Pseudo-Random Generation Algorithm) - Generate encrypted output
	for k := 0; k < len(data); k++ {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		// XOR encrypted byte with generated pseudo-random byte from S array
		encrypted[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}

	return encrypted
}

// CaesarEncryption function implements the Caesar encryption algorithm
func CaesarEncryption(shellcode []byte, shift int) []byte {
	encrypted := make([]byte, len(shellcode))
	for i, char := range shellcode {
		// Apply Caesar cipher encryption
		encryptedChar := char + byte(shift)
		encrypted[i] = encryptedChar
	}
	return encrypted
}

// DetectEncryption function
func DetectEncryption(cipher string, shellcode string, key int) (string, []byte, string) {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)

	// Set cipher to lower
	cipher = strings.ToLower(cipher)

	// Convert shellcode to bytes
	shellcodeInBytes := []byte(shellcode)

	// Set key size
	shift := key

	switch cipher {
	case "xor":
		// Call function named GenerateRandomXORKey
		xorKey := GenerateRandomXORKey(shift)

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

		// Call function named XOREncryption
		encryptedShellcode := XOREncryption(shellcodeInBytes, xorKey)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode)

		return shellcodeFormatted, xorKey, ""
	case "caesar":
		// Print selected shift key
		fmt.Printf("[+] Selected Shift Key: %d\n\n", shift)

		// Call function named XOREncryption
		encryptedShellcode := CaesarEncryption(shellcodeInBytes, shift)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode)

		return shellcodeFormatted, nil, ""
	case "aes":
		fmt.Println("Hello2")
		return "", nil, ""
	case "rc4":
		// Call function named GenerateRandomPassphrase
		randomPassphrase := GenerateRandomPassphrase(key)

		// Convert passphrase to bytes
		rc4Key := []byte(randomPassphrase)

		// Print generated passphrase
		fmt.Printf("[+] Generated Passphrase: %s\n\n", randomPassphrase)

		// Call function named RC4Encryption
		encryptedShellcode := RC4Encryption(shellcodeInBytes, rc4Key)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode)

		return shellcodeFormatted, nil, randomPassphrase
	default:
		logger.Fatal("Unsupported encryption cipher")
		return "", nil, ""
	}
}
