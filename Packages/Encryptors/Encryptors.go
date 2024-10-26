package Encryptors

import (
	"Supernova/Packages/Colors"
	"Supernova/Packages/Converters"
	"Supernova/Packages/Output"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// chars defines the set of characters used to generate a random key and IV.
	chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]"

	// ivSize specifies the size (in bytes) of the initialization vector (IV).
	ivSize = 16
)

// GenerateRandomBytes function
func GenerateRandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic("[!] Failed to generate a random key.")
	}
	return randomBytes
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

// XOREncryption function
// Performs XOR encryption on input shellcode using a multi xor key.
func XOREncryption(shellcode []byte, key []byte) []byte {
	encrypted := make([]byte, len(shellcode))
	keyLen := len(key)

	for i := 0; i < len(shellcode); i++ {
		encrypted[i] = shellcode[i] ^ key[i%keyLen]
	}

	return encrypted
}

// CaesarEncryption function
// Implements the Caesar encryption algorithm
func CaesarEncryption(shellcode []byte, shift int) []byte {
	encrypted := make([]byte, len(shellcode))
	for i, char := range shellcode {
		// Apply Caesar cipher encryption
		encrypted[i] = byte((int(char) + shift) % 256)
	}
	return encrypted
}

// PKCS7Padding function
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// AESEncryption function
// Performs AES-CBC encryption
func AESEncryption(key []byte, iv []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Apply PKCS7 padding to ensure plaintext length is a multiple of the block size
	paddedData := PKCS7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))

	// Create a new CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

// RC4Encryption function
// Implements the RC4 encryption algorithm
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

// Encrypt data using given key (32 bytes)
// https://github.com/alinz/crypto.go/blob/main/chacha20.go
func Chacha20Encryption(data []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, nonceSize, nonceSize+len(data)+aead.Overhead())

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	return aead.Seal(nonce, nonce, data, nil), nil
}

// DetectEncryption function
func DetectEncryption(cipher string, shellcode string, key int, language string) (string, int, []byte) {
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
		// Call function named GenerateRandomBytes
		xorKey := GenerateRandomBytes(shift)

		// Print generated XOR key
		fmt.Printf("[+] Generated XOR key: ")

		// Call function named PrintKeyDetails
		Output.PrintKeyDetails(xorKey)

		// Call function named XOREncryption
		encryptedShellcode := XOREncryption(shellcodeInBytes, xorKey)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode, language)

		return shellcodeFormatted, len(encryptedShellcode), encryptedShellcode
	case "rot":
		// Convert the integer to a string
		shiftString := strconv.Itoa(shift)

		// Print selected shift key
		fmt.Printf("[+] Selected Shift key: %s\n\n", Colors.BoldGreen(shiftString))

		// Call function named XOREncryption
		encryptedShellcode := CaesarEncryption(shellcodeInBytes, shift)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode, language)

		return shellcodeFormatted, len(encryptedShellcode), encryptedShellcode
	case "aes":
		// Set key from argument key
		keySize := key

		// Generate a random key-byte key and a random 16-byte IV
		key := GenerateRandomBytes(keySize)
		iv := GenerateRandomBytes(ivSize)

		// Print generated key
		fmt.Printf("[+] Generated key (%d-byte): ", keySize)

		// Call function named PrintKeyDetails
		Output.PrintKeyDetails(key)

		// Print generated key
		fmt.Printf("[+] Generated IV (16-byte): ")

		// Call function named PrintKeyDetails
		Output.PrintKeyDetails(iv)

		// Call function named DetectNotification
		keyNotification := Output.DetectNotification(keySize)

		// Print AES-<keyNotification>-CBC notification
		fmt.Printf("[+] Using AES-%d-CBC encryption\n\n", keyNotification)

		// Encrypt the shellcode using AES-256-CBC
		encryptedShellcode, err := AESEncryption(key, iv, shellcodeInBytes)
		if err != nil {
			panic(err)
		}

		// Convert the integer to a string
		lenEncryptedShellcodeString := strconv.Itoa(len(encryptedShellcode))

		// Print length changed notification
		fmt.Printf("[+] New Payload size: %s bytes\n\n", Colors.BoldYellow(lenEncryptedShellcodeString))

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode, language)

		return shellcodeFormatted, len(encryptedShellcode), encryptedShellcode
	case "rc4":
		// Call function named GenerateRandomPassphrase
		randomPassphrase := GenerateRandomPassphrase(key)

		// Convert passphrase to bytes
		rc4Key := []byte(randomPassphrase)

		// Print generated XOR key
		fmt.Printf("[+] Generated RC4 key: ")

		// Call function named PrintKeyDetails
		Output.PrintKeyDetails(rc4Key)

		// Call function named RC4Encryption
		encryptedShellcode := RC4Encryption(shellcodeInBytes, rc4Key)

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode, language)

		return shellcodeFormatted, len(encryptedShellcode), encryptedShellcode
	case "chacha20":
		// Call function named GenerateRandomBytes
		chacha20Key := GenerateRandomBytes(key)

		// Print generated Chacha2 key
		fmt.Printf("[+] Generated Chacha20 key: ")

		// Call function named PrintKeyDetails
		Output.PrintKeyDetails(chacha20Key)

		// Call function named Chacha20Encryption
		encryptedShellcode, _ := Chacha20Encryption(shellcodeInBytes, chacha20Key)

		// Convert the integer to a string
		lenEncryptedShellcodeString := strconv.Itoa(len(encryptedShellcode))

		// Print length changed notification
		fmt.Printf("[+] New Payload size: %s bytes\n\n", Colors.BoldYellow(lenEncryptedShellcodeString))

		// Call function named FormatShellcode
		shellcodeFormatted := Converters.FormatShellcode(encryptedShellcode, language)

		return shellcodeFormatted, len(encryptedShellcode), encryptedShellcode
	default:
		logger.Fatal("Unsupported encryption cipher")
		return "", 0, nil
	}
}
