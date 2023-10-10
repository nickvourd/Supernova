package Output

import (
	"Supernova/Utils"
	"fmt"
	"log"
	"os"
)

// SaveOutputToFile function
func SaveOutputToFile(outputData string, filename string) error {
	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the output data to the file
	_, err = file.WriteString(outputData)
	if err != nil {
		return err
	}

	// Call function named GetAbsolutePath
	absolutePath, err := Utils.GetAbsolutePath(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	fmt.Printf("[+] Save encrypted shellcode to " + absolutePath + "\n\n")
	return nil
}

// PrintKeyDetails function
func PrintKeyDetails(key []byte) {
	for i, b := range key {
		decimalValue := int(b)
		hexValue := fmt.Sprintf("%02x", b)
		fmt.Printf("byte(0x%s) => %d", hexValue, decimalValue)
		if i < len(key)-1 {
			fmt.Printf(", ")
		}
	}

	fmt.Printf("\n\n")
}

// KeyDetailsFormatter function
func KeyDetailsFormatter(key []byte) string {
	var formattedKey string
	for i, b := range key {
		hexValue := fmt.Sprintf("%02x", b)
		formattedKey += "0x" + hexValue
		if i < len(key)-1 {
			formattedKey += ", "
		}
	}
	return formattedKey
}

// DetectNotification function
func DetectNotification(key int) int {
	logger := log.New(os.Stderr, "[!] ", 0)
	keyNotification := 0
	switch key {
	case 16:
		keyNotification = 128
	case 24:
		keyNotification = 192
	case 32:
		keyNotification = 256
	default:
		logger.Fatal("Initial Error, valid AES key not found\n")
	}

	return keyNotification
}
