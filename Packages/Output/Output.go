package Output

import (
	"Supernova/Packages/Colors"
	"Supernova/Packages/Converters"
	"Supernova/Packages/Utils"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// PrintKeyDetails function
func PrintKeyDetails(key []byte) {
	for i, b := range key {
		var asciiValue string
		decimalValue := int(b)
		hexValue := fmt.Sprintf("0x%02x", b)

		// Determine ASCII value if printable
		if b >= 32 && b <= 126 { // Printable ASCII range
			asciiValue = string(b)
			fmt.Printf("byte(%s) => %s => %s", Colors.BoldRed(hexValue), Colors.BoldMagneta(strconv.Itoa(decimalValue)), Colors.BoldGreen(asciiValue))
		} else {
			// Non-printable character, only show hex and decimal
			fmt.Printf("byte(%s) => %s", Colors.BoldRed(hexValue), Colors.BoldMagneta(strconv.Itoa(decimalValue)))
		}

		if i < len(key)-1 {
			fmt.Printf(", ")
		}
	}

	fmt.Printf("\n\n")
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

// SaveOutputToFile function
func SaveOutputToFile(outputData string, filename string, statement bool, process string) error {
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
		fmt.Println("[!] Error:", err)
		return err
	}

	//fmt.Println(statement)
	if statement {
		fmt.Printf("[+] The %s shellcode saved to %s file.\n\n", strings.ToLower(process), absolutePath)
	} else {
		fmt.Print("[+] The obfuscated shellcode saved to " + absolutePath + " file.\n\n")
	}

	return nil
}

// SaveShellcodeToFile function
func SaveShellcodeToFile(shellcode, filename string, process string) error {
	// Removes Spaces and the "0x" prefix from the string
	shellcode = Converters.CleanShellcodeString(shellcode)

	// Decodes shellcode string into byte array
	data, err := hex.DecodeString(shellcode)
	if err != nil {
		fmt.Println("Error decoding shellcode: ", err)
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file: ", err)
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		fmt.Println("Error writing to file: ", err)
		return err
	}

	absolutePath, err := Utils.GetAbsolutePath(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	fmt.Printf("[+] The %s shellcode saved to %s file.\n\n", strings.ToLower(process), absolutePath)
	return nil
}
