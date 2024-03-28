package Obfuscators

import (
	"Supernova/Packages/Converters"
	"fmt"
	"log"
	"os"
	"strings"
)

// IPv4Obfuscation function
func IPv4Obfuscation(shellcode string) string {
	// Split the original string into chunks of four digits
	chunks := strings.Fields(shellcode)

	// Initialize an empty slice to store the chunkResult
	var chunkResult []string

	// Declare variables
	var shellcodeProperty string

	// Iterate over the chunks and add them to the chunkResult slice
	for i, chunk := range chunks {
		chunkResult = append(chunkResult, chunk)

		// Add a dot after every fourth chunk, except for the last chunk
		if (i+1)%4 == 0 && i != len(chunks)-1 {
			// Join the slice into a string with dots
			configResult := strings.Join(chunkResult, ".")
			shellcodeProperty += "\"" + configResult + "\", "
			chunkResult = chunkResult[:0] // Reset chunkResult slice for the next iteration
		}
	}

	// Join the last remaining elements into a string with dots
	configResult := strings.Join(chunkResult, ".")
	shellcodeProperty += "\"" + configResult + "\""

	return shellcodeProperty
}

// DetectObfuscation function
func DetectObfuscation(obfuscation string, shellcode []string) {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)
	switch obfuscation {
	case "ipv4":
		// Call function named ShellcodeFromStringHex2Decimal
		shellcodeDecArray := Converters.ShellcodeFromStringHex2Decimal(shellcode)

		// Call function named ShellcodeDecimalArray2String
		shellcodeStr := Converters.ShellcodeDecimalArray2String(shellcodeDecArray)

		// Call function named IPv4Obfuscation
		obfuscatedShellcodeString := IPv4Obfuscation(shellcodeStr)

		fmt.Println(obfuscatedShellcodeString)
	case "ipv6":
		fmt.Println("IPv6 Hello")
	case "mac":
		fmt.Println("MAC Hello")
	case "uuid":
		fmt.Println("UUID Hello")
	default:
		logger.Fatal("Unsupported obfuscation technique")
	}
}
