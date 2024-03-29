package Obfuscators

import (
	"Supernova/Packages/Converters"
	"fmt"
	"log"
	"os"
	"strings"
)

// MacObfuscation function
func MacObfuscation(shellcode string) string {
	// split the shellcode string by space separator
	split := strings.Split(shellcode, " ")

	// initialize an empty slice to store the resulting groups
	var result []string

	// iterate over the split shellcode with a step of 6
	for i := 0; i < len(split); i += 6 {
		// define the end index for the current group
		end := i + 6
		// if the end index exceeds the length of split, set it to the length of split
		if end > len(split) {
			end = len(split)
		}
		// create a group of up to 6 elements
		group := split[i:end]

		// if the group has less than 6 elements, join them with "-" and wrap each element in quotes
		if len(group) < 6 {
			result = append(result, fmt.Sprintf("\"%s\"", strings.Join(group, "-")))
		} else {
			// if the group has exactly 6 elements, join them with "-" and wrap each element in quotes
			result = append(result, fmt.Sprintf("\"%s-%s-%s-%s-%s-%s\"", group[0], group[1], group[2], group[3], group[4], group[5]))
		}
	}

	// join the resulting groups with ", " separator
	output := strings.Join(result, ", ")

	// trim any trailing ", \"-\"" from the output string
	output = strings.TrimSuffix(output, ", \"-\"")

	return output
}

// IPv6Obfuscation function
func IPv6Obfuscation(shellcode string) []string {
	// Remove all spaces
	shellcode = strings.ReplaceAll(shellcode, " ", "")

	// Check if the length of the string is less than 32
	if len(shellcode) < 32 {
		fmt.Println("[!] The input string is too short!")
		os.Exit(1)
		return nil
	}

	// Split the string every 32 characters
	var parts []string
	for i := 0; i < len(shellcode); i += 32 {
		// Check if there are enough characters left
		if i+32 > len(shellcode) {
			parts = append(parts, shellcode[i:])
			break
		}
		parts = append(parts, shellcode[i:i+32])
	}

	// Add ":" every four characters of 32, exclude the last four
	for i, part := range parts {
		var newPart string
		for j := 0; j < len(part)-4; j += 4 {
			newPart += part[j:j+4] + ":"
		}
		newPart += part[len(part)-4:]
		parts[i] = "\"" + newPart + "\", "
	}

	return parts
}

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
func DetectObfuscation(obfuscation string, shellcode []string) string {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)

	// Declare variables
	var obfuscatedShellcodeString string

	switch obfuscation {
	case "ipv4":
		// Call function named ShellcodeFromStringHex2Decimal
		shellcodeDecArray := Converters.ShellcodeFromStringHex2Decimal(shellcode)

		// Call function named ShellcodeDecimalArray2String
		shellcodeStr := Converters.ShellcodeDecimalArray2String(shellcodeDecArray)

		// Call function named IPv4Obfuscation
		obfuscatedShellcodeString = IPv4Obfuscation(shellcodeStr)
	case "ipv6":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		// Call function named IPv6Obfuscation
		obfuscatedShellcode := IPv6Obfuscation(shellcodeStr)

		// Add any part to a string
		for _, part := range obfuscatedShellcode {
			obfuscatedShellcodeString += part
		}

		// Remove comma
		obfuscatedShellcodeString = obfuscatedShellcodeString[:len(obfuscatedShellcodeString)-2]
	case "mac":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		// Call function named MacObfuscation
		obfuscatedShellcodeString = MacObfuscation(shellcodeStr)
	case "uuid":
		fmt.Println("UUID Hello")
	default:
		logger.Fatal("Unsupported obfuscation technique")
	}

	return obfuscatedShellcodeString
}
