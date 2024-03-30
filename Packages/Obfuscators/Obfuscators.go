package Obfuscators

import (
	"Supernova/Packages/Converters"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

// LittleEndian function
func LittleEndian(slice []string) []string {
	newSlice := make([]string, len(slice))
	copy(newSlice, slice)
	for i := len(newSlice)/2 - 1; i >= 0; i-- {
		opp := len(newSlice) - 1 - i
		newSlice[i], newSlice[opp] = newSlice[opp], newSlice[i]
	}
	return newSlice
}

// GetSegment function
func GetSegment(segment []string, start, end int) string {
	if start >= len(segment) {
		return ""
	}
	if end > len(segment) {
		end = len(segment)
	}

	return strings.Join(LittleEndian(segment[start:end]), "")
}

// UUIDObfuscation function
func UUIDObfuscation(shellcode string) string {
	// Split the shellcode into hex pairs.
	hexPairs := strings.Split(shellcode, " ")

	var result []string
	var finalResult string

	// Iterate over the hex pairs in groups of 18.
	for i := 0; i < len(hexPairs); i += 18 {
		// Determine the end of the current group.
		end := i + 18
		if end > len(hexPairs) {
			end = len(hexPairs)
		}

		// Get the current group of hex pairs.
		segment := hexPairs[i:end]

		// Split the segment into five parts to form a UUID.
		segment1 := GetSegment(segment, 0, 4)
		segment2 := GetSegment(segment, 4, 6)
		segment3 := GetSegment(segment, 6, 8)
		segment4 := GetSegment(segment, 8, 10)
		segment5 := GetSegment(segment, 10, 16)

		// Append the formatted UUID to the result.
		result = append(result, fmt.Sprintf("\"%s-%s-%s-%s-%s\"", segment1, segment2, segment3, segment4, segment5))
	}

	// Call function named UUIDTrimmer
	result = Converters.UUIDTrimmer(result)

	// Join the result array into a single string.
	finalResult = strings.Join(result, ", ")

	return finalResult
}

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
func IPv6Obfuscation(shellcode string) ([]string, int, []string) {
	// Remove all spaces
	shellcode = strings.ReplaceAll(shellcode, " ", "")

	// Initialize the counter for the random hexadecimal values
	randomHexCount := 0
	var randomHexValues []string

	// Check if the length of the string is not a multiple of 32
	if len(shellcode)%32 != 0 {
		// Calculate the number of characters needed to make it a multiple of 32
		remaining := 32 - (len(shellcode) % 32)

		// Generate random hexadecimal values and append them to the shellcode
		for i := 0; i < remaining; i++ {
			randomHex := fmt.Sprintf("%X", rand.Intn(16))
			shellcode += strings.ToLower(randomHex)
			randomHexValues = append(randomHexValues, randomHex)
			randomHexCount++
		}
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
		parts[i] = "\"" + newPart + "\","
	}

	return parts, randomHexCount, randomHexValues
}

// IPv4Obfuscation function
func IPv4Obfuscation(shellcode string) string {
	// Arrays to store added numbers and their hexadecimal representations
	var addedNumbers []int
	var hexRepresentations []string

	// Variables eclaration
	var pronous string = "it"
	var pronousNum string = "number"
	var result string

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

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Loop until the length of chunkResult is equal to 4
	for len(chunkResult) < 4 {
		// Generate a random decimal from 0 to 255
		randomNumber := rand.Intn(256)

		// Convert decimal to hexadecimal
		randomHex := fmt.Sprintf("0x%X", randomNumber)

		// Convert the random number to a string
		randomString := fmt.Sprintf("%d", randomNumber)

		// Add the random number and its hexadecimal representation to arrays
		addedNumbers = append(addedNumbers, randomNumber)
		hexRepresentations = append(hexRepresentations, randomHex)

		// Add the random string to the slice
		chunkResult = append(chunkResult, randomString)
	}

	// Print the message with the count of added numbers and their details
	count := len(addedNumbers)

	// if count more than one
	if count > 1 {
		pronousNum = "numbers"
	}

	fmt.Printf("[+] Configure payload length evenly for IPv4 obfuscation by adding %d random %s:\n\n", count, pronousNum)

	// Iterate over each element and build the result string
	for i, num := range addedNumbers {
		hexRep := hexRepresentations[i]

		// Append the formatted string to the result
		if i < count-1 {
			result += fmt.Sprintf("%d => byte(%s), ", num, strings.ToLower(hexRep))
		} else {
			result += fmt.Sprintf("%d => byte(%s)", num, strings.ToLower(hexRep))
		}
	}

	fmt.Printf("	" + result + "\n\n")

	// if generated numbers are more than one
	if count > 1 {
		pronous = "them"
	}

	fmt.Printf("[!] Be sure to remove %s during the implementation process!\n\n", pronous)

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
	var hexString string
	var pronousChar string = "character"
	var pronous string = "it"

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
		obfuscatedShellcode, randomHexCount, randomHexValues := IPv6Obfuscation(shellcodeStr)

		// If count more than one
		if randomHexCount > 1 {
			pronousChar = "characters"
		}

		fmt.Printf("[+] Configure payload length evenly for IPv6 obfuscation by adding %d random %s:\n\n", randomHexCount, pronousChar)

		// Iterate over each character
		for i, char := range randomHexValues {
			// Convert the character to its hexadecimal representation
			hexValue := fmt.Sprintf("0x%X", char[0])

			// Append the hexadecimal representation to the string
			if i < len(randomHexValues)-1 {
				hexString += fmt.Sprintf("%s => byte(%s), ", strings.ToLower(char), strings.ToLower(hexValue))
			} else {
				hexString += fmt.Sprintf("%s => byte(%s)", strings.ToLower(char), strings.ToLower(hexValue))
			}
		}

		fmt.Printf("	" + hexString + "\n\n")

		// If count more than one
		if randomHexCount > 1 {
			pronous = "them"
		}

		fmt.Printf("[!] Be sure to remove %s during the implementation process!\n\n", pronous)

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
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		//Call function named UUIDObfuscation
		obfuscatedShellcodeString = UUIDObfuscation(shellcodeStr)
	default:
		logger.Fatal("Unsupported obfuscation technique")
	}

	return obfuscatedShellcodeString
}
