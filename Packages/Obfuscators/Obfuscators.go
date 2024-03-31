package Obfuscators

import (
	"Supernova/Packages/Colors"
	"Supernova/Packages/Converters"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
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

// GetSegmentNormal function (without LittleEndian)
func GetSegmentNormal(segment []string, start, end int) string {
	if start >= len(segment) {
		return ""
	}

	if end > len(segment) {
		end = len(segment)
	}

	return strings.Join(segment[start:end], "")
}

// EnsureSegmentLength function
// EnsureSegmentLength checks if a segment has the desired length and appends random hex if needed
func EnsureSegmentLength(segment string, desiredLength int) (string, int, []string) {
	// Declare variables
	var randomHexValues []string
	totalRandomHexAdded := 0

	if len(segment) < desiredLength {
		// Append random hex values until the segment reaches the desired length
		for len(segment) < desiredLength {
			randomHex := fmt.Sprintf("%02X", rand.Intn(240)+16)
			segment += strings.ToLower(randomHex)
			randomHexValues = append(randomHexValues, randomHex)
			totalRandomHexAdded++
		}
	}
	return segment, totalRandomHexAdded, randomHexValues
}

// UUIDObfuscation function
func UUIDObfuscation(shellcode string) (string, int, []string) {
	// Split the shellcode into hex pairs.
	hexPairs := strings.Split(shellcode, " ")

	// Initialize a counter for the random hex values
	var randomHexCount1, randomHexCount2, randomHexCount3, randomHexCount4, randomHexCount5 int
	var randomHexValues1, randomHexValues2, randomHexValues3, randomHexValues4, randomHexValues5 []string
	var result []string
	var nonEmptyStrings []string
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
		segment4 := GetSegmentNormal(segment, 8, 10)
		segment5 := GetSegmentNormal(segment, 10, 16)

		// Ensure each segment has the desired length
		segment1, randomHexCount1, randomHexValues1 = EnsureSegmentLength(segment1, 8)
		segment2, randomHexCount2, randomHexValues2 = EnsureSegmentLength(segment2, 4)
		segment3, randomHexCount3, randomHexValues3 = EnsureSegmentLength(segment3, 4)
		segment4, randomHexCount4, randomHexValues4 = EnsureSegmentLength(segment4, 4)
		segment5, randomHexCount5, randomHexValues5 = EnsureSegmentLength(segment5, 12)

		// Append the formatted UUID to the result.
		result = append(result, fmt.Sprintf("\"%s-%s-%s-%s-%s\"", segment1, segment2, segment3, segment4, segment5))
	}

	// Sum of counters
	TotalCounter := randomHexCount1 + randomHexCount2 + randomHexCount3 + randomHexCount4 + randomHexCount5

	// Function to filter out empty strings and append non-empty ones
	filterAndAppend := func(arr []string) {
		for _, s := range arr {
			if s != "" {
				nonEmptyStrings = append(nonEmptyStrings, s)
			}
		}
	}

	// Apply the filterAndAppend function to each array
	filterAndAppend(randomHexValues1)
	filterAndAppend(randomHexValues2)
	filterAndAppend(randomHexValues3)
	filterAndAppend(randomHexValues4)
	filterAndAppend(randomHexValues5)

	// Call function named UUIDTrimmer
	result = Converters.UUIDTrimmer(result)

	// Join the result array into a single string.
	finalResult = strings.Join(result, ", ")

	return finalResult, TotalCounter, nonEmptyStrings
}

// MacObfuscation function
func MacObfuscation(shellcode string) (string, int, []string) {
	// Trim leading and trailing spaces from the shellcode string
	shellcode = strings.TrimSpace(shellcode)

	// Split the shellcode string by space separator
	split := strings.Split(shellcode, " ")

	// Initialize an empty slice to store the resulting groups
	var result []string

	// Initialize a counter for the random hex values
	var randomHexCount int
	var randomHexValues []string

	// Iterate over the split shellcode with a step of 6
	for i := 0; i < len(split); i += 6 {
		// Define the end index for the current group
		end := i + 6
		// If the end index exceeds the length of split, set it to the length of split
		if end > len(split) {
			end = len(split)
		}
		// Create a group of up to 6 elements
		group := split[i:end]

		// If the group has less than 6 elements, generate and append random hex values
		if len(group) < 6 {
			// Generate and append random hex values to the group
			for j := len(group); j < 6; j++ {
				randomHex := fmt.Sprintf("%02X", rand.Intn(240)+16)
				group = append(group, strings.ToLower(randomHex))
				randomHexValues = append(randomHexValues, randomHex)
				randomHexCount++
			}
		}

		// Join the elements of the group with "-" separator and wrap each element in quotes
		result = append(result, fmt.Sprintf("\"%s-%s-%s-%s-%s-%s\"", group[0], group[1], group[2], group[3], group[4], group[5]))
	}

	// Join the resulting groups with ", " separator
	output := strings.Join(result, ", ")

	return output, randomHexCount, randomHexValues
}

// IPv6Obfuscation function
func IPv6Obfuscation(shellcode string) ([]string, int, []string) {
	// Remove all spaces
	shellcode = strings.ReplaceAll(shellcode, " ", "")

	// Initialize the counter for the random hexadecimal values
	randomHexCount := 0

	// Declare string array
	var randomHexValues []string

	// Check if the length of the string is not a multiple of 32
	if len(shellcode)%32 != 0 {
		// Calculate the number of characters needed to make it a multiple of 32
		remaining := 32 - (len(shellcode) % 32)

		// Generate random hexadecimal values and append them to the shellcode
		for i := 0; i < remaining; i = i + 2 {
			randomHex := fmt.Sprintf("%X", rand.Intn(240)+16)
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

	if count > 0 {
		fmt.Printf("[+] Configure payload length evenly for IPv4 obfuscation by adding %d random %s:\n\n", count, pronousNum)

		// Iterate over each element and build the result string
		for i, num := range addedNumbers {
			hexRep := hexRepresentations[i]

			// Append the formatted string to the result
			if i < count-1 {
				result += fmt.Sprintf(Colors.BoldRed("%d "), num)
				result += fmt.Sprintf("=> byte(%s)", Colors.BoldMagneta(strings.ToLower(hexRep)))
				result += ", "
			} else {
				result += fmt.Sprintf(Colors.BoldRed("%d "), num)
				result += fmt.Sprintf("=> byte(%s)", Colors.BoldMagneta(strings.ToLower(hexRep)))
			}
		}

		fmt.Printf("	" + result + "\n\n")

		// if generated numbers are more than one
		if count > 1 {
			pronous = "them"
		}

		fmt.Printf("[!] Be sure to remove %s during the implementation process!\n\n", pronous)
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
	var pronousChar string = "byte"
	var pronous string = "it"

	switch obfuscation {
	case "ipv4":
		// Call function named ShellcodeFromStringHex2Decimal
		shellcodeDecArray := Converters.ShellcodeFromStringHex2Decimal(shellcode)

		// Call function named ShellcodeDecimalArray2String
		shellcodeStr := Converters.ShellcodeDecimalArray2String(shellcodeDecArray)

		// Call function named IPv4Obfuscation
		obfuscatedShellcodeString = IPv4Obfuscation(shellcodeStr)

		return obfuscatedShellcodeString
	case "ipv6":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		// Call function named IPv6Obfuscation
		obfuscatedShellcode, randomHexCount, randomHexValues := IPv6Obfuscation(shellcodeStr)

		// if count more than zero
		if randomHexCount > 0 {
			// if count more than one
			if randomHexCount > 1 {
				pronousChar = "bytes"
				pronous = "them"
			}

			// Call function named CustomPayloadMessage
			CustomPayloadMessage(obfuscation, randomHexCount, randomHexValues, pronous, pronousChar)
		}

		// Add any part to a string
		for _, part := range obfuscatedShellcode {
			obfuscatedShellcodeString += part
		}

		// Remove comma
		obfuscatedShellcodeString = obfuscatedShellcodeString[:len(obfuscatedShellcodeString)-1]

		return obfuscatedShellcodeString
	case "mac":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		// Call function named MacObfuscation
		obfuscatedShellcodeString, randomHexCount, randomHexValues := MacObfuscation(shellcodeStr)

		// if count more than zero
		if randomHexCount > 0 {
			// if count more than one
			if randomHexCount > 1 {
				pronousChar = "bytes"
				pronous = "them"
			}

			// Call function named CustomPayloadMessage
			CustomPayloadMessage(obfuscation, randomHexCount, randomHexValues, pronous, pronousChar)
		}

		return obfuscatedShellcodeString
	case "uuid":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		//Call function named UUIDObfuscation
		obfuscatedShellcodeString, randomHexCount, randomHexValues := UUIDObfuscation(shellcodeStr)

		// if count more than zero
		if randomHexCount > 0 {
			// if count more than one
			if randomHexCount > 1 {
				pronousChar = "bytes"
				pronous = "them"
			}

			// Call function named CustomPayloadMessage
			CustomPayloadMessage(obfuscation, randomHexCount, randomHexValues, pronous, pronousChar)
		}

		return obfuscatedShellcodeString
	default:
		logger.Fatal("Unsupported obfuscation technique")
		return ""
	}
}

// CustomPayloadMessage function
func CustomPayloadMessage(obfuscation string, randomHexCount int, randomHexValues []string, pronous string, pronousChar string) {
	// Declare variables
	var hexString string

	fmt.Printf("[+] Configure payload length evenly for %s obfuscation by adding %d random %s:\n\n", obfuscation, randomHexCount, pronousChar)

	// Iterate over each character
	for i, char := range randomHexValues {
		// Convert the character to lowercase and append it to hexString
		hexString += Colors.BoldRed(strings.ToLower(char))

		// Add a comma and space if it's not the last element
		if i < len(randomHexValues)-1 {
			hexString += ", "
		}
	}

	fmt.Printf("	" + hexString + "\n\n")

	fmt.Printf("[!] Be sure to remove %s during the implementation process!\n\n", pronous)

}
