package Obfuscators

import (
	"Supernova/Packages/Colors"
	"Supernova/Packages/Converters"
	"fmt"
	"log"
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
			//randomHex := fmt.Sprintf("%02X", rand.Intn(240)+16)
			randomHex := "90"
			segment += strings.ToLower(randomHex)
			randomHexValues = append(randomHexValues, randomHex)
			totalRandomHexAdded++
		}
	}

	return segment, totalRandomHexAdded, randomHexValues
}

// UUIDObfuscation function creates a UUID string from shellcode.
func UUIDObfuscation(shellcode string) (string, int, []string) {
	// Split the shellcode into hex pairs.
	hexPairs := strings.Split(shellcode, " ")

	var randomHexCount int
	var randomHexValues []string
	var result []string
	var finalResult string

	// Iterate over the hex pairs in groups of 16.
	for i := 0; i < len(hexPairs); i += 16 {
		// Determine the end of the current group.
		end := i + 16
		if end > len(hexPairs) {
			end = len(hexPairs)
		}

		// Get the current group of hex pairs and join them into a single string.
		segment := strings.Join(hexPairs[i:end], "")

		// Ensure padding is correct.
		paddedSegment, randomHexAdded, addedValues := EnsureSegmentLength(segment, 32)
		randomHexCount += randomHexAdded
		randomHexValues = append(randomHexValues, addedValues...)

		// Split the padded segment back into hex pairs.
		reSegmented := make([]string, len(paddedSegment)/2)
		for j := 0; j < len(reSegmented); j++ {
			reSegmented[j] = paddedSegment[2*j : 2*j+2]
		}

		// Split the segment into five parts to form a UUID.
		segment1 := GetSegment(reSegmented, 0, 4)
		segment2 := GetSegment(reSegmented, 4, 6)
		segment3 := GetSegment(reSegmented, 6, 8)
		segment4 := GetSegmentNormal(reSegmented, 8, 10)
		segment5 := GetSegmentNormal(reSegmented, 10, 16)

		// Append the formatted UUID to the result.
		result = append(result, fmt.Sprintf("\"%s-%s-%s-%s-%s\"", segment1, segment2, segment3, segment4, segment5))
	}

	// Join the result array into a single string.
	finalResult = strings.Join(result, ", ")

	return finalResult, randomHexCount, randomHexValues
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
				//randomHex := fmt.Sprintf("%02X", rand.Intn(240)+16)
				randomHex := "90"
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
			//randomHex := fmt.Sprintf("%X", rand.Intn(240)+16)
			randomHex := "90"
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
func IPv4Obfuscation(shellcode string) (string, int, []string) {
	var hexRepresentations []string // contains decimal string values of added numbers (kept name for compatibility)
	var addedNumbers []int

	// split the input into tokens
	chunks := strings.Fields(shellcode)

	var chunkResult []string
	var sb strings.Builder
	prevLastOctet := "" // last octet of the last fully completed group

	// iterate tokens and form full groups of 4
	for _, token := range chunks {
		if token == "" {
			continue
		}
		chunkResult = append(chunkResult, token)

		if len(chunkResult) == 4 {
			// join and append as a quoted group
			if sb.Len() > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(`"` + strings.Join(chunkResult, ".") + `"`)

			// track the last octet of this completed group
			prevLastOctet = chunkResult[3]

			// reset for next group
			chunkResult = chunkResult[:0]
		}
	}

	// if nothing remains, return current result
	if len(chunkResult) == 0 {
		return sb.String(), 0, nil
	}

	// special rule:
	// if remainder is exactly one token "0" and the previous group's last octet was "0",
	// then do NOT append the padded final group
	if len(chunkResult) == 1 && chunkResult[0] == "0" && prevLastOctet == "0" {
		return sb.String(), 0, nil
	}

	// otherwise pad remainder to 4 with 90
	for len(chunkResult) < 4 {
		randomNumber := 90
		addedNumbers = append(addedNumbers, randomNumber)
		hexRepresentations = append(hexRepresentations, fmt.Sprintf("%d", randomNumber))
		chunkResult = append(chunkResult, fmt.Sprintf("%d", randomNumber))
	}

	// append final padded group
	if sb.Len() > 0 {
		sb.WriteString(", ")
	}
	sb.WriteString(`"` + strings.Join(chunkResult, ".") + `"`)

	return sb.String(), len(addedNumbers), hexRepresentations
}

// WordsObfuscation function
func WordsObfuscation(shellcode string) (string, map[string]string, int) {
	// Remove all spaces and convert to lowercase
	cleaned := strings.ToLower(strings.ReplaceAll(shellcode, " ", ""))

	// Create mapping of hex characters to random words
	charToWord := make(map[string]string)
	usedWords := make(map[string]bool)

	// Create unique mappings for each hex character
	for _, char := range cleaned {
		charStr := string(char)
		if _, exists := charToWord[charStr]; !exists {
			// Generate a unique random word
			var word string
			for {
				word = Converters.GenerateRandomWordSimple()
				if !usedWords[word] {
					usedWords[word] = true
					break
				}
			}
			charToWord[charStr] = word
		}
	}

	// Build the substituted string with commas and quotes
	var result strings.Builder

	for i, char := range cleaned {
		charStr := string(char)
		result.WriteString(`"`)
		result.WriteString(charToWord[charStr])
		result.WriteString(`"`)
		// Add comma after every word except the last one
		if i < len(cleaned)-1 {
			result.WriteString(", ")
		}
	}

	return result.String(), charToWord, len(charToWord)
}

// PrintWordsMapping prints the character to word mapping
func PrintWordsMapping(mapping map[string]string) {
	fmt.Println("[+] Character to Word Mapping:")
	// Print in sorted order for hex characters
	hexChars := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	for _, char := range hexChars {
		if word, exists := mapping[char]; exists {
			fmt.Printf("	%s => %s\n", Colors.BoldGreen(char), Colors.BoldRed(word))
		}
	}
	fmt.Println()
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
		obfuscatedShellcodeString, randomHexCount, randomHexValues := IPv4Obfuscation(shellcodeStr)

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

		// Call function named CountQuotedStrings
		countQuotedStrings := CountQuotedStrings(obfuscatedShellcodeString)

		// Print total elements
		fmt.Printf("[+] Total Elements: %s\n\n", Colors.BoldYellow(countQuotedStrings))

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

		// Call function named CountQuotedStrings
		countQuotedStrings := CountQuotedStrings(obfuscatedShellcodeString)

		// Print total elements
		fmt.Printf("[+] Total Elements: %s\n\n", Colors.BoldYellow(countQuotedStrings))

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

		// Call function named CountQuotedStrings
		countQuotedStrings := CountQuotedStrings(obfuscatedShellcodeString)

		// Print total elements
		fmt.Printf("[+] Total Elements: %s\n\n", Colors.BoldYellow(countQuotedStrings))

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

		// Call function named CountQuotedStrings
		countQuotedStrings := CountQuotedStrings(obfuscatedShellcodeString)

		// Print total elements
		fmt.Printf("[+] Total Elements: %s\n\n", Colors.BoldYellow(countQuotedStrings))

		return obfuscatedShellcodeString
	case "words":
		// Call function named ConvertShellcodeHex2String
		shellcodeStr := Converters.ConvertShellcodeHex2String(shellcode)

		// Call function named WordsObfuscation
		obfuscatedShellcodeString, mapping, uniqueChars := WordsObfuscation(shellcodeStr)

		// Print the mapping
		fmt.Printf("[+] Generated %s unique words for hex characters (0-9, a-f)\n\n", Colors.BoldYellow(uniqueChars))
		PrintWordsMapping(mapping)

		// Count total words
		wordCount := len(strings.Fields(obfuscatedShellcodeString))
		fmt.Printf("[+] Total Words: %s\n\n", Colors.BoldYellow(wordCount))

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

	fmt.Printf("[+] Configure payload length evenly for %s obfuscation by adding %d NOP %s:\n\n", strings.ToUpper(obfuscation), randomHexCount, pronousChar)

	// Iterate over each character
	for i, char := range randomHexValues {
		// Convert the character to lowercase and append it to hexString
		hexString += Colors.BoldRed(strings.ToLower(char))

		// Add a comma and space if it's not the last element
		if i < len(randomHexValues)-1 {
			hexString += ", "
		}
	}

	fmt.Print("	" + hexString + "\n\n")

	//fmt.Printf("[!] Be sure to remove %s during the implementation process!\n\n", pronous)
}

// CountQuotedStrings function
func CountQuotedStrings(input string) int {
	// Count commas and add 1
	count := strings.Count(input, ",") + 1
	return count
}
