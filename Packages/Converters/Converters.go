package Converters

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

// consonants and vowels for generating pronounceable words
var consonants = []string{"b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "x", "z"}
var vowels = []string{"a", "e", "i", "o", "u"}

// prefixes and suffixes for more variety
var prefixes = []string{"", "st", "pr", "tr", "br", "cr", "dr", "fr", "gr", "bl", "cl", "fl", "gl", "pl", "sl"}
var suffixes = []string{"", "ed", "er", "ing", "ly", "tion", "ness", "ful", "less"}

// UUIDTrimmer function
func UUIDTrimmer(uuidShellcode []string) []string {
	// Process each UUID in the slice
	for i, uuid := range uuidShellcode {
		// Check if this is the last UUID in the slice
		if i == len(uuidShellcode)-1 {
			// Developer's debug
			// fmt.Println("Before:", uuid)

			// Repeat the replacement until there are no more trailing hyphens after characters
			for strings.HasSuffix(uuid, "-\"") {
				uuid = strings.Replace(uuid, "-\"", "\"", 1)
			}

			// Update the last UUID in the slice
			uuidShellcode[i] = uuid

			// Developer's debug
			//fmt.Println("After:", uuidShellcode[i]) // Print the updated UUID
		}
	}

	// Check if the last element is only hyphens
	lastElement := uuidShellcode[len(uuidShellcode)-1]
	//fmt.Println(lastElement)
	if lastElement == "\"\"" {
		// If yes, remove the last element
		uuidShellcode = uuidShellcode[:len(uuidShellcode)-1]
		// Developer's debug
		//fmt.Println(uuidShellcode[len(uuidShellcode)-1])
	}

	return uuidShellcode
}

// ConvertShellcodeHex2String function
func ConvertShellcodeHex2String(shellcode []string) string {
	// Variable declaration
	var formattedShellcode string

	// Join hexadecimal strings into one string with space after every two characters
	for _, hexStr := range shellcode {
		formattedShellcode += hexStr + " "
	}

	return formattedShellcode
}

// ConvertShellcode2String function
func ConvertShellcode2String(shellcodePath string) (string, error) {
	// Read the contents of the file into a byte slice
	fileContent, err := os.ReadFile(shellcodePath)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a string
	rawShellcode := strings.TrimSpace(string(fileContent))

	return rawShellcode, nil
}

// ConvertShellcode2Hex function
func ConvertShellcode2Hex(shellcode string, language string) (string, int) {
	// Convert raw shellcode to hexadecimal
	hexShellcode := hex.EncodeToString([]byte(shellcode))

	// Split hex shellcode into individual hex values
	hexValues := strings.Split(hexShellcode, "")

	var builder strings.Builder

	// Format and add "\x" in front of each pair of hex characters
	switch language {
	case "python", "perl", "ruby":
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("\\x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
		}
	case "java":
		// Format and add "(byte) 0x" in front of each pair of hex characters
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("(byte) 0x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
			if i < len(hexValues)-2 {
				builder.WriteString(", ")
			}
		}
	default:
		// Format and add "0x" in front of each pair of hex characters
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("0x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
			if i < len(hexValues)-2 {
				builder.WriteString(", ")
			}
		}
	}

	formattedHexShellcode := builder.String()

	// Calculate shellcode size in bytes
	shellcodeSize := len(shellcode)

	return formattedHexShellcode, shellcodeSize
}

// ConvertShellcode2Template function
func ConvertShellcode2Template(shellcode string, language string, length int, variable string) string {
	switch language {
	case "c":
		template := fmt.Sprintf(`unsigned char %s[] = {%s};`, variable, shellcode)
		return template
	case "csharp":
		template := fmt.Sprintf(`byte[] %s = new byte[%d] {%s};`, variable, length, shellcode)
		return template
	case "nim":
		template := fmt.Sprintf(`var %s: array[%d, byte] = [byte %s]`, variable, length, shellcode)
		return template
	case "rust":
		template := fmt.Sprintf(`let %s: [u8; %d] = [%s];`, variable, length, shellcode)
		return template
	case "go":
		template := fmt.Sprintf(`%s := []byte{%s};`, variable, shellcode)
		return template
	case "python":
		template := fmt.Sprintf(`%s = b"%s"`, variable, shellcode)
		return template
	case "raw":
		return shellcode
	case "powershell":
		template := fmt.Sprintf(`[Byte[]] $%s = %s`, variable, shellcode)
		return template
	case "perl":
		template := fmt.Sprintf(`my $%s = "%s";`, variable, shellcode)
		return template
	case "vba":
		template := fmt.Sprintf(`%s = Array(%s)`, variable, shellcode)
		return template
	case "ruby":
		template := fmt.Sprintf(`%s = "%s"`, variable, shellcode)
		return template
	case "java":
		template := fmt.Sprintf(`byte %s[] = new byte {%s};`, variable, shellcode)
		return template
	default:
		fmt.Println("[!] Unsupported programming language:", language)
		os.Exit(1)
		return ""
	}
}

// FormatShellcode function
func FormatShellcode(encryptedShellcode []byte, language string) string {
	var formattedShellcode []string
	var shellcodeFormatted string

	for counter, b := range encryptedShellcode {
		switch language {
		case "python", "perl", "ruby":
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("\\x%02x", b))
		case "java":
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("(byte) 0x%02x", b))
			// Respect VBAs string length limit
		case "vba":
			if (counter%50) == 0 && counter > 0 {
				formattedShellcode = append(formattedShellcode, fmt.Sprintf("_\n%d", b))
			} else {
				formattedShellcode = append(formattedShellcode, fmt.Sprintf("%d", b))
			}
		default:
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("0x%02x", b))
		}
	}

	// Combine elements into a single string
	if language == "python" || language == "perl" || language == "ruby" {
		shellcodeFormatted = strings.Join(formattedShellcode, "")
	} else {
		shellcodeFormatted = strings.Join(formattedShellcode, ", ")
	}

	return shellcodeFormatted
}

// CleanShellcodeString function
func CleanShellcodeString(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, ",", "")
	return s
}

// ShellcodeFromByte2String function
// Function to convert byte array to string representation
func ShellcodeFromByte2String(shellcode []byte) string {
	var builder strings.Builder
	for _, b := range shellcode {
		builder.WriteString(fmt.Sprintf("%02x ", b))
	}
	return builder.String()
}

// hexToDecimal function
// Function to convert array of hexadecimal strings to decimal integers
func ShellcodeFromStringHex2Decimal(shellcode []string) []int {
	decArray := make([]int, len(shellcode))
	for i, hexStr := range shellcode {
		decVal, _ := strconv.ParseInt(hexStr, 16, 64)
		decArray[i] = int(decVal)
	}
	return decArray
}

// ShellcodeDecimalArray2String function
// Function to convert a array of decimal to strings
func ShellcodeDecimalArray2String(decArray []int) string {
	// Create an empty string
	str := ""

	// Iterate over each decimal value in the array
	for _, dec := range decArray {
		// Convert the decimal value to string and append it to the string with a space
		str += strconv.Itoa(dec) + " "
	}

	// Trim any trailing space and return the resulting string
	return strings.TrimSpace(str)
}

// ConvertObfShellcode2Template function
func ConvertObfShellcode2Template(shellcode string, language string, variable string) string {
	switch language {
	case "c":
		template := fmt.Sprintf(`char* %s[] = {%s};`, variable, shellcode)
		return template
	case "csharp":
		template := fmt.Sprintf(`string[] %s = new string[] {%s};`, variable, shellcode)
		return template
	case "nim":
		template := fmt.Sprintf(`var %s = [%s]`, variable, shellcode)
		return template
	case "rust":
		template := fmt.Sprintf(`let %s = [%s];`, variable, shellcode)
		return template
	case "go":
		template := fmt.Sprintf(`%s := [...]string{%s}`, variable, shellcode)
		return template
	case "python":
		template := fmt.Sprintf(`%s = [%s]`, variable, shellcode)
		return template
	case "raw":
		return shellcode
	case "powershell":
		template := fmt.Sprintf(`$%s = @(%s)`, variable, shellcode)
		return template
	case "perl":
		template := fmt.Sprintf(`my @%s = (%s);`, variable, shellcode)
		return template
	case "ruby":
		template := fmt.Sprintf(`%s = [%s]`, variable, shellcode)
		return template
	case "java":
		template := fmt.Sprintf(`String[] %s = {%s};`, variable, shellcode)
		return template
	case "vba":
		template := fmt.Sprintf(`%s = Array(%s)`, variable, shellcode)
		return template
	default:
		fmt.Println("[!] Unsupported programming language:", language)
		os.Exit(1)
		return ""
	}
}

// getRandomElement returns a random element from a string slice
func getRandomElement(slice []string) string {
	max := big.NewInt(int64(len(slice)))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return slice[0]
	}
	return slice[n.Int64()]
}

// generateRandomInt generates a random integer between min and max
func generateRandomInt(min, max int) int {
	diff := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return min
	}
	return int(n.Int64()) + min
}

// GenerateRandomWord generates a random pronounceable word
func GenerateRandomWord() string {
	var word strings.Builder

	// Random word length between 4-8 characters
	length := generateRandomInt(4, 8)

	// Start with consonant or vowel randomly
	startWithVowel := generateRandomInt(0, 1) == 0

	for i := 0; i < length; i++ {
		if (i%2 == 0 && !startWithVowel) || (i%2 == 1 && startWithVowel) {
			// Add consonant
			word.WriteString(getRandomElement(consonants))
		} else {
			// Add vowel
			word.WriteString(getRandomElement(vowels))
		}
	}

	return word.String()
}

// GenerateRandomWordWithPattern generates a more complex random word
// Uses patterns like: prefix + consonant-vowel pairs + suffix
func GenerateRandomWordWithPattern() string {
	var word strings.Builder

	// Optionally add prefix (30% chance)
	if generateRandomInt(0, 9) < 3 {
		word.WriteString(getRandomElement(prefixes))
	}

	// Add 2-3 consonant-vowel pairs
	pairs := generateRandomInt(2, 3)
	for i := 0; i < pairs; i++ {
		word.WriteString(getRandomElement(consonants))
		word.WriteString(getRandomElement(vowels))
	}

	// Optionally add suffix (20% chance)
	if generateRandomInt(0, 9) < 2 {
		word.WriteString(getRandomElement(suffixes))
	}

	return word.String()
}

// GenerateRandomWordSimple generates simple 4-6 letter pronounceable words
func GenerateRandomWordSimple() string {
	var word strings.Builder

	// Pattern: consonant-vowel-consonant-vowel or consonant-vowel-consonant-vowel-consonant
	length := generateRandomInt(2, 3) // 2 or 3 pairs

	for i := 0; i < length; i++ {
		word.WriteString(getRandomElement(consonants))
		word.WriteString(getRandomElement(vowels))
	}

	// 50% chance to add final consonant
	if generateRandomInt(0, 1) == 0 {
		word.WriteString(getRandomElement(consonants))
	}

	return word.String()
}

// ShellcodeToWordSubstitution converts shellcode hex to word substitution
// Each unique hex character gets a unique random word generated on the fly
func ShellcodeToWordSubstitution(shellcode string) (string, map[string]string) {
	// Remove all spaces and convert to lowercase
	cleaned := strings.ToLower(strings.ReplaceAll(shellcode, " ", ""))

	// Create mapping of hex characters to random words
	charToWord := make(map[string]string)
	usedWords := make(map[string]bool)

	// First pass: create unique mappings
	for _, char := range cleaned {
		charStr := string(char)
		if _, exists := charToWord[charStr]; !exists {
			// Generate a unique random word
			var word string
			for {
				word = GenerateRandomWordSimple() // or use GenerateRandomWord() or GenerateRandomWordWithPattern()
				if !usedWords[word] {
					usedWords[word] = true
					break
				}
			}
			charToWord[charStr] = word
		}
	}

	// Second pass: build the substituted string
	var result strings.Builder
	for i, char := range cleaned {
		charStr := string(char)
		result.WriteString(charToWord[charStr])
		if i < len(cleaned)-1 {
			result.WriteString(" ")
		}
	}

	return result.String(), charToWord
}

// ShellcodeToWordSubstitutionArray converts shellcode hex to word substitution array
// Returns slice of words instead of string
func ShellcodeToWordSubstitutionArray(shellcode string) ([]string, map[string]string) {
	// Remove all spaces and convert to lowercase
	cleaned := strings.ToLower(strings.ReplaceAll(shellcode, " ", ""))

	// Create mapping of hex characters to random words
	charToWord := make(map[string]string)
	usedWords := make(map[string]bool)

	// First pass: create unique mappings
	for _, char := range cleaned {
		charStr := string(char)
		if _, exists := charToWord[charStr]; !exists {
			// Generate a unique random word
			var word string
			for {
				word = GenerateRandomWordSimple()
				if !usedWords[word] {
					usedWords[word] = true
					break
				}
			}
			charToWord[charStr] = word
		}
	}

	// Second pass: build the substituted array
	result := make([]string, len(cleaned))
	for i, char := range cleaned {
		charStr := string(char)
		result[i] = charToWord[charStr]
	}

	return result, charToWord
}

// WordSubstitutionToShellcode reverses the word substitution back to shellcode
func WordSubstitutionToShellcode(wordString string, mapping map[string]string) string {
	// Create reverse mapping (word -> hex char)
	wordToChar := make(map[string]string)
	for char, word := range mapping {
		wordToChar[word] = char
	}

	// Split the word string
	words := strings.Fields(wordString)

	// Build shellcode
	var result strings.Builder
	for i, word := range words {
		if char, exists := wordToChar[word]; exists {
			result.WriteString(char)
		}
		// Add space every 2 characters (every byte)
		if i%2 == 1 && i < len(words)-1 {
			result.WriteString(" ")
		}
	}

	return result.String()
}

// PrintMapping prints the character to word mapping
func PrintMapping(mapping map[string]string) {
	fmt.Println("\n[+] Character to Word Mapping:")
	// Print in sorted order for hex characters
	hexChars := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	for _, char := range hexChars {
		if word, exists := mapping[char]; exists {
			fmt.Printf("    '%s' => '%s'\n", char, word)
		}
	}
}
