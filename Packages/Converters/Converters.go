package Converters

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
	if language == "python" || language == "perl" || language == "c" || language == "ruby" {
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("\\x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
		}
	} else if language == "java" {
		// Format and add "(byte) 0x" in front of each pair of hex characters
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("(byte) 0x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
			if i < len(hexValues)-2 {
				builder.WriteString(", ")
			}
		}
	} else {
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
		template := fmt.Sprintf(`unsigned char %s[] = "%s";`, variable, shellcode)
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

	for _, b := range encryptedShellcode {
		if language == "python" || language == "perl" || language == "c" || language == "ruby" {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("\\x%02x", b))
		} else if language == "java" {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("(byte) 0x%02x", b))
		} else {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("0x%02x", b))
		}
	}

	// Combine elements into a single string
	if language == "python" || language == "perl" || language == "c" || language == "ruby" {
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
		template := fmt.Sprintf(`char *%s[] = {%s};`, variable, shellcode)
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
	default:
		fmt.Println("[!] Unsupported programming language:", language)
		os.Exit(1)
		return ""
	}
}
