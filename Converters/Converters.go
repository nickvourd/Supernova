package Converters

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// ConvertShellcode2Hex
func ConvertShellcode2Hex(shellcode string, language string) (string, int) {
	// Convert raw shellcode to hexadecimal
	hexShellcode := hex.EncodeToString([]byte(shellcode))

	// Split hex shellcode into individual hex values
	hexValues := strings.Split(hexShellcode, "")

	var builder strings.Builder

	if language == "python" {
		for i := 0; i < len(hexValues); i += 2 {
			builder.WriteString("\\x")
			builder.WriteString(hexValues[i])
			builder.WriteString(hexValues[i+1])
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
	default:
		fmt.Println("[!] Unsupported programming language:", language)
		os.Exit(1)
		return ""
	}
}

// ConvertShellcode2String function
func ConvertShellcode2String(shellcodePath string) (string, error) {
	// Read the contents of the file into a byte slice
	fileContent, err := ioutil.ReadFile(shellcodePath)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a string
	rawShellcode := strings.TrimSpace(string(fileContent))

	return rawShellcode, nil
}

// FormatKeysToHex function
func FormatKeysToHex(byteArray []byte) string {
	var hexBytes []string
	for _, byteVal := range byteArray[:len(byteArray)-1] {
		hexBytes = append(hexBytes, fmt.Sprintf("0x%02x", byteVal))
	}
	hexBytes = append(hexBytes, fmt.Sprintf("0x%02x", byteArray[len(byteArray)-1]))

	return strings.Join(hexBytes, ", ")
}

// FormatShellcode function
func FormatShellcode(encryptedShellcode []byte, language string) string {
	var formattedShellcode []string
	var shellcodeFormatted string

	for _, b := range encryptedShellcode {
		if language == "python" {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("\\x%02x", b))
		} else {
			formattedShellcode = append(formattedShellcode, fmt.Sprintf("0x%02x", b))
		}
	}

	// Combine elements into a single string
	if language == "python" {
		shellcodeFormatted = strings.Join(formattedShellcode, "")
	} else {
		shellcodeFormatted = strings.Join(formattedShellcode, ", ")
	}

	return shellcodeFormatted
}

// AddValues2Template function
func AddValues2Template(operatingSystem string, template string) string {
	if strings.ToLower(operatingSystem) == "linux" || strings.ToLower(operatingSystem) == "windows" {
		template = "#include <Windows.h>" + template
	}

	return template
}

// CleanShellcodeString function
func CleanShellcodeString(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, ",", "")
	return s
}
