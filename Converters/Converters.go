package Converters

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// ConvertShellcode2Hex
func ConvertShellcode2Hex(shellcode string, language string) string {
	// Convert raw shellcode to hexadecimal
	hexShellcode := hex.EncodeToString([]byte(shellcode))

	// Split hex shellcode into individual hex values
	hexValues := strings.Split(hexShellcode, "")

	formattedHexShellcode := ""

	if language == "c" {
		// Format and add "\\x" in front of each pair of hex characters
		for i := 0; i < len(hexValues); i += 2 {
			formattedHexShellcode += "\\x" + hexValues[i] + hexValues[i+1]
		}

	} else {
		// Format and add "0x" in front of each pair of hex characters
		for i := 0; i < len(hexValues); i += 2 {
			formattedHexShellcode += "0x" + hexValues[i] + hexValues[i+1]
			if i < len(hexValues)-2 {
				formattedHexShellcode += ", "
			}
		}
	}

	return formattedHexShellcode
}

// ConvertShellcode2Template function
func ConvertShellcode2Template(shellcode string, language string) {
	switch language {
	case "nim":
		fmt.Println(language)
	case "rust":
		fmt.Println(language)
	case "c":
		fmt.Println(language)
	case "csharp":
		fmt.Println(language)
	default:
		fmt.Println("[!] Unsupported programming language:", language)
		os.Exit(1)
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
