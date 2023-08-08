package Converter

import (
	"fmt"
)

// ConvertShellcode2Template function
func ConvertShellcode2Template(shellcode string, language string) {
	switch language {
	case "nim":
		fmt.Println(language)
	case "rust":
		fmt.Println(language)
	case "c":
		fmt.Println(language)
	case "c#":
		fmt.Println(language)
	default:
		fmt.Println("[!] Unsupported programming language:", language)
	}
}
