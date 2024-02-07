package Arguments

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// ArgumentLength function
func ArgumentLength(versionFlag bool) {
	logger := log.New(os.Stderr, "[!] ", 0)
	// if no arguments print help menu
	if len(os.Args) == 1 {
		fmt.Println("Usage of Suprenova.exe:")
		flag.PrintDefaults()
		os.Exit(0)
		// If arguments are more than 2
	} else if len(os.Args) > 2 {
		// if versionFlag is enabled
		if versionFlag {
			logger.Fatal("You cannot use the -version flag in conjunction with other arguments.")
		}
	}
}

// ShowVersion function
func ShowVersion(version string, versionFlag bool) {
	// if arguments are 2
	if len(os.Args) == 2 {
		// if versionFlag is enabled
		if versionFlag {
			fmt.Printf("[+] Current version: " + version + "\n\n")
			os.Exit(0)
		} else {
			fmt.Println("Usage of Suprenova.exe:")
			flag.PrintDefaults()
			os.Exit(0)
		}
	}
}

// ArgumentEmpty function
func ArgumentEmpty(statement string, option int) {
	if statement == "" {
		logger := log.New(os.Stderr, "[!] ", 0)
		switch option {
		case 1:
			logger.Fatal("Please provide a path to a file containing raw 64-bit shellcode.")
		case 2:
			logger.Fatal("Please provide a valid value for the programming language (e.g., C, CSharp, Rust, Nim, Go, Python).")
		default:
			logger.Fatal("Invalid option specified for ArgumentEmpty function.")
		}
	}
}

// ValidateArgument function
func ValidateArgument(argName string, argValue string, validValues []string) string {
	if strings.ToLower(argValue) == "golang" {
		argValue = "Go"
	}

	for _, valid := range validValues {
		if strings.EqualFold(strings.ToLower(argValue), strings.ToLower(valid)) {
			valid = strings.ToLower(valid)
			return valid
		}
	}

	fmt.Printf("[!] Invalid value '%s' for argument '%s'. Valid values are: %v\n", argValue, argName, validValues)
	os.Exit(1)
	return ""
}

// ValidateKeySize function
func ValidateKeySize(key int, encryption string) int {
	logger := log.New(os.Stderr, "[!] ", 0)
	if key <= 0 {
		logger.Fatal("Please provide a valid key value for the size...\n")
	}

	if strings.ToLower(encryption) == "aes" || strings.ToLower(encryption) == "b64aes" {
		switch key {
		case 128, 16:
			key = 16
		case 192, 24:
			key = 24
		case 256, 32:
			key = 32
		default:
			logger.Fatal("Provide a valid AES key:\n\nFor AES-128-CBC:\n\n-k 128 or -k 16\n\nFor AES-192-CBC:\n\n-k 192 or -k 24\n\nFor AES-256-CBC:\n\n-k 256 or -k 32\n\n")
		}
	}
	return key
}
