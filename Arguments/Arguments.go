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
		if versionFlag != false {
			logger.Fatal("You cannot use the -version flag in conjunction with other arguments.")
		}
	}
}

// ShowVersion function
func ShowVersion(version string, versionFlag bool) {
	// if arguments are 2
	if len(os.Args) == 2 {
		// if versionFlag is enabled
		if versionFlag != false {
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
			logger.Fatal("Please provide a valid value for the programming language (e.g., C++, CSharp, Rust, Nim).")
		case 3:
			logger.Fatal("Please provide a valid value for the encryption (e.g., ROT, XOR, RC4, AES).")
		default:
			logger.Fatal("Invalid option specified for ArgumentEmpty function.")
		}
	}
}

// ValidateArgument function
func ValidateArgument(argName string, argValue string, validValues []string) string {
	for _, valid := range validValues {
		if strings.ToLower(argValue) == strings.ToLower(valid) {
			valid = strings.ToLower(valid)
			return valid
		}
	}
	fmt.Printf("[!] Invalid value '%s' for argument '%s'. Valid values are: %v\n", argValue, argName, validValues)
	os.Exit(1)
	return ""
}

// ValidateKeySize function
func ValidateKeySize(key int, encryption string) {
	logger := log.New(os.Stderr, "[!] ", 0)
	if key <= 0 {
		logger.Fatal("Please provide a valid key value for the size...\n")
	}

	if encryption == "aes" {
		if key > 1 {
			logger.Fatal("The AES cipher does not require a separate 'key' argument. It employs a standard key length of 32-byte. Please remove it...\n")
		}
	}
}
