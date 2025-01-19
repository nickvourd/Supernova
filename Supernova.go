package main

import (
	"Supernova/Packages/Arguments"
	"Supernova/Packages/Colors"
	"Supernova/Packages/Converters"
	"Supernova/Packages/Manager"
	"Supernova/Packages/Utils"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// main function
func main() {
	// Declare variables
	var template string
	var encryptedShellcode []byte
	var shellcode []byte
	var processType string
	var processVerb string

	// Call function named PrintAscii
	Arguments.PrintAscii()

	// Call function named CheckGoVersion
	Utils.CheckGoVersion()

	// Parsing command line flags
	options := Arguments.Options()

	// Call function named ArgumentLength
	Arguments.ArgumentLength(options.Version)

	// Call function named ArgumentEmpty
	Arguments.ArgumentEmpty(options.InputFile, 1)

	// Call function named ShellcodeSizeValidation
	fileSizeFlag := Arguments.ShellcodeSizeValidation(options.InputFile)

	// If fileSizeFlag is true
	if fileSizeFlag {
		// Call function named ArgumentEmpty
		Arguments.ArgumentEmpty(options.OutFile, 3)
	}

	// Call function named ArgumentEmpty
	Arguments.ArgumentEmpty(options.Language, 2)

	// Call function ValidateArgument
	foundLanguage := Arguments.ValidateArgument("lang", options.Language, []string{"Nim", "Rust", "C", "CSharp", "Go", "Python", "PowerShell", "Perl", "VBA", "Ruby", "Java", "Raw"})

	if options.Encryption == "" && options.Obfuscation == "" {
		logger := log.New(os.Stderr, "[!] ", 0)
		logger.Fatal("Please choose either the Encryption option (-enc) or the Obfuscation option (-obf) to proceed, or select both.\n\n")
	}

	// if Encryption option is enable
	if options.Encryption != "" {
		// Call function named ValidateArgument
		Arguments.ValidateArgument("enc", options.Encryption, []string{"ROT", "XOR", "RC4", "AES", "CHACHA20"})

		// Call function named ManageProcess
		processType, processVerb = Manager.ManageProcess(options.Encryption)
	}

	// Obfuscation option is enable
	if options.Obfuscation != "" {
		// Call function named ValidateArgument
		Arguments.ValidateArgument("obf", options.Obfuscation, []string{"IPV4", "IPV6", "MAC", "UUID"})
	}

	// Call function name ConvertShellcode2String
	rawShellcode, err := Converters.ConvertShellcode2String(options.InputFile)
	if err != nil {
		fmt.Println("[!] Error:", err)
		return
	}

	// Call function named ConvertShellcode2Hex
	convertedShellcode, payloadLength := Converters.ConvertShellcode2Hex(rawShellcode, foundLanguage)

	// Convert the integer to a string
	payloadLengthString := strconv.Itoa(payloadLength)

	// Print payload size and chosen language
	fmt.Printf("[+] Payload size: %s bytes\n\n[+] Converted payload to %s language\n\n", Colors.BoldCyan(payloadLengthString), strings.ToUpper(foundLanguage))

	// if Debug true
	if options.Debug {
		switch fileSizeFlag {
		case true:
			fmt.Printf("[!] The size of the original shellcode exceeds the maximum display limit.\n\n[!] Supernova cannot display it on the screen.\n\n")
		default:
			// if language is raw
			if foundLanguage == "raw" {
				fmt.Printf("[!] The original shellcode is displayed in raw format represented as hexadecimal on the terminal.\n\n")
			}
			// Call function named ConvertShellcode2Template
			template := Converters.ConvertShellcode2Template(convertedShellcode, foundLanguage, payloadLength, options.Variable)

			// Print original template
			fmt.Printf("[+] The original payload:\n\n%s\n\n", template)
		}
	}

	// Encryption option is enable
	if options.Encryption != "" {
		// Record the start time
		encryptionStartTime := time.Now()

		// Call function named EncryptionManager
		template, encryptedShellcode = Manager.EncryptionManager(options.Key, options.Encryption, options.Obfuscation, options.Debug, options.Variable, rawShellcode, foundLanguage, fileSizeFlag, processVerb)

		// Record the end time
		encryptionEndTime := time.Now()

		// Calculate the duration
		encryptionDuration := encryptionEndTime.Sub(encryptionStartTime)

		fmt.Printf("[+] Payload %s with %s completed successfully! (Completed in %s)\n\n", strings.ToLower(processType), strings.ToUpper(options.Encryption), encryptionDuration)
	}

	// Obfuscation option is enables
	if options.Obfuscation != "" {
		// Record the start time
		encryptionStartTime := time.Now()

		// if fileSizeFlag is enabled
		if fileSizeFlag {
			fmt.Printf("[!] Please be patient as Supernova processes your request.\n\n")
		}

		// Encryption option is enable
		if options.Encryption != "" {
			// Set as shellcode the encryptedShellcode (byte)
			shellcode = encryptedShellcode

			// Call function named ObfuscationManager
			template = Manager.ObfuscationManager(shellcode, strings.ToLower(options.Obfuscation), foundLanguage, options.Variable, fileSizeFlag)
		} else {
			// Convert raw shellcode to bytes
			shellcode = []byte(rawShellcode)

			// Call function named ObfuscationManager
			template = Manager.ObfuscationManager(shellcode, strings.ToLower(options.Obfuscation), foundLanguage, options.Variable, fileSizeFlag)
		}

		// Record the end time
		encryptionEndTime := time.Now()

		// Calculate the duration
		encryptionDuration := encryptionEndTime.Sub(encryptionStartTime)

		fmt.Printf("[+] Payload obfuscation as %s completed successfully! (Completed in %s)\n\n", strings.ToUpper(options.Obfuscation), encryptionDuration)
	}

	// Call function named OutputManager
	Manager.OutputManager(options.OutFile, foundLanguage, template, options.Encryption, options.Obfuscation, processVerb)
}
