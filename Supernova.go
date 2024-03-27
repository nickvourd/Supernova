package main

import (
	"Supernova/Arguments"
	"Supernova/Converters"
	"Supernova/Manager"
	"Supernova/Utils"
	"fmt"
	"log"
	"os"
	"strings"
)

// main function
func main() {
	template := ""
	encryptedShellcode := ""

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
	foundLanguage := Arguments.ValidateArgument("lang", options.Language, []string{"Nim", "Rust", "C", "CSharp", "Go", "Python", "Raw"})

	if options.Encryption == "" && options.Obfuscation == "" {
		logger := log.New(os.Stderr, "[!] ", 0)
		logger.Fatal("Please choose either the encryption option or the obfuscation option to proceed, or select both.\n")
	}

	// if Encryption option is enable
	if options.Encryption != "" {
		// Call function named ValidateArgument
		Arguments.ValidateArgument("enc", options.Encryption, []string{"ROT", "XOR", "RC4", "AES", "CHACHA20"})
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

	// Print payload size and chosen language
	fmt.Printf("[+] Payload size: %d bytes\n\n[+] Converted payload to %s language\n\n", payloadLength, strings.ToUpper(foundLanguage))

	// Debug true
	if options.Debug {
		// If fileSizeFlag is true
		if fileSizeFlag {
			fmt.Printf("[!] The size of the original raw shellcode exceeds the maximum display limit.\n\n[!] Supernova cannot display it on the screen.\n\n")
		} else {
			// Call function named ConvertShellcode2Template
			template := Converters.ConvertShellcode2Template(convertedShellcode, foundLanguage, payloadLength, options.Variable)

			// Print original template
			fmt.Printf("[+] The original payload:\n\n%s\n\n", template)
		}
	}

	// Encryption option is enable
	if options.Encryption != "" {
		// Call function named EncryptionManager
		template, encryptedShellcode = Manager.EncryptionManager(options.Key, options.Encryption, options.Obfuscation, options.Variable, rawShellcode, foundLanguage, fileSizeFlag)
	}

	// Obfuscation option is enable
	if options.Obfuscation != "" {
		fmt.Println(encryptedShellcode)
	}

	// Call function named OutputManager
	Manager.OutputManager(options.OutFile, foundLanguage, template)
}
