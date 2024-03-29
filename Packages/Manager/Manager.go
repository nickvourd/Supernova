package Manager

import (
	"Supernova/Packages/Arguments"
	"Supernova/Packages/Converters"
	"Supernova/Packages/Encryptors"
	"Supernova/Packages/Obfuscators"
	"Supernova/Packages/Output"
	"fmt"
	"strings"
)

// EncryptionManager function
func EncryptionManager(Key int, Encryption string, Obfuscation string, Debug bool, Variable string, rawShellcode string, foundLanguage string, fileSizeFlag bool) (string, []byte) {
	// Call function ValidateKeySize
	Key = Arguments.ValidateKeySize(Key, Encryption)

	// Call function named DetectEncryption
	encryptedShellcode, encryptedLength, decEncryptedShellcode := Encryptors.DetectEncryption(Encryption, rawShellcode, Key, foundLanguage)

	// Call function named ConvertShellcode2Template
	template := Converters.ConvertShellcode2Template(encryptedShellcode, foundLanguage, encryptedLength, Variable)

	// Check if Obfuscation is empty
	if Obfuscation == "" {
		// Handle the case when Obfuscation is empty
		if fileSizeFlag {
			// If fileSizeFlag is true
			fmt.Printf("[!] The size of the encrypted shellcode exceeds the maximum display limit.\n\n[!] Supernova cannot display it on the screen.\n\n")
		} else {
			if foundLanguage == "raw" {
				// If the foundLanguage is "raw"
				fmt.Printf("[!] The encrypted shellcode is displayed in raw format represented as hexadecimal on the terminal.\n\n")
			}
			// Print the encrypted template
			fmt.Printf("[+] The encrypted payload with %s:\n\n%s\n\n", strings.ToUpper(Encryption), template)
		}
	} else {
		// Handle the case when Obfuscation is not empty
		if Debug {
			// If Debug mode is enabled
			if fileSizeFlag {
				// If fileSizeFlag is true
				fmt.Printf("[!] The size of the encrypted shellcode exceeds the maximum display limit.\n\n[!] Supernova cannot display it on the screen.\n\n")
			} else {
				if foundLanguage == "raw" {
					// If the foundLanguage is "raw"
					fmt.Printf("[!] The encrypted shellcode is displayed in raw format represented as hexadecimal on the terminal.\n\n")
				}
				// Print the encrypted template
				fmt.Printf("[+] The encrypted payload with %s:\n\n%s\n\n", strings.ToUpper(Encryption), template)
			}
		}
	}

	return template, decEncryptedShellcode
}

// OutputManager function
func OutputManager(OutFile string, Language string, template string) {
	// Outfile option is enable
	if OutFile != "" {
		language := strings.ToLower(Language)
		if language == "raw" {
			err := Output.SaveShellcodeToFile(template, OutFile)
			if err != nil {
				fmt.Println("[!] Error:", err)
				return
			}
		} else {
			err := Output.SaveOutputToFile(template, OutFile)
			if err != nil {
				fmt.Println("[!] Error:", err)
				return
			}
		}
	}
}

// ObfuscationManager function
func ObfuscationManager(shellcode []byte, Obfuscation string, Language string, Variable string, fileSizeFlag bool) {

	// Call function named ShellcodeFromByteString
	formattedStringShellcode := Converters.ShellcodeFromByte2String(shellcode)

	// Convert string to array of hexadecimal strings
	shellcodeHexArray := strings.Split(formattedStringShellcode, " ")

	// Call function named DetectObfuscation
	ObfuscatedShellcode := Obfuscators.DetectObfuscation(Obfuscation, shellcodeHexArray)

	// Call function named ConvertObfShellcode2Template
	template := Converters.ConvertObfShellcode2Template(ObfuscatedShellcode, Language, Variable)

	// If fileSizeFlag is true
	if fileSizeFlag {
		fmt.Printf("[!] The size of the obfuscated shellcode exceeds the maximum display limit.\n\n[!] Supernova cannot display it on the screen.\n\n")
	} else {
		// Print the obfuscated template
		fmt.Printf("[+] The obfuscated payload as %s:\n\n%s\n\n", strings.ToUpper(Obfuscation), template)
	}
}
