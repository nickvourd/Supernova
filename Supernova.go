package main

import (
	"Supernova/Arguments"
	"Supernova/Converters"
	"Supernova/Decryptors"
	"Supernova/Encryptors"
	"Supernova/Output"
	"Supernova/Utils"
	"flag"
	"fmt"
	"strings"
)

// Structure
type FlagOptions struct {
	outFile     string
	inputFile   string
	language    string
	encryption  string
	obfuscation string
	variable    string
	key         int
	debug       bool
	guide       bool
	version     bool
}

// global variables
var (
	__version__   = "2.0.0"
	__license__   = "MIT"
	__author__    = "@nickvourd"
	__github__    = "https://github.com/nickvourd/Supernova"
	__coauthors__ = [2]string{"@Papadope9", "@0xvm"}
)

var __ascii__ = `

███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

Supernova v%s - Real fucking shellcode encryptor and obfuscator.
Supernova is an open source tool licensed under %s.
Written with <3 by %s, %s and %s...
Please visit %s for more...

`

// Options function
func Options() *FlagOptions {
	inputFile := flag.String("i", "", "Path to the raw 64-bit shellcode")
	encryption := flag.String("enc", "", "Shellcode encoding/encryption (i.e., ROT, XOR, RC4, AES)")
	language := flag.String("lang", "", "Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp, Go)")
	outFile := flag.String("o", "", "Name of the output file")
	variable := flag.String("v", "shellcode", "Name of dynamic variable")
	debug := flag.Bool("d", false, "Enable Debug mode")
	key := flag.Int("k", 1, "Key lenght size for encryption")
	version := flag.Bool("version", false, "Show Supernova current version")
	guide := flag.Bool("guide", false, "Enable guide mode")
	obfuscation := flag.String("obf", "", "Shellcode obfuscation (i.e., IPv4, IPv6, MAC, UUID)")
	flag.Parse()

	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, language: *language, encryption: *encryption, variable: *variable, debug: *debug, key: *key, version: *version, guide: *guide, obfuscation: *obfuscation}
}

// main function
func main() {
	// Print ascii
	fmt.Printf(__ascii__, __version__, __license__, __author__, __coauthors__[1], __coauthors__[0], __github__)

	// Check GO version of the current system
	Utils.Version()

	// Retrieve command-line options using the Options function
	options := Options()

	// Check Arguments Length
	Arguments.ArgumentLength(options.version)

	// Check Version of tool
	Arguments.ShowVersion(__version__, options.version)

	// Call function named ArgumentEmpty
	Arguments.ArgumentEmpty(options.inputFile, 1)

	// Call function name ConvertShellcode2String
	rawShellcode, err := Converters.ConvertShellcode2String(options.inputFile)
	if err != nil {
		fmt.Println("[!] Error:", err)
		return
	}

	// Call function named ArgumentEmpty
	Arguments.ArgumentEmpty(options.language, 2)

	// Call function named ArgumentEmpty
	Arguments.ArgumentEmpty(options.encryption, 3)

	// Call function ValidateKeySize
	options.key = Arguments.ValidateKeySize(options.key, options.encryption)

	// Check for valid values of language argument
	foundLanguage := Arguments.ValidateArgument("lang", options.language, []string{"Nim", "Rust", "C", "CSharp", "Go"})

	// Call function named ConvertShellcode2Hex
	convertedShellcode, payloadLength := Converters.ConvertShellcode2Hex(rawShellcode, foundLanguage)

	// Print payload size and chosen language
	fmt.Printf("[+] Payload size: %d bytes\n\n[+] Converted payload to %s language\n\n", payloadLength, foundLanguage)

	if options.debug {
		// Call function named ConvertShellcode2Template
		template := Converters.ConvertShellcode2Template(convertedShellcode, foundLanguage, payloadLength, options.variable)

		// Print original template
		fmt.Printf("[+] The original payload:\n\n%s\n\n", template)
	}

	// Encryption option is enable
	if options.encryption != "" {
		// Call function named ValidateArgument
		Arguments.ValidateArgument("enc", options.encryption, []string{"XOR", "RC4", "AES", "ROT"})

		// Call function named DetectEncryption
		encryptedShellcode, encryptedLength, key, passphrase, iv := Encryptors.DetectEncryption(options.encryption, rawShellcode, options.key)

		// Call function named ConvertShellcode2Template
		template := Converters.ConvertShellcode2Template(encryptedShellcode, foundLanguage, encryptedLength, options.variable)

		// Print encrypted template
		fmt.Printf("[+] The encrypted payload with %s:\n\n%s\n\n", strings.ToUpper(options.encryption), template)

		// Guide option is enable
		if options.guide {
			Decryptors.DecryptorsTemplates(foundLanguage, options.encryption, options.variable, options.key, encryptedLength, encryptedShellcode, key, passphrase, iv)
		}

		// Outfile option is enable
		if options.outFile != "" {
			err := Output.SaveOutputToFile(template, options.outFile)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
		}
	}
}
