package main

import (
	"Supernova/Arguments"
	"Supernova/Converters"
	"Supernova/Utils"
	"flag"
	"fmt"
	"log"
	"os"
)

// Structure
type FlagOptions struct {
	outFile     string
	inputFile   string
	language    string
	encryption  string
	obfuscation string
}

// global variables
var (
	__version__ = "1.0.0"
	__license__ = "MIT"
	__author__  = "@nickvourd"
	__github__  = "https://github.com/nickvourd/Supernova"
)

var __ascii__ = `

███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

Supernova v%s - A real fucking shellcode encryptor.
Supernova is an open source tool licensed under %s.
Written with <3 by %s...
Please visit %s for more...

`

// Options function
func Options() *FlagOptions {
	inputFile := flag.String("i", "", "Path to the raw 64-bit shellcode.")
	encryption := flag.String("enc", "", "Shellcode encryption (i.e., XOR, RC4, AES)")
	obfuscation := flag.String("obs", "", "Shellcode obfuscation")
	language := flag.String("lang", "", "Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp)")
	outFile := flag.String("o", "", "Name of output file")
	flag.Parse()

	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, language: *language, encryption: *encryption, obfuscation: *obfuscation}
}

// main function
func main() {
	// Print ascii
	fmt.Printf(__ascii__, __version__, __license__, __author__, __github__)

	// Check GO version of the current system
	Utils.Version()

	// Retrieve command-line options using the Options function
	options := Options()

	// Check Arguments Length
	Arguments.ArgumentLength()

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

	// Check for valid values of language argument
	foundLanguage := Arguments.ValidateArgument("lang", options.language, []string{"Nim", "Rust", "C", "CSharp"})

	// Checks if either encryption or obfuscation options are provided.
	if options.encryption == "" && options.obfuscation == "" {
		logger := log.New(os.Stderr, "[!] ", 0)
		logger.Fatal("Please provide at least -enc or -obs option with a valid value...")
	}

	// Check for valid values of encryption argument
	if options.encryption != "" {
		Arguments.ValidateArgument("enc", options.encryption, []string{"XOR", "RC4", "AES"})
	}

	// Check for valid values of obfuscation argument
	if options.obfuscation != "" {
		Arguments.ValidateArgument("obs", options.obfuscation, []string{"IPv4", "IPv6", "MAC", "UUID"})
	}

	// Call function named ConvertShellcode2Hex
	convertedShellcode := Converters.ConvertShellcode2Hex(rawShellcode, foundLanguage)

	fmt.Println(convertedShellcode)

	// Call function named ConvertShellcode2Template
	Converters.ConvertShellcode2Template(options.inputFile, foundLanguage)
}
