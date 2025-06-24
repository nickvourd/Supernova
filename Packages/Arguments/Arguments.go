package Arguments

import (
	"Supernova/Packages/Colors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// FlagOptions struct represents the options parsed from command line flags
type FlagOptions struct {
	OutFile     string
	InputFile   string
	Language    string
	Encryption  string
	Obfuscation string
	Variable    string
	Debug       bool
	Key         int
	Version     bool
}

var (
	version     = "3.6"
	versionName = "Moon Dust"
	license     = "MIT"
	author      = "@nickvourd"
	github      = "https://github.com/nickvourd/Supernova"
	ascii       = `

███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
`

	text = `
Supernova v%s - Real fucking shellcode encryptor & obfuscator tool.
Supernova is an open source tool licensed under %s.
Written with <3 by %s.
Please visit %s for more...

`
)

// PrintAscii function
func PrintAscii() {
	// Initialize RandomColor
	randomColor := Colors.RandomColor()
	fmt.Print(randomColor(ascii))
	fmt.Printf(text, version, license, author, github)
}

// Options function
// Options function parses command line flags and returns FlagOptions
func Options() *FlagOptions {
	inputFile := flag.String("input", "", "Path to a raw shellcode")
	encryption := flag.String("enc", "", "Shellcode encoding/encryption (i.e., ROT, XOR, RC4, AES, CHACHA20)")
	language := flag.String("lang", "", "Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp, Go, Python, PowerShell, Perl, VBA, Ruby, Java, Raw)")
	outFile := flag.String("output", "", "Name of the output shellcode file")
	variable := flag.String("var", "shellcode", "Name of dynamic variable")
	debug := flag.Bool("debug", false, "Enable Debug mode")
	key := flag.Int("key", 1, "Key length size for encryption")
	version := flag.Bool("version", false, "Show Supernova current version")
	obfuscation := flag.String("obf", "", "Shellcode obfuscation (i.e., IPV4, IPV6, MAC, UUID)")
	flag.Parse()

	return &FlagOptions{
		OutFile:     *outFile,
		InputFile:   *inputFile,
		Language:    *language,
		Encryption:  *encryption,
		Variable:    *variable,
		Debug:       *debug,
		Key:         *key,
		Version:     *version,
		Obfuscation: *obfuscation,
	}
}

// ShowHelp function
func ShowHelp() {
	fmt.Println("Usage of Suprenova:")
	flag.PrintDefaults()
	os.Exit(0)
}

// ArgumentLength function
func ArgumentLength(versionFlag bool) {
	logger := log.New(os.Stderr, "[!] ", 0)
	switch len(os.Args) {
	case 1:
		// if no arguments print help menu
		// Call function named ShowHelp
		ShowHelp()
	case 2:
		// if one argument
		if versionFlag {
			// if version flag exists
			fmt.Print("[+] Current version: " + Colors.BoldRed(version) + "\n\n[+] Version name: " + Colors.BoldRed(versionName) + "\n\n")
			os.Exit(0)
		} else {
			// if version flag not exists
			// Call function named ShowHelp
			ShowHelp()
		}
	default:
		// if version flag exists
		if versionFlag {
			logger.Fatal("You cannot use the '-version' flag in conjunction with other arguments.\n\n")
		}
	}
}

// ArgumentEmpty function
func ArgumentEmpty(statement string, option int) {
	if statement == "" {
		logger := log.New(os.Stderr, "[!] ", 0)
		switch option {
		case 1:
			logger.Fatal("The '-input' flag specifying the path to raw shellcode is mandatory.\n\n")
		case 2:
			logger.Fatal("The '-lang' flag specifying a valid language option is mandatory (e.g., C, CSharp, Rust, Nim, Go, Python, PowerShell, Perl, VBA, Ruby, Java, Raw).\n\n")
		case 3:
			logger.Fatal("The size of the provided raw shellcode is too large!\n\n[!] The '-output' flag specifying the path to output shellcode is mandatory.\n\n")
		default:
			logger.Fatal("Invalid option specified for ArgumentEmpty function.")
		}
	}
}

// ValidateArgument function
func ValidateArgument(argName string, argValue string, validValues []string) string {
	// Add aliases for the language command-line names
	if strings.ToLower(argValue) == "golang" || strings.ToLower(argValue) == "go-lang" {
		argValue = "go"
	}

	if strings.ToLower(argValue) == "pwsh" || strings.ToLower(argValue) == "ps1" || strings.ToLower(argValue) == "pshell" {
		argValue = "powershell"
	}

	if strings.ToLower(argValue) == "rb" {
		argValue = "ruby"
	}

	if strings.ToLower(argValue) == "py" {
		argValue = "python"
	}

	if strings.ToLower(argValue) == "pl" {
		argValue = "perl"
	}

	if strings.ToLower(argValue) == "office" {
		argValue = "vba"
	}

	if strings.ToLower(argValue) == "c#" || strings.ToLower(argValue) == "cs" || strings.ToLower(argValue) == "c-sharp" || strings.ToLower(argValue) == ".net" || strings.ToLower(argValue) == "net" {
		argValue = "csharp"
	}

	if strings.ToLower(argValue) == "bin" {
		argValue = "raw"
	}

	if strings.ToLower(argValue) == "rustlang" || strings.ToLower(argValue) == "rust-lang" || strings.ToLower(argValue) == "rs" {
		argValue = "rust"
	}

	if strings.ToLower(argValue) == "nimlang" || strings.ToLower(argValue) == "nim-lang" {
		argValue = "nim"
	}

	for _, valid := range validValues {
		if strings.EqualFold(strings.ToLower(argValue), strings.ToLower(valid)) {
			valid = strings.ToLower(valid)
			return valid
		}
	}

	fmt.Printf("[!] Invalid value '%s' for argument '%s'. Valid values are: %v\n\n", argValue, argName, validValues)
	os.Exit(1)
	return ""
}

// ShellcodeSizeValidation function
func ShellcodeSizeValidation(filename string) bool {
	// set starting flag
	stagelessFlag := false
	logger := log.New(os.Stderr, "[!] ", 0)
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()

	// Get the file information
	fileInfo, err := file.Stat()
	if err != nil {
		logger.Fatal(err)
	}

	// Get the file size
	fileSize := fileInfo.Size()

	// Convert 197 KB to bytes
	sizeThresholdKB := 197
	sizeThresholdBytes := int64(sizeThresholdKB) * 1024

	// Check if the file size is equal or greater than 197KB
	if fileSize >= sizeThresholdBytes {
		stagelessFlag = true
	} else {
		stagelessFlag = false
	}

	return stagelessFlag
}

// ValidateKeySize function
func ValidateKeySize(key int, encryption string) int {
	logger := log.New(os.Stderr, "[!] ", 0)

	// if key is negative number or zero
	if key <= 0 {
		logger.Fatal("The provided key value is not valid.\n\n[!] Please provide a valid key value for the size.\n\n")
	}

	// if encryption is AES
	if strings.ToLower(encryption) == "aes" {
		switch key {
		case 128, 16:
			key = 16
		case 192, 24:
			key = 24
		case 256, 32:
			key = 32
		default:
			logger.Fatal("Provide a valid AES key:\n\n~> For AES-128-CBC: '-key 128' or '-key 16'\n\n~> For AES-192-CBC: '-key 192' or '-key 24'\n\n~> For AES-256-CBC: '-key 256' or '-key 32'\n\n")
		}
	}

	// if encryption is chacha20
	if strings.ToLower(encryption) == "chacha20" {
		switch key {
		case 32:
			key = 32
		default:
			logger.Fatal("Provide a valid Chacha20 key: '-key 32'\n\n")
		}
	}

	return key
}
