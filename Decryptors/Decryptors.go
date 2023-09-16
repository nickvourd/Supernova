package Decryptors

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// global variables tamplates
var __csharp_rot__ = `
using System;
using System.Text;
namespace ROTDecryption
{
	class Program
	{
		static void Main(string[] args)
		{
		
			byte[] %s = new byte[] { /* Your encrypted byte array here */ };
			int encryptedKey = %d;
			byte[] decryptedPayload = DecryptROTPayload(%s, encryptedKey);
			string payloadText = Encoding.ASCII.GetString(decryptedPayload);
			Console.WriteLine("Decrypted Payload: " + payloadText);
		}
		static byte[] DecryptROTPayload(byte[] encryptedData, int key)
		{
			byte[] decrypted = new byte[encryptedData.Length];
			for (int i = 0; i < encryptedData.Length; i++)
			{
				decrypted[i] = (byte)(((uint)(encryptedData[i] - key) & 0xFF));
			}
			return decrypted;
		}
	}
}
`

// SaveTemplae2File function
func SaveTamplate2File(filename string, tamplate string, cipher string) {
	// Open a file for writing. If the file doesn't exist, it will be created.
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close() // Close the file when the function exits

	// Write the variable value to the file
	_, err = fmt.Fprintln(file, tamplate)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	cipher = strings.ToUpper(cipher)
	fmt.Printf("[+] %s decrytpion function has been saved to %s file\n\n", cipher, filename)
}

// SetDecryptionFile function
func SetDecryptionFile(extension string) string {
	// Set filename according to preferred language
	filename := "Program." + extension

	return filename
}

// DecryptorsTemplates function
func DecryptorsTemplates(language string, cipher string, variable string, key int) {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)

	// Set cipher to lower
	cipher = strings.ToLower(cipher)

	switch language {
	case "csharp":
		extension := "cs"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		switch strings.ToLower(cipher) {
		case "rot":
			// Config dynamic variable
			__csharp_rot__ = fmt.Sprintf(__csharp_rot__, variable, key, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_rot__, cipher)
		}
	case "c":
		extension := "c"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		fmt.Println(foundFilename)
	case "rust":
		extension := "rs"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		fmt.Println(foundFilename)
	case "nim":
		extension := "nim"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		fmt.Println(foundFilename)
	default:
		logger.Fatal("Unsupported programming language")
	}
}
