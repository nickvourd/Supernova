package Decryption

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
        
            byte[] encryptedPayload = new byte[] { /* Your encrypted byte array here */ };

            int encodedKey = 7;

            byte[] decryptedPayload = DecryptROTPayload(encryptedPayload, encodedKey);

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
func SaveTamplate2File(filename string, tamplate string, language string, encryption string) {
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

	fmt.Printf("[+] %s Decryption function in %s language has been saved to %s file\n\n", strings.ToUpper(encryption), language, filename)
}

// SetDecryptionFile function
func SetDecryptionFile(extension string) string {
	// Set filename according to preferred language
	filename := "Program." + extension

	return filename
}

// DecryptorsTemplates function
func DecryptorsTemplates(language string, cipher string) {
	// Set logger for errors
	logger := log.New(os.Stderr, "[!] ", 0)

	switch language {
	case "csharp":
		extension := "cs"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		switch strings.ToLower(cipher) {
		case "rot":
			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_rot__, language, cipher)
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
