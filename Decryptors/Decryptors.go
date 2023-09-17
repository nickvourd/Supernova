package Decryptors

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// global variables tamplates
// Csharp rot template
var __csharp_rot__ = `
using System;
using System.Text;
namespace ROTDecryption
{
	class Program
	{
		static void Main(string[] args)
		{
			byte[] %s = new byte[%d] {%s};
			int encryptedKey = %d;
			byte[] decryptedPayload = DecryptROTPayload(%s, encryptedKey);
			string payloadText = Encoding.ASCII.GetString(decryptedPayload);
			
			// Convert decryptedPayload to a hexadecimal string
            StringBuilder hex = new StringBuilder(decryptedPayload.Length * 2);
            int totalCount = decryptedPayload.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = decryptedPayload[count];

                if ((count + 1) == totalCount) // Don't append a comma for the last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }
            }

            Console.WriteLine("ROT Decrypted Payload:\n");
            Console.WriteLine($"byte[] %s = new byte[{%s.Length}] {{ {hex} }};\n\n");
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

// C rot template
var __c_rot__ = `
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t* DecryptROTPayload(const uint8_t* encryptedData, size_t dataSize, int key) {
    uint8_t* decrypted = (uint8_t*)malloc(dataSize);
    if (decrypted == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < dataSize; i++) {
        decrypted[i] = (encryptedData[i] - key) & 0xFF;
    }

    return decrypted;
}

int main() {
    uint8_t %s[] = {%s};

    int encryptedKey = %d;
    size_t dataSize = sizeof(%s);

    uint8_t* decryptedPayload = DecryptROTPayload(%s, dataSize, encryptedKey);

    if (decryptedPayload != NULL) {
        printf("ROT Decrypted Payload:\n\n");
        printf("unsigned char %s[] = \"");

        for (size_t i = 0; i < dataSize; i++) {
            printf("0x%%02x", decryptedPayload[i]);
            if (i < dataSize - 1) {
                printf(", ");
            }
        }

        printf("\";\n");

        free(decryptedPayload);
    }

    return 0;
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
func DecryptorsTemplates(language string, cipher string, variable string, key int, payloadSize int, encryptedShellcode string) {
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
			__csharp_rot__ = fmt.Sprintf(__csharp_rot__, variable, payloadSize, encryptedShellcode, key, variable, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_rot__, cipher)
		}
	case "c":
		extension := "c"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		switch strings.ToLower(cipher) {
		case "rot":
			// Config dynamic variable
			__c_rot__ = fmt.Sprintf(__c_rot__, variable, encryptedShellcode, key, variable, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __c_rot__, cipher)
		}
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
