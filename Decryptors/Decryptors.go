package Decryptors

import (
	"Supernova/Output"
	"fmt"
	"log"
	"os"
	"strings"
)

// global variables tamplates
// csharp rot template
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

// c rot template
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
        printf("ROT Decrypted Payload:\n");
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

// rust rot template
var __rust_rot__ = `
fn decrypt_rot_payload(encrypted_data: &[u8], key: i32) -> Vec<u8> {
    let mut decrypted = Vec::with_capacity(encrypted_data.len());

    for &byte in encrypted_data {
        let decrypted_byte = (byte as i32 - key) as u8;
        decrypted.push(decrypted_byte);
    }

    decrypted
}

fn main() {
    let %s: [u8; %d] = [%s];

    let encrypted_key = %d;

    let decrypted_payload = decrypt_rot_payload(&%s, encrypted_key);

    println!("ROT Decrypted Payload:\n");
    print!("let %s[u8; %d] = [");

    for (i, &byte) in decrypted_payload.iter().enumerate() {
        print!("0x{:02x}", byte);

        if i < decrypted_payload.len() - 1 {
            print!(", ");
        }
    }

    println!("];");
}
`

// csharp xor template
var __csharp_xor__ = `
using System;
using System.Text;

namespace XORDecryption
{
    class Program
    {
        static byte[] MultiXORDecrypt(byte[] encryptedData, byte[] key)
        {
            byte[] decrypted = new byte[encryptedData.Length];
            for (int i = 0; i < encryptedData.Length; i++)
            {
                decrypted[i] = (byte)(encryptedData[i] ^ key[i %% key.Length]);
            }

            return decrypted;
        }
        
        static void Main(string[] args)
        {
            byte[] %s = new byte[%d] {%s};

            byte[] multiXORKey = new byte[] {%s};

            byte[] decryptedPayload = MultiXORDecrypt(%s, multiXORKey);

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

            Console.WriteLine("Multi-XOR Decrypted Payload:\n");
            Console.WriteLine($"byte[] %s = new byte[{decryptedPayload.Length}] {{ {hex} }};\n\n");
        }
    }
}
`

// c xor template
var __c_xor__ = `
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t* MultiXORDecrypt(const uint8_t* encryptedData, size_t dataSize, const uint8_t* key, size_t keySize) {
    uint8_t* decrypted = (uint8_t*)malloc(dataSize);
    if (decrypted == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < dataSize; i++) {
        decrypted[i] = encryptedData[i] ^ key[i %% keySize];
    }

    return decrypted;
}

int main() {
    uint8_t %s[] = {%s};
    size_t dataSize = sizeof(%s);

    uint8_t xorKey[] = {%s};

    uint8_t* decryptedPayload = MultiXORDecrypt(%s, dataSize, xorKey, sizeof(xorKey));

    if (decryptedPayload != NULL) {
        printf("Multi-XOR Decrypted Payload:\n");
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

// rust xor template
var __rust_xor__ = `
fn multi_xor_decrypt(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = vec![0; encrypted_data.len()];
    for (i, byte) in encrypted_data.iter().enumerate() {
        decrypted[i] = byte ^ key[i %% key.len()];
    }
    decrypted
}

fn main() {
    let %s: [u8; %d] = [%s];
    let xor_key: [u8; %d] = [%s];

    let decrypted_payload = multi_xor_decrypt(&%s, &xor_key);

    println!("Multi-XOR Decrypted Payload:\n");
    print!("let %s[u8; %d] = [");
    for (i, byte) in decrypted_payload.iter().enumerate() {
        print!("0x{:02x}", byte);
        if i < decrypted_payload.len() - 1 {
            print!(", ");
        }
    }
    println!("];");
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
func DecryptorsTemplates(language string, cipher string, variable string, key int, payloadSize int, encryptedShellcode string, byteKey []byte) {
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
		case "xor":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Config dynamic variable
			__csharp_xor__ = fmt.Sprintf(__csharp_xor__, variable, payloadSize, encryptedShellcode, formattedKey, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_xor__, cipher)
		}
	case "c":
		extension := "c"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		switch strings.ToLower(cipher) {
		case "rot":
			// Config dynamic variable
			__c_rot__ = fmt.Sprintf(__c_rot__, variable, encryptedShellcode, key, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __c_rot__, cipher)
		case "xor":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Config dynamic variable
			__c_xor__ = fmt.Sprintf(__c_xor__, variable, encryptedShellcode, variable, formattedKey, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __c_xor__, cipher)
		}
	case "rust":
		extension := "rs"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		switch strings.ToLower(cipher) {
		case "rot":
			// Config dynamic variable
			__rust_rot__ = fmt.Sprintf(__rust_rot__, variable, payloadSize, encryptedShellcode, key, variable, variable, payloadSize)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __rust_rot__, cipher)
		case "xor":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Config dynamic variable
			__rust_xor__ = fmt.Sprintf(__rust_xor__, variable, payloadSize, encryptedShellcode, key, formattedKey, variable, variable, payloadSize)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __rust_xor__, cipher)
		}
	case "nim":
		extension := "nim"

		// Call function named SetDecryptionFile
		foundFilename := SetDecryptionFile(extension)

		fmt.Println(foundFilename)
	default:
		logger.Fatal("Unsupported programming language")
	}
}
