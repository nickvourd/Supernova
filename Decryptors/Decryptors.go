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

// csharp rc4 template
var __csharp_rc4__ = `
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RC4Dencryption
{
    class Program
    {
        static byte[] RC4Dencrypt(byte[] data, byte[] key)
        {
            byte[] encrypted = new byte[data.Length];
            byte[] s = new byte[256];

            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i %% key.Length]) %% 256;
                byte temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            int x = 0;
            int y = 0;
            for (int idx = 0; idx < data.Length; idx++)
            {
                x = (x + 1) %% 256;
                y = (y + s[x]) %% 256;

                byte temp = s[x];
                s[x] = s[y];
                s[y] = temp;

                int t = (s[x] + s[y]) %% 256;
                encrypted[idx] = (byte)(data[idx] ^ s[t]);
            }

            return encrypted;
        }

        static byte[] GetKeyFromPassphrase(string passphrase)
        {
            // Convert the passphrase to bytes using UTF-8 encoding
            return Encoding.UTF8.GetBytes(passphrase);
        }

        static void Main(string[] args)
        {
            byte[] %s = new byte[%d] {%s};
            string passphrase = "%s";

            byte[] key = GetKeyFromPassphrase(passphrase);
            byte[] dencryptedPayload = RC4Dencrypt(%s, key);

            // Convert encryptedPayload to a hexadecimal string
            StringBuilder hex = new StringBuilder(dencryptedPayload.Length * 2);
            int totalCount = dencryptedPayload.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = dencryptedPayload[count];

                if ((count + 1) == totalCount) // Don't append a comma for the last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }
            }

            Console.WriteLine("RC4 Dencrypted Payload:\n");
            Console.WriteLine($"byte[] %s = new byte[{dencryptedPayload.Length}] {{ {hex} }};\n\n");
        }
    }
}
`

// c rc4 template
var __c_rc4__ = `
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// RC4 algorithm for decryption
void RC4Decrypt(const uint8_t* encryptedData, size_t dataSize, const uint8_t* key, size_t keySize, uint8_t* decryptedData) {
    uint8_t s[256];
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i %% keySize]) %% 256;
        // Swap s[i] and s[j]
        uint8_t temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    int i = 0;
    j = 0;
    for (size_t k = 0; k < dataSize; k++) {
        i = (i + 1) %% 256;
        j = (j + s[i]) %% 256;

        // Swap s[i] and s[j]
        uint8_t temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // Calculate the pseudo-random key
        uint8_t keyStream = s[(s[i] + s[j]) %% 256];

        // Decrypt the data
        decryptedData[k] = encryptedData[k] ^ keyStream;
    }
}

// Function to convert passphrase to bytes
void PassphraseToBytes(const char* passphrase, uint8_t* key, size_t* keySize) {
    size_t passphraseLength = strlen(passphrase);
    *keySize = passphraseLength;

    for (size_t i = 0; i < passphraseLength; i++) {
        key[i] = (uint8_t)passphrase[i];
    }
}

int main() {
    const char* passphrase = "%s"; // Replace with your passphrase
    uint8_t rc4Key[256];
    size_t keySize;

    // Convert passphrase to bytes
    PassphraseToBytes(passphrase, rc4Key, &keySize);

    uint8_t %s[] = {%s};

    size_t dataSize = sizeof(%s);

    uint8_t* decryptedPayload = (uint8_t*)malloc(dataSize);

    if (decryptedPayload == NULL) {
        printf("Memory allocation failed.\n");
        return 1; // Return an error code
    }

    // Perform RC4 decryption
    RC4Decrypt(%s, dataSize, rc4Key, keySize, decryptedPayload);

    printf("RC4 Decrypted Payload:\n\n");
    printf("unsigned char %s[] = \"");
    for (size_t i = 0; i < dataSize; i++) {
        printf("0x%%02x", decryptedPayload[i]);
        if (i < dataSize - 1) {
            printf(", ");
        }
    }
    printf("\";\n");

    // Free the allocated memory
    free(decryptedPayload);

    return 0;
}
`

// rust rc4 template
var __rust_rc4__ = `
fn rc4_decrypt(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u16 = 0; // Change j to u16

    for i in 0..=255 {
        j = (j + u16::from(s[i]) + u16::from(key[i %% key.len()])) %% 256; // Use u16 for j and casting
        s.swap(i as usize, j as usize);
    }

    let mut i: u8 = 0;
    j = 0;
    let mut decrypted_data = Vec::with_capacity(encrypted_data.len());

    for k in encrypted_data {
        i = i.wrapping_add(1);
        j = (j + u16::from(s[i as usize])) %% 256; // Use u16 for j and casting
        s.swap(i as usize, j as usize);
        let key_stream = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        decrypted_data.push(k ^ key_stream);
    }

    decrypted_data
}

fn main() {
    let passphrase = "%s";
    let rc4_key: Vec<u8> = passphrase.bytes().collect();

    let %s: [u8; %d] = [%s];

    let decrypted_payload = rc4_decrypt(&%s, &rc4_key);

    println!("RC4 Decrypted Payload:\n\n");
    print!("let %s: [u8; %d] = [");
    for (i, byte) in decrypted_payload.iter().enumerate() {
        print!("0x{:02x}", byte);
        if i < decrypted_payload.len() - 1 {
            print!(", ");
        }
    }
    println!("];");
}
`

// csharp aes template
var __csharp_aes__ = `
using System;
using System.Security.Cryptography;
using System.Text;

namespace AESDecryption
{
    class Program
    {
        static byte[] AESDecrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream msOutput = new MemoryStream())
                        {
                            // Decrypt the data and write it to the output stream.
                            csDecrypt.CopyTo(msOutput);
                            return msOutput.ToArray();
                        }
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            byte[] %s = new byte[%d] {%s};
            byte[] aesKey = new byte[%d] {%s};
            byte[] aesIV = new byte[16] {%s};

            byte[] decryptedPayload = AESDecrypt(%s, aesKey, aesIV);

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

            Console.WriteLine("AES Decrypted Payload:\n\n");
            Console.WriteLine($"byte[] %s = new byte[{decryptedPayload.Length}] {{ {hex} }};\n\n");
        }
    }
}
`

// c aes template
var __c_aes__ = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int AESDecrypt(const uint8_t* encryptedData, size_t encryptedDataLength, const uint8_t* key, const uint8_t* iv, uint8_t* decryptedData) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int decryptedLength = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_%d_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decryptedData, &len, encryptedData, encryptedDataLength);
    decryptedLength += len;
    EVP_DecryptFinal_ex(ctx, decryptedData + len, &len);
    decryptedLength += len;

    EVP_CIPHER_CTX_free(ctx);

    return decryptedLength;
}

int main() {
    uint8_t %s[] = {%s};
    size_t shellcodeLength = sizeof(%s);

    uint8_t aesKey[] = {%s};

    uint8_t aesIV[] = {%s};

    uint8_t* decryptedPayload = (uint8_t*)malloc(shellcodeLength);
    if (decryptedPayload == NULL) {
        perror("Memory allocation failed");
        return 1;
    }

    int decryptedLength = AESDecrypt(%s, shellcodeLength, aesKey, aesIV, decryptedPayload);

    printf("AES Decrypted Payload:\n\n");
    printf("unsigned char %s[] = \"");
    for (size_t i = 0; i < decryptedLength; i++) {
        printf("0x%%02x", decryptedPayload[i]);
        if (i < decryptedLength - 1) {
            printf(", ");
        }
    }
    printf("\";\n");

    free(decryptedPayload);

    return 0;
}
`

// rust aes template
var __rust_aes__ = `
extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;
use std::io::Write;

fn aes_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_%d_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;

    let mut decrypted_data = vec![0; encrypted_data.len() + cipher.block_size()];
    let mut count = decrypter.update(encrypted_data, &mut decrypted_data)?;

    count += decrypter.finalize(&mut decrypted_data[count..])?;

    decrypted_data.truncate(count);

    Ok(decrypted_data)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let %s: [u8; %d] = [%s];

    let aes_key: [u8; %d] = [%s];

    let aes_iv: [u8; 16] = [%s];

     match aes_decrypt(&%s, &aes_key, &aes_iv) {
        Ok(decrypted_payload) => {
            let payload_len = decrypted_payload.len();

            println!("AES Decrypted Payload:\n");
            print!("let %s: [u8; {}] = [", payload_len);
            for (i, byte) in decrypted_payload.iter().enumerate() {
                print!("{:#04x}", byte);
                if i < payload_len - 1 {
                    print!(", ");
                }
            }
            println!("];\n");
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    Ok(())
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
func DecryptorsTemplates(language string, cipher string, variable string, key int, payloadSize int, encryptedShellcode string, byteKey []byte, passphrase string, iv []byte) {

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
		case "rc4":
			// Config dynamic variable
			__csharp_rc4__ = fmt.Sprintf(__csharp_rc4__, variable, payloadSize, encryptedShellcode, passphrase, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_rc4__, cipher)
		case "aes":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Call function named KeyDetailsFormatter
			formattedIv := Output.KeyDetailsFormatter(iv)

			// Config dynamic variable
			__csharp_aes__ = fmt.Sprintf(__csharp_aes__, variable, payloadSize, encryptedShellcode, key, formattedKey, formattedIv, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __csharp_aes__, cipher)
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
		case "rc4":
			// Config dynamic variable
			__c_rc4__ = fmt.Sprintf(__c_rc4__, passphrase, variable, encryptedShellcode, variable, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __c_rc4__, cipher)
		case "aes":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Call function named KeyDetailsFormatter
			formattedIv := Output.KeyDetailsFormatter(iv)

			// Call function named DetectNotification
			keyNotification := Output.DetectNotification(key)

			// Config dynamic variable
			__c_aes__ = fmt.Sprintf(__c_aes__, keyNotification, variable, encryptedShellcode, variable, formattedKey, formattedIv, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __c_aes__, cipher)
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
		case "rc4":
			// Config dynamic variable
			__rust_rc4__ = fmt.Sprintf(__rust_rc4__, passphrase, variable, payloadSize, encryptedShellcode, variable, variable, payloadSize)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __rust_rc4__, cipher)
		case "aes":
			// Call function named KeyDetailsFormatter
			formattedKey := Output.KeyDetailsFormatter(byteKey)

			// Call function named KeyDetailsFormatter
			formattedIv := Output.KeyDetailsFormatter(iv)

			// Call function named DetectNotification
			keyNotification := Output.DetectNotification(key)

			// Config dynamic variable
			__rust_aes__ = fmt.Sprintf(__rust_aes__, keyNotification, variable, payloadSize, encryptedShellcode, key, formattedKey, formattedIv, variable, variable)

			// Call function named SaveTamplate2File
			SaveTamplate2File(foundFilename, __rust_aes__, cipher)
		}
	case "nim":
		fmt.Printf("[!] Guide mode does not support Nim language, yet!\n\n")
	default:
		logger.Fatal("Unsupported programming language")
	}
}
