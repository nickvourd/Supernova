package Output

import (
	"Supernova/Converters"
	"fmt"
	"strings"
)

// Template XOR Decryption with CSharp
var __csharp_xor__ = `static byte[] XORDecryption(byte[] %s, byte[] key)
{
	byte[] decrypted = new byte[%s.Length];
	int keyLen = key.Length;

	for (int i = 0; i < %s.Length; i++)
	{
		decrypted[i] = (byte)(%s[i] ^ key[i %% keyLen]);
	}

	return decrypted;
}`

// Template XOR with C
var __c_xor__ = `unsigned char* XORDecryption(unsigned char* %s, unsigned char* key, size_t %sLength, size_t keyLength){
    unsigned char* decrypted = (unsigned char*)malloc(%sLength);
    
    for (size_t i = 0; i < %sLength; i++) {
        decrypted[i] = %s[i] ^ key[i %% keyLength];
    }

    return decrypted;
}`

// Template XOR with Rust
var __rust_xor__ = `fn XORDecryption(%s: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::with_capacity(%s.len());
    let key_len = key.len();

    for i in 0..%s.len() {
        decrypted.push(%s[i] ^ key[i %% key_len]);
    }

    decrypted
}`

// Template XOR with Nim
var __nim_xor__ = `proc XORDecryption(%s: array[byte], key: array[byte]): array[byte] =
  var decrypted: array[byte, %s.len]
  let keyLen = key.len

  for i in 0..<%s.len:
    decrypted[i] = %s[i] xor key[i mod keyLen]

  hexKey = decrypted`

// OutputDecryption function
func OutputDecryption(language string, variable string, encryption string, key []byte) {
	switch strings.ToLower(encryption) {
	case "xor":
		// Call function named FormatKeysToHex
		hexKey := Converters.FormatKeysToHex(key)
		switch language {
		case "csharp":
			fmt.Printf("[+] %s function for decryption (%s):\n\n"+__csharp_xor__+"\n\n", strings.ToUpper(language), strings.ToLower(encryption), variable, variable, variable, variable)
			fmt.Printf("[+] Set key in main:\n\nbyte[] key = new byte[] { " + hexKey + " };\n\n")
			fmt.Printf("[+] Call function in main:\n\n"+"%s = XORDecryption(%s, key);\n\n", variable, variable)
		case "c":
			fmt.Printf("[+] %s function for decryption (%s):\n\n"+__c_xor__+"\n\n", strings.ToUpper(language), strings.ToLower(encryption), variable, variable, variable, variable, variable)
			fmt.Printf("[+] Set key in main:\n\nunsigned char key[] = { " + hexKey + " };\n\n")
			fmt.Printf("[+] Store key & shellcode size (in bytes) in main:\n\nsize_t %sLength = sizeof(%s);\n\nsize_t keyLength = sizeof(key);\n\n", variable, variable)
			fmt.Printf("[+] Call function in main:\n\n"+"%s = XORDecryption(%s, key, %sLength, keyLength);\n\n", variable, variable, variable)
		case "rust":
			fmt.Printf("[+] %s function for decryption (%s):\n\n"+__rust_xor__+"\n\n", strings.ToUpper(language), strings.ToLower(encryption), variable, variable, variable, variable)
			fmt.Printf("[+] Set key in main:\n\nlet key: Vec<u8> = vec![ " + hexKey + " ];\n\n")
			fmt.Printf("[+] Call function in main:\n\n"+"%s = XORDecryption(&%s, &key);\n\n", variable, variable)
		case "nim":
			fmt.Printf("[+] %s function for decryption (%s):\n\n"+__nim_xor__+"\n\n", strings.ToUpper(language), strings.ToLower(encryption), variable, variable, variable, variable)
			fmt.Printf("[+] Set key in main:\n\nvar key: array[byte] = @[ " + hexKey + " ]\n\n")
			fmt.Printf("[+] Call function in main:\n\n"+"%s = XORDecryption(%s, key)\n\n", variable, variable)
		}
	case "rc4":
		switch language {
		case "csharp":
			fmt.Println("Hello World")
		}
	}
}
