package Output

import (
	"fmt"
	"strings"
)

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

// OutputDecryption function
func OutputDecryption(language string, variable string, encryption string, key []byte) {
	switch strings.ToLower(encryption) {
	case "xor":
		switch language {
		case "csharp":
			fmt.Printf("[+] %s function for decryption (%s):\n\n"+__csharp_xor__+"\n\n", strings.ToUpper(language), strings.ToLower(encryption), variable, variable, variable, variable)
			fmt.Printf("[+] Set key in main:\n\nbyte[] key = new byte[] { /* XOR key bytes here like 0xfc, 0x55 ...*/ };\n\n")
			fmt.Printf("[+] Call function in main:\n\n"+"%s = XORDecryption(%s, key);\n\n", variable, variable)
		}
	}
}
