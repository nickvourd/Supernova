package Output

import "fmt"

var __csharp__ = `static byte[] XORDecryption(byte[] %s, byte[] key)
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
func OutputDecryption(language string, variable string) {
	switch language {
	case "csharp":
		fmt.Printf("[+] Csharp function for decryption:\n\n"+__csharp__+"\n\n", variable, variable, variable, variable)
		fmt.Printf("[+] Set key in main:\n\nbyte[] key = new byte[] { /* XOR key bytes here */ };\n\n")
		fmt.Printf("[+] Call function in main:\n\n"+"byte[] decryptedShellcode = XORDecryption(%s, key);\n\n", variable)
	}

}
