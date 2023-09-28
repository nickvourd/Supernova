# Supernova
Real fucking shellcode encryptor

<p align="center">
  <img width="350" height="350" src="https://github.com/nickvourd/Supernova/blob/main/Pictures/supernova_logo.png">
</p>

## Description
Supernova is an open-source Golang tool that empowers users to securely encrypt their raw shellcodes. Additionally, it offers automatic conversion of the encrypted shellcode into formats compatible with various programming languages, including:
- C
- C#
- Rust
- Nim

It supports a variety of different ciphers, including:
- ROT
- XOR
- RC4
- AES

Moreover, this tool generates the decrypted function using the chosen cipher and language, while also supplying instructions on how to utilize it effectively. 

Supernova is written in Golang, a cross-platform language, enabling its use on both Windows and Linux systems.

## License

This tool is licensed under the [![License: MIT](https://img.shields.io/badge/MIT-License-yellow.svg)](LICENSE).

## Acknowledgement

Special thanks to my brothers [@S1ckB0y1337](https://twitter.com/S1ckB0y1337) and [@IAMCOMPROMISED](https://twitter.com/IAMCOMPROMISED), who provided invaluable assistance during the beta testing phase of the tool.

This tool was inspired during the malware development courses of [MALDEV Academy](https://maldevacademy.com).

Supernova was created with :heart: by [@nickvourd](https://twitter.com/nickvourd), [@0xvm](https://twitter.com/0xvm) and [@Papadope9](https://twitter.com/Papadope9).

## Table of Contents
- [Supernova](#supernova)
  - [Description](#description)
  - [License](#license)
  - [Acknowledgement](#acknowledgement)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Background](#background)
      - [Command Line Usage](#command-line-usage)
      - [About Dynamic Variable Name](#about-dynamic-variable-name)
        - [Dynamic Variable Name Example](#dynamic-variable-name-example)
      - [About Guide](#about-guide)
         - [Guide Example](#guide-example)
      - [About Debug](#about-debug)
        - [Debug Example](#debug-example)
      - [About Output File](#about-output-file)
        - [Output File Example](#output-file-example)
      - [About Host Identifier](#about-host-identifier)
        - [Host Identifier Example](#host-identifier-example)
  - [Encryptions](#encryptions)
      - [ROT Encryption](#rot-encryption)
      - [XOR Encryption](#xor-encryption)
      - [RC4 Encryption](#rc4-encryption)
      - [AES Encryption](#aes-encryption)
        - [AES-256-CBC](#aes-256-cbc)
  - [References](#references)

## Installation

To install Supernova, run the following command, or use the [compiled binary](https://github.com/nickvourd/Supernova/releases):
```
go build Supernova.go
```

:information_source: Supernova works without the necessity of installing any additional dependencies.

## Background

### Command Line Usage

```
███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

Supernova v1.0.0 - Real fucking shellcode encryptor.
Supernova is an open source tool licensed under MIT.
Written with <3 by @nickvourd, @0xvm and @Papadope9...
Please visit https://github.com/nickvourd/Supernova for more...

Usage of Supernova.exe:
  -d    Enable Debug mode
  -enc string
        Shellcode encryption (i.e., ROT, XOR, RC4, AES)
  -guide
        Enable guide mode
  -i string
        Path to the raw 64-bit shellcode
  -k int
        Key lenght size for encryption (default 1)
  -lang string
        Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp)
  -o string
        Name of the output file
  -v string
        Name of dynamic variable (default "shellcode")
  -version
        Show Supernova current version
```

### About Dynamic Variable Name

Dynamic variable name is employed to insert the desired variable name for the shellcode payload and the exported decryption function. This approach imparts dynamism to the output code by incorporating variables, thereby enhancing the code's copy-and-paste utility.

Use dynamic variable name with `-v` switch and provide your preferred value.

The default value of dynamic variable name is `shellcode`.

#### Dynamic Variable Name Example

Here is a simple example demonstrating how the dynamic variable name operates.

An attacker uses XOR encryption and utilizes the C# language option in conjunction with the variable setting as value `nickvourd`:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc xor -lang csharp -k 2 -v nickvourd
```

Outcome:

![Variable-Example](/Pictures/XOR-Csharp-Variable.png)

### About Guide

 This section provides information about the `-guide` option, which is designed to work in conjunction with the `-lang` and `-enc` options. It proves to be particularly valuable when users are unfamiliar with the decryption functionality or wish to experiment with different languages. The three primary actions encompass:

 - Decryption functionality
 - Set key/passphrase in main
 - Call function in main

 Additionally, when used in conjunction with the `-v` flag and a value (default `shellcode`), it can make the output's code dynamic by incorporating variables, thereby enhancing the code's copy-and-paste utility.
 
 Last but not least, `-guide` saves the decryption function to a file named Program with the specific file extension of the chosen language.

⚠️ Guide mode does not support the Nim language at this stage of the release.

 #### Guide Example

 Here is a simple example demonstrating how the guide mode operates.

 An attacker uses ROT encryption and utilizes the C# language option in conjunction with the guide mode and variable setting:

 ```
 .\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rot -lang csharp -k 2 -guide -v buffer
 ```

 Outcome:

![Guide-Example](/Pictures/ROT-Csharp-Guide-Variable.png)

Decryption file preview example:

![Guide-Preview-File](/Pictures/ROT-Csharp-Guide-Variable-Preview.png)

### About Debug

The debug mode is useful if you want to observe the original payload in a selected programming language. To activate this functionality, you need to include the `-d` option.

#### Debug Example

Here is a simple example illustrating the functioning of the debug option.

An adversary uses ROT encryption and utilizes the C# language option in conjunction with the debug option:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rot -lang csharp -k 2 -d
```

Outcome:

![Debug-Example](/Pictures/Caesar-Csharp-Debug-Mode.png)

### About Output File

The output option is indicated by the `-o` switch, followed by the desired value, allowing you to save the encrypted payload into a file.

#### Output File Example

Here is a simple example illustrating the functioning of the output option.

An attacker uses RC4 encryption and utilizes the C language option in conjunction with the output option and a desired filename:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rc4 -lang c -k 3 -o shellcode.bin
```

Outcome:

![Output-Example](/Pictures/RC4-C-Output-Option.png)

### About Host Identifier

Supernova tool utilizes a utility to identify the host machine's operating system. When used in conjunction with the `-guide` option, it checks if the host machine is running Linux and, if so, adds the `<Windows.h>` header in the C language decryption templates.

The following code accomplishes this in the background:

```
// AddValues2Template function
func AddValues2Template(operatingSystem string, template string) string {
	if strings.ToLower(operatingSystem) == "linux" {
		template = "#include <Windows.h>" + template
	}

	return template
}
```

#### Host Identifier Example

Here is a simple example illustrating the functioning of the host identifier utility.

An attacker uses AES encryption and utilizes the C language option in conjunction with `-guide` mode from Linux host machine:

```
Supernova -i /root/shellcode.bin -enc aes -lang c -guide
```

Outcome:

![Host-Identifier-Example](/Pictures/Host-Identifier-Example.png)

## Encryptions

### ROT Encryption

The ROT cipher, also known as the rotation cipher, is a family of simple substitution ciphers in which the letters of the alphabet are shifted by a fixed number of positions. The term "ROT" is often followed by a number that indicates the amount of rotation applied to the letters. Each variant of the ROT cipher corresponds to a specific shift value.

Each letter in the plaintext message is replaced with the letter that appears a certain number of positions ahead in the alphabet, based on the key. The shifting is performed circularly, wrapping around from "Z" to "A".

As an example, using the Swift key 13:

```
"A" becomes "N"
"B" becomes "O"
...
"N" becomes "A"
"O" becomes "B"
...
"Z" becomes "M"
```

To employ Supernova with the ROT cipher, you must select a key that signifies the shift key, a preferred programming language, and provide a raw shellcode:

In the provided example, the preferred language is Rust, and the chosen Swift key is 7:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rot -lang rust -k 7
```

Outcome:

![ROT-Example](/Pictures/Caesar-Rust.png)

### XOR Encryption

The XOR cipher, also known as the exclusive OR cipher, is a basic encryption technique that operates by applying the XOR (exclusive OR) operation between each bit of the plaintext and a corresponding bit of a secret key. This results in ciphertext that appears random and can only be decrypted by performing the XOR operation again with the same secret key.

The XOR operation is performed between each bit of the plaintext message and the corresponding bit of the key. If the bits are the same (both 0 or both 1), the result is 0; if the bits are different, the result is 1.

For example, given a key of "10110":

```
Plaintext "01001" XOR Key "10110" = Ciphertext "11111"
```

To employ Supernova with the XOR cipher, you must select a key that generates random XOR byte keys, a preferred programming language, and provide a raw shellcode:

In the given illustration, the preferred programming language is Nim, and the selected key is 4. This key will be utilized to generate four-byte sequences for encryption purposes:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc xor -lang nim -k 4
```

Outcome:

![XOR-Example](/Pictures/XOR-Nim.png)

### RC4 Encryption

The RC4 cipher, also known as the Rivest Cipher 4 or ARC4, is a symmetric stream cipher that was designed by Ron Rivest in 1987. It gained popularity due to its simplicity and efficiency in generating a pseudorandom stream of bits, which can be used for encryption and decryption. The RC4 cipher was initially a trade secret, but it later became widely known and used in various applications.

The RC4 algorithm starts by initializing two arrays, S (state) and T (temporary). The key is used to initialize these arrays based on a process called key scheduling. The key can be of variable length, which influences the strength of the cipher.

The PRGA (Pseudorandom Generation Algorithm) generates a pseudorandom stream of bytes that are used to encrypt or decrypt the plaintext. The PRGA operates as follows:

- The arrays S and T are mixed based on the key to create the initial state.
- For each byte of the output stream, the values in arrays S and T are further mixed and used to generate a pseudorandom byte.
- This pseudorandom byte is XORed with the plaintext byte to produce the ciphertext byte (or vice versa for decryption).

The pseudorandom stream generated by the PRGA is called the keystream. This keystream is combined with the plaintext using the XOR operation to produce the ciphertext. 

To employ Supernova with the RC4 cipher, you must select a key that generates a random Passphrase, a preferred programming language, and provide a raw shellcode. Additionally, the numerical value provided in the "key" argument specifies the desired length of the generated random passphrase:

In the given illustration, the preferred programming language is CSharp, and the selected key is 9:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rc4 -lang csharp -k 9
```
Outcome:

![RC4-Example](/Pictures/RC4-Csharp.png)

### AES Encryption

The Advanced Encryption Standard (AES) is a widely adopted symmetric encryption algorithm that provides strong security for various applications. It was established as a standard encryption algorithm by the U.S. National Institute of Standards and Technology (NIST) in 2001, following a competition to find a replacement for the aging Data Encryption Standard (DES). AES is known for its efficiency and robust security features, making it a cornerstone of modern cryptography.

Supernova uses AES-256-CBC cipher.

#### AES-256-CBC

The "AES-256" in the name refers to the key length used in the algorithm. AES-256 employs a 256-bit encryption key, which means there are 2^256 possible key combinations, making it incredibly difficult and time-consuming for attackers to brute-force the key and decrypt the encrypted data without the proper key.

The "CBC" part of the name stands for Cipher Block Chaining. This mode of operation enhances the security of the encryption by chaining together the blocks of plaintext before encryption. Each block of plaintext is XORed (exclusive OR) with the previous ciphertext block before encryption, which introduces an element of randomness and dependency among blocks. This helps to prevent patterns in the plaintext from being apparent in the ciphertext, adding an extra layer of confidentiality.

Here's a breakdown of how AES-256-CBC works:

- Initialization Vector (IV): An IV is a random value used to initialize the encryption process. It ensures that even if the same plaintext is encrypted multiple times with the same key, the resulting ciphertext will be different due to the randomization introduced by the IV.

- Dividing Data into Blocks: The plaintext message is divided into fixed-size blocks (usually 128 bits or 16 bytes) before encryption.

- Chaining Blocks: Each plaintext block is XORed with the previous ciphertext block (or the IV for the first block) before encryption. This chaining helps prevent patterns from appearing in the ciphertext.

- Encryption: The XORed block is then encrypted using the AES-256 encryption algorithm with the provided encryption key.

To employ Supernova with the AES-256-CBC cipher, you must select a preferred programming language and provide a raw shellcode. Additionally, the generated key is a random 32-byte value, and the generated IV is a random 16-byte value.

In the given illustration, the preferred programming language is Csharp:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc aes -lang csharp
```

Outcome:

![AES-Example](/Pictures/AES-Csharp.png)

## References

- [Caesar Cipher Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [XOR Cipher Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [RC4 Cipher Wikipedia](https://en.wikipedia.org/wiki/RC4)
- [AES Cipher Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Nim (programming language)](https://en.wikipedia.org/wiki/Nim_(programming_language))
- [Rust (programming language)](https://en.wikipedia.org/wiki/Rust_(programming_language))
- [C Sharp (programming language)](https://en.wikipedia.org/wiki/C_Sharp_(programming_language))
- [C (programming language)](https://en.wikipedia.org/wiki/C_(programming_language))
- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
- [OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)
