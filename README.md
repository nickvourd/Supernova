# Supernova
Real fucking shellcode encryptor.

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

Special thanks to my brother [@S1ckB0y1337](https://twitter.com/S1ckB0y1337), who provided invaluable assistance during the beta testing phase of the tool.

Supernova was created with :heart: by [@nickvourd](https://twitter.com/nickvourd) and [@IAMCOMPROMISED](https://twitter.com/IAMCOMPROMISED).

Supernova is licensed under the [![License: MIT](https://img.shields.io/badge/MIT-License-yellow.svg)](LICENSE).

## Table of Contents
- [Supernova](#supernova)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Background](#background)
      - [Command Line Usage](#command-line-usage)
      - [About Guide](#about-guide)
        - [Guide Example](#guide-example)
      - [About Debug](#about-debug)
        - [Debug Example](#debug-example)
      - [About Output File](#about-output-file)
        - [Output File Example](#output-file-example)
  - [ROT Encryption](#rot-encryption)
  - [XOR Encryption](#xor-encryption)
  - [RC4 Encryption](#rc4-encryption)
  - [AES Encryption](#aes-encryption)
  - [References](#references)

## Installation

To install Supernova, run the following command, or use the [compiled binary](https://github.com/nickvourd/Supernova/releases):
```
go build Supernova.go
```

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
Written with <3 by @nickvourd and @IAMCOMPROMISED...
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
        Name of shellcode variable (default "shellcode")
  -version
        Show Supernova current version
```

### About Guide

This section provides information about the `-guide` option, which is designed to work in conjunction with the `-lang` and `-enc` options. It proves to be particularly valuable when users are unfamiliar with the decryption functionality or wish to experiment with different languages. The three primary actions encompass:

- Decryption functionality
- Set key/passphrase in main
- Call function in main

Additionally, when used in conjunction with the `-v` flag and a value (default `shellcode`, it can make the output's code dynamic by incorporating variables, thereby enhancing the code's copy-and-paste utility.

#### Guide Example

Here is a simple example demonstrating how the guide mode operates.

An attacker uses XOR encryption and utilizes the C# language option in conjunction with the guide mode and variable setting:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc xor -lang csharp -k 2 -guide -v buffer
```

## About Debug

The debug mode is useful if you want to observe the original payload in a selected programming language. To activate this functionality, you need to include the `-d` option.

#### Debug Example

Here is a simple example illustrating the functioning of the debug option.

An adversary uses ROT encryption and utilizes the C# language option in conjunction with the debug option:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rot -lang csharp -k 2 -d
```

Outcome:

![Debug-Example](/Pictures/Caesar-Csharp-Debug-Mode.png)

## About Output File

The output option is indicated by the `-o` switch, followed by the desired value, allowing you to save the encrypted payload into a file.

#### Output File Example

Here is a simple example illustrating the functioning of the output option.

An atatcker uses RC4 encryption and utilizes the C language option in conjunction with the output option and a desired filename:

```
.\Supernova.exe -i C:\Users\User\Desktop\shellcode.bin -enc rc4 -lang c -k 3 -o shellcode.bin
```

Outcome:

![Output-Example](/Pictures/RC4-C-Output-Option.png)

## ROT Encryption

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

## XOR Encryption

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

## RC4 Encryption

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

## AES Encryption

The Advanced Encryption Standard (AES) is a widely adopted symmetric encryption algorithm that provides strong security for various applications. It was established as a standard encryption algorithm by the U.S. National Institute of Standards and Technology (NIST) in 2001, following a competition to find a replacement for the aging Data Encryption Standard (DES). AES is known for its efficiency and robust security features, making it a cornerstone of modern cryptography.

## References

- [Caesar Cipher Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [XOR Cipher Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [RC4 Cipher Wikipedia](https://en.wikipedia.org/wiki/RC4)
- [AES Cipher Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
