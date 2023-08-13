# Supernova
Real fucking shellcode encryptor.

## Description
Supernova is an open-source Golang tool that empowers users to securely encrypt their raw shellcodes. Additionally, it offers automatic conversion of the encrypted shellcode into formats compatible with various programming languages, including:
- C
- C#
- Rust
- Nim

It supports a variety of different ciphers, including:
- Caesar
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
        Shellcode encryption (i.e., XOR, RC4, AES)
  -guide
        Enable guide mode
  -i string
        Path to the raw 64-bit shellcode
  -k int
        Key lenght size for encryption (default 1)
  -lang string
        Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp)
  -o string
        Name of output file
  -v string
        Name of shellcode variable (default "shellcode")
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

## References

- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
