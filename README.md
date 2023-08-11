# Supernova
Real fucking shellcode encryptor.

## Description
Supernova is an open-source Golang tool that empowers users to securely encrypt their raw shellcodes. Additionally, it offers automatic conversion of the encrypted shellcode into formats compatible with various programming languages, including:
- C
- C#
- Rust
- Nim

It supports a variety of different ciphers, including:
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
  - [References](#references)

## Installation

To install Supernova, run the following command, or use the compiled binary:
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

## References

- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)