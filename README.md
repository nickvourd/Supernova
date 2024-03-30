# Supernova
Real fucking shellcode encryptor & obfuscator.

<p align="center">
  <img width="350" height="350" src="/Pictures/Supernova-Logo.png"><br /><br />
  <img alt="Static Badge" src="https://img.shields.io/badge/License-MIT-green?link=https%3A%2F%2Fgithub.com%2Fnickvourd%2FSupernova%2Fblob%2Fmain%2FLICENSE">
  <img alt="Static Badge" src="https://img.shields.io/badge/Version-2.0.0%20(Grand%20Canyon)-red?link=https%3A%2F%2Fgithub.com%2Fnickvourd%2FSupernova%2Freleases">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/nickvourd/Supernova?style=plastic&labelColor=grey&color=yellow">
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/nickvourd/Supernova?style=plastic&labelColor=grey&color=red">
</p>

## Description
Supernova is an open-source Golang tool that empowers users to securely encrypt and/or obfuscate their raw shellcode.

## Table of Contents
- [Supernova](#supernova)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement](#acknowledgement)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
  - [References](#references)

## Acknowledgement

Special thanks to my brothers [@S1ckB0y1337](https://twitter.com/S1ckB0y1337) and [@IAMCOMPROMISED](https://twitter.com/IAMCOMPROMISED), who provided invaluable assistance during the beta testing phase of the tool.

Grateful acknowledgment to [@y2qaq](https://twitter.com/y2qaq) for his valuable contributions.

This tool was inspired during the malware development courses of [MALDEV Academy](https://maldevacademy.com).

Supernova was created with :heart: by [@nickvourd](https://twitter.com/nickvourd), [@Papadope9](https://twitter.com/Papadope9) and [@0xvm](https://twitter.com/0xvm).

## Features

Supernova offers automatic conversion of the encrypted shellcode into formats compatible with various programming languages, including:
- C
- C#
- Rust
- Nim
- Golang (Community request by [@_atsika](https://twitter.com/_atsika))
- Python
- Perl
- PowerShell
- Java
- Ruby
- Raw (Implemented by [@y2qaq](https://twitter.com/y2qaq))

Supports a variety of different ciphers, including:
- ROT
- XOR
- RC4
- AES (AES-128-CBC, AES-192-CBC, AES-256-CBC)
- Chacha20 (Implemented by [@y2qaq](https://twitter.com/y2qaq))

Supports various obfuscation techniques, which make the malicious shellcode appear as if it were:
- IPv4
- IPv6
- MAC
- UUID (Supported by [@S1ckB0y1337](https://twitter.com/S1ckB0y1337))

Supernova is written in Golang, a cross-platform language, enabling its use on both Windows and Linux systems.

## Installation

### Golang Installation

You can use the [precompiled binaries](https://github.com/nickvourd/Supernova/releases), or you can manually install Supernova by following the next steps:

1) Clone the repository by executing the following command:

```
git clone https://github.com/nickvourd/Supernova.git
```

2) Once the repository is cloned, navigate into the Supernova directory:

```
cd Supernova
```

3) Install the third-party dependencies:

```
go mod download
```

4) Build Supernova with the following command:

```
go build Supernova
```

## Usage

:information_source: Please refer to the [Supernova wiki](https://github.com/nickvourd/Supernova/wiki) for detailed usage instructions and examples of commands.

```

███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

Supernova v2.0.0 - Real fucking shellcode encryptor & obfuscator tool.
Supernova is an open source tool licensed under MIT.
Written with <3 by @nickvourd, @Papadope9 and 0xvm.
Please visit https://github.com/nickvourd/Supernova for more...

Usage of Suprenova:
  -debug
        Enable Debug mode
  -enc string
        Shellcode encoding/encryption (i.e., ROT, XOR, RC4, AES, CHACHA20)
  -input string
        Path to a raw shellcode
  -key int
        Key length size for encryption (default 1)
  -lang string
        Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp, Go, Python, PowerShell, Perl, Ruby, Java, Raw)
  -obf string
        Shellcode obfuscation (i.e., IPV4, IPV6, MAC, UUID)
  -output string
        Name of the output shellcode file
  -var string
        Name of dynamic variable (default "shellcode")
  -version
        Show Supernova current version
```

## References

- [Caesar Cipher Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [XOR Cipher Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [RC4 Cipher Wikipedia](https://en.wikipedia.org/wiki/RC4)
- [AES Cipher Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
- [OSEP-Code-Snippets GitHub by Chvancooten](https://github.com/chvancooten/OSEP-Code-Snippets)
- [From the Front Lines | Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection by SentinelOne](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Shellcode Obfuscation by Bordergate](https://www.bordergate.co.uk/shellcode-obfuscation/)