# Supernova
Real fucking shellcode encryptor & obfuscator.

<p align="center">
  <img width="350" height="350" src="/Pictures/Supernova-Logo.png">
</p>

## Description
Supernova is an open-source Golang tool that empowers users to securely encrypt and/or obfuscate their raw shellcode.

Additionally, it offers automatic conversion of the encrypted shellcode into formats compatible with various programming languages, including:
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

It supports a variety of different ciphers, including:
- ROT
- XOR
- RC4
- AES (AES-128-CBC, AES-192-CBC, AES-256-CBC)
- Chacha20 (Implemented by [@y2qaq](https://twitter.com/y2qaq))

Supernova supports various obfuscation techniques, which make the malicious shellcode appear as if it were:
- IPv4
- IPv6
- MAC
- UUID

Supernova is written in Golang, a cross-platform language, enabling its use on both Windows and Linux systems.

## Version

### 2.0.0 (Grand Canyon)

## License

This tool is licensed under the [![License: MIT](https://img.shields.io/badge/MIT-License-yellow.svg)](LICENSE).

## Acknowledgement

Special thanks to my brothers [@S1ckB0y1337](https://twitter.com/S1ckB0y1337) and [@IAMCOMPROMISED](https://twitter.com/IAMCOMPROMISED), who provided invaluable assistance during the beta testing phase of the tool.

Grateful acknowledgment to [@y2qaq](https://twitter.com/y2qaq) for his valuable contributions.

This tool was inspired during the malware development courses of [MALDEV Academy](https://maldevacademy.com).

Supernova was created with :heart: by [@nickvourd](https://twitter.com/nickvourd), [@Papadope9](https://twitter.com/Papadope9) and [@0xvm](https://twitter.com/0xvm).

## Table of Contents
- [Supernova](#supernova)
  - [Description](#description)
  - [Version](#version)
  - [License](#license)
  - [Acknowledgement](#acknowledgement)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [References](#references)

## Installation

## References

- [Caesar Cipher Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [XOR Cipher Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [RC4 Cipher Wikipedia](https://en.wikipedia.org/wiki/RC4)
- [AES Cipher Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
- [OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)
- [From the Front Lines | Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection by SentinelOne](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Shellcode Obfuscation by Bordergate](https://www.bordergate.co.uk/shellcode-obfuscation/)