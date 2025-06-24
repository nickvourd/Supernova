# Supernova
Real fucking shellcode encryptor & obfuscator.

<p align="center">
  <img width="350" height="350" src="/Pictures/Logo/Supernova-Logo.png"><br /><br />
  <img alt="GitHub License" src="https://img.shields.io/github/license/nickvourd/Supernova?style=social&logo=GitHub&logoColor=purple">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/nickvourd/Supernova?logoColor=yellow"><br />
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/nickvourd/Supernova?logoColor=red">
  <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/nickvourd/Supernova?logoColor=blue">
  <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/nickvourd/Supernova?style=social&logo=GitHub&logoColor=green">
</p>

## Description

Supernova is an open-source tool that empowers users to securely encrypt and/or obfuscate their raw shellcode. 

![Static Badge](https://img.shields.io/badge/Golang-cyan?style=flat&logoSize=auto)
![Static Badge](https://img.shields.io/badge/Version-3.6%20(Moon%20Dust)-red?link=https%3A%2F%2Fgithub.com%2Fnickvourd%2FSupernova%2Freleases)

Supernova supports various features beyond those typically found in a common shellcode encryptor tool. Please refer to the <a href="#features"> Features</a> section for more information.

For command-line usage and examples, please refer to our [Wiki](https://github.com/nickvourd/Supernova/wiki).

> If you find any bugs, don’t hesitate to [report them](https://github.com/nickvourd/Supernova/issues). Your feedback is valuable in improving the quality of this project!

## Disclaimer

The authors and contributors of this project are not liable for any illegal use of the tool. It is intended for educational purposes only. Users are responsible for ensuring lawful usage.

## Table of Contents

- [Supernova](#supernova)
  - [Description](#description)
  - [Disclaimer](#disclaimer)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement](#acknowledgement)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
  - [References](#references)

## Acknowledgement

Special thanks to my brothers [@S1ckB0y1337](https://twitter.com/S1ckB0y1337) and [@IAMCOMPROMISED](https://twitter.com/IAMCOMPROMISED), who provided invaluable assistance during the beta testing phase of the tool.

Grateful acknowledgment to [@y2qaq](https://twitter.com/y2qaq) and [@VeryDampTowel](https://twitter.com/VeryDampTowel) for their valuable contributions.

Special thanks to my friend [@MikeAngelowtt](https://twitter.com/MikeAngelowtt) for all our evening discussions during the development process.

A heartfelt thanks to my friend [@0xvmar](https://x.com/0xvm) for his invaluable guidance and support throughout the years.

Special thanks to my friend [Efstratios Chatzoglou](https://www.linkedin.com/in/efstratios-chatzoglou-b2b09616b/) and his tool named [Pandora](https://github.com/efchatz/pandora), which inspired me to improve the beauty of this `README.md` file.

This tool was inspired during the malware development courses of [MALDEV Academy](https://maldevacademy.com).

Supernova was created with :heart: by [@nickvourd](https://twitter.com/nickvourd).

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
- VBA (Implemented by [@verydamptowel](https://twitter.com/verydamptowel))
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
- UUID (Supported by [@S1ckB0y1337](https://twitter.com/S1ckB0y1337) & [@MikeAngelowtt](https://twitter.com/MikeAngelowtt))

Supernova is written in Golang, a cross-platform language, making it compatible with Windows, Linux, and macOS.

## Installation

You can use the [precompiled binaries](https://github.com/nickvourd/Supernova/releases), or you can manually install Supernova by following the next steps:

⚠️ Please ensure that Go is installed on your system.

ℹ️ For Linux platforms install the following package:

```
sudo apt install golang -y
```

ℹ️ For MacOS platforms install the following package:

```
brew install go
```

ℹ️ For Windows platforms, please visit the [official Go website](https://go.dev/dl/) and download the appropriate MSI file for installation.

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

:information_source: Please refer to the [Supernova Wiki](https://github.com/nickvourd/Supernova/wiki) for detailed usage instructions and examples of commands.

```
███████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗
███████╗██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║██║   ██║███████║
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
███████║╚██████╔╝██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

Supernova v3.6 - Real fucking shellcode encryptor & obfuscator tool.
Supernova is an open source tool licensed under MIT.
Written with <3 by @nickvourd.
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
        Programming language to translate the shellcode (i.e., Nim, Rust, C, CSharp, Go, Python, PowerShell, Perl, VBA, Ruby, Java, Raw)
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
- [ChaCha20-Poly1305 Wikipedia](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
- [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Sector7 Institute](https://institute.sektor7.net/)
- [MalDev Academy](https://maldevacademy.com/)
- [OSEP-Code-Snippets GitHub by Chvancooten](https://github.com/chvancooten/OSEP-Code-Snippets)
- [From the Front Lines | Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection by SentinelOne](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Shellcode Obfuscation by Bordergate](https://www.bordergate.co.uk/shellcode-obfuscation/)
