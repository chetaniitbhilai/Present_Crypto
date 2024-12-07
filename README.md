# PRESENT Cipher Analysis and Tools

This repository is dedicated to the **PRESENT cipher**, a lightweight block cipher designed for constrained environments. It includes the cipher's implementation, cryptographic analysis tools, and utility scripts.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
- [Usage](#usage)
  - [PRESENT Cipher](#present-cipher)
  - [Differential Cryptanalysis](#differential-cryptanalysis)
  - [Integral Cryptanalysis](#integral-cryptanalysis)
  - [VPN Implementation](#vpn-implementation)
  - [LAT Generation](#lat-generation)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The **PRESENT cipher** is a lightweight encryption algorithm designed for embedded systems and other constrained environments. This repository includes:
- A Python implementation of the cipher.
- Scripts for differential and integral cryptanalysis.
- A basic implementation of a VPN server and client using PRESENT cipher for encryption.
- Tools to evaluate the cipher's S-boxes.

---

## Features

- **PRESENT Cipher Implementation**: Includes encryption and decryption functions.
- **Cryptographic Analysis**:
  - Differential and integral attack scripts.
  - S-box evaluation tools for LAT and DDT generation.
- **VPN Implementation**: Demonstrates how PRESENT can be used for secure communication in a VPN-like setup.

---

## Directory Structure

```plaintext
RL_3_Project/
├── __pycache__/                # Python bytecode cache (auto-generated)
├── differential_attack/        # Scripts for differential cryptanalysis
│   ├── ddt_make.py             # Generates Differential Distribution Table (DDT)
│   ├── diff.py                 # Differential analysis scripts
├── integral_attack/            # Scripts for integral cryptanalysis
│   ├── attack.py               # Implementation of integral cryptanalysis
├── software/                   # Additional utilities and tools
│   ├── present.py              # PRESENT cipher implementation
│   ├── vpn_client.py           # VPN client script
│   ├── vpn_server.py           # VPN server script
├── LAT_generation.py           # Script for generating Linear Approximation Table (LAT)
├── present.py                  # Another PRESENT cipher implementation (entry point)
├── README.md                   # Documentation for the project
