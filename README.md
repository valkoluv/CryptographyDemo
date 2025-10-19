## 💻 CryptographyDemo

This project is a simple, command-line Java application that demonstrates the practical use of three fundamental cryptographic concepts: **Symmetric Encryption (AES)**, **Asymmetric Encryption (RSA)**, and **Digital Signatures (SHA256withRSA)** using the Java Cryptography Architecture (JCA).

-----

## ✨ Features

  * **AES Encryption/Decryption**: Demonstrates 128-bit AES encryption in **CBC** (Cipher Block Chaining) mode with **PKCS5Padding**.
  * **RSA Encryption/Decryption**: Demonstrates 2048-bit RSA encryption in **ECB** (Electronic Codebook) mode with **PKCS1Padding** using an asymmetric key pair (Public/Private keys).
  * **Digital Signatures**: Illustrates how to sign data using a **Private Key** and verify the signature using the corresponding **Public Key** with the `SHA256withRSA` algorithm.
  * **Interactive Demo**: The `main` method provides an interactive, step-by-step demonstration for a user-inputted string, confirming the success of each cryptographic operation.

-----

## 🛠️ Technology and Algorithms

| Concept | Algorithm | Key Size / Transformation | Method(s) in Code |
| :--- | :--- | :--- | :--- |
| **Symmetric** | AES | 128-bit / `AES/CBC/PKCS5Padding` | `generateAesKey`, `aesEncrypt`, `aesDecrypt` |
| **Asymmetric** | RSA | 2048-bit / `RSA/ECB/PKCS1Padding` | `generateRsaKeyPair`, `rsaEncrypt`, `rsaDecrypt` |
| **Signature** | RSA | `SHA256withRSA` | `sign`, `verifySignature` |

-----

## 🚀 Getting Started

### Prerequisites

  * **Java Development Kit (JDK) 8 or newer** installed on your system.

### Running the Demo

1.  **Save the Code**: Save the content of `src/CryptographyDemo.java` into a file named `CryptographyDemo.java` within a `src` directory.

2.  **Compile**: Open your terminal or command prompt, navigate to the project's root directory (where the `src` folder is), and compile the Java file.

    ```bash
    javac src/CryptographyDemo.java
    ```

3.  **Execute**: Run the compiled class file.

    ```bash
    java -cp src CryptographyDemo
    ```

4.  **Interact**: The program will prompt you to enter a text string, then proceed to demonstrate the AES, RSA, and Digital Signature processes, printing the results and verification status for each.

-----

## 📜 Code Structure

The core logic is contained within `src/CryptographyDemo.java`.

### Key Methods

| Method | Description |
| :--- | :--- |
| `generateAesKey()` | Creates a new 128-bit AES `SecretKey`. |
| `aesEncrypt(...)` / `aesDecrypt(...)` | Handles the symmetric encryption and decryption using the AES key and an Initialization Vector (IV). |
| `generateRsaKeyPair()` | Creates a new 2048-bit RSA `KeyPair` (Public and Private keys). |
| `rsaEncrypt(...)` / `rsaDecrypt(...)` | Handles the asymmetric encryption using the **Public Key** and decryption using the **Private Key**. |
| `sign(...)` | Generates a digital signature for a given data string using the **Private Key**. |
| `verifySignature(...)` | Verifies the signature against the original data using the **Public Key**. |
| `main(...)` | The demonstration driver that orchestrates all the steps and outputs the results. |

-----

## ⚖️ License

This project is released under the **MIT License**. See the `LICENSE` file for details.
