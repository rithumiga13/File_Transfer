

# 🔐 Secure File Transfer System (C + AES-256 + Sockets)

A lightweight and secure file transfer system written in C using **AES-256 encryption (OpenSSL)** and **TCP sockets**.
It supports encrypting files, securely sending them over the network, receiving them, and decrypting the output.

---

## 🚀 Features

* **AES-256-CBC encryption & decryption** using OpenSSL
* **Secure file sending** using TCP sockets
* **Automatic IV generation & handling**
* **Menu-driven UI** for easy usage
* **File receiver with automatic key exchange**
* **Cross-platform (Linux/macOS)**

---

## 📦 Compilation

Install OpenSSL first:

```bash
brew install openssl
```

Compile the program:

```bash
gcc file_transfer.c -o transfer -lssl -lcrypto
```

---

## 🛠 Usage

### **Start Receiver (Device B)**

```bash
./transfer
Choose: 2
Enter filename to save received file: received.enc
Enter filename for decrypted output: output.txt
```

### **Send Encrypted File (Device A)**

```bash
./transfer
Choose: 1
Enter input filename: secret.txt
Enter output encrypted filename: encrypted.bin
Enter receiver IP: <Receiver_IP_Address>
```

---

## 📁 Program Flow

### **Sender**

1. Generate AES-256 key
2. Encrypt chosen file
3. Connect to receiver
4. Send:

   * Encrypted filename
   * AES key
   * Encrypted data

### **Receiver**

1. Listen on port **5512**
2. Accept incoming file
3. Receive:

   * filename
   * AES key
   * file data
4. Save & decrypt

---

## ⚠️ Security Notes

This project is for learning purposes.
The AES key is transmitted in plain form over the socket. For production-level security, add:

* Diffie-Hellman key exchange
* TLS/SSL sockets
* File integrity check (SHA-256)
* Authentication

I can help you implement these if you want.

---

## 📄 License

MIT License — free to use and modify.


