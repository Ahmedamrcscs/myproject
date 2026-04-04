# Multi-Layered Password Authentication System

This Python application provides a secure user registration and login system featuring a robust, multi-stage encryption pipeline and a clean Graphical User Interface (GUI) built with Tkinter.

##  Features

*   **Multi-Stage Encryption:** Chains SHA-256, DES, AES, and RSA to secure user credentials.
*   **Strong Password Validation:** Enforces complexity (length, casing, digits, and special characters).
*   **Hybrid Interface:** Includes both a user-friendly Tkinter GUI and a CLI menu structure.
*   **Persistent Storage:** Saves encrypted tokens to a local `users.txt` file.

---

##  The Encryption Pipeline

To ensure **deterministic authentication** (the same input always produces the same output), the app processes passwords through the following flow:

1.  **Hashing:** The raw password is converted via **SHA-256**.
2.  **DES Encryption:** The hash is encrypted with **DES (ECB mode)** using an 8-byte key derived from the username.
3.  **AES Encryption:** The result is encrypted with **AES-128 (ECB mode)** using a 16-byte key derived from the username.
4.  **RSA Encryption:** Final encryption using **RSA**. A 1024-bit keypair is generated, seeded by the username to maintain consistency across sessions.

