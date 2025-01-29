Network security- E2EE

-Technical details-

-Description- The system ensures secure end-to-end messaging, similar to WhatsApp.

-Requirements- Python 3.12

-Libraries and Dependencies- json: I used json for handling structured data, encoding, and decoding, as it allows us to securely exchange and store information in a standardized format.

cryptography.hazmat.primitives.asymmetric: I used cryptography.hazmat.primitives.asymmetric for asymmetric cryptography operations like public/private key encryption and decryption, ensuring secure key exchanges and maintaining message integrity.

cryptography.hazmat.primitives: I used cryptography.hazmat.primitives for general cryptographic operations, including hashing and key derivation functions, to ensure data security, integrity, and secure key management.

cryptography.hazmat.primitives.ciphers: I used cryptography.hazmat.primitives.ciphers for symmetric encryption, which enables secure data encryption and decryption with algorithms like AES to protect sensitive information

cryptography.hazmat.primitives.padding: I used cryptography.hazmat.primitives.padding to handle padding schemes, ensuring data is aligned correctly for encryption and decryption, which is essential for maintaining data security and avoiding errors.

from cryptography.hazmat.primitives import hashing: This import allows us to use cryptographic hash functions, which are essential for creating fixed-size secure representations of data. I used this for hashing for digital signatures

import cryptography.exceptions: This import provides access to various exceptions raised by the cryptography library. It is important for handling errors during cryptographic operations, ensuring the robustness and reliability of the cryptographic processes.

-How to run-
Step 1: Run the server: python server.py

Step 2: Run the client file: python client.py

Step 3: Open as many clients as you want and.. start a conversation.

Good luck!
