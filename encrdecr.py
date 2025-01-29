import json
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Encrypt message with RSA public key
def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Decrypt the RSA-encrypted AES key or data
def decrypt_message(message, private_key):
    decrypted_message = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

#Generates a random 256-bit AES key and a 16-byte initialization vector (IV).
def generate_aes_key_and_iv():
    aes_key = os.urandom(32) # 256-bit AES key
    iv = os.urandom(16)  # Initialization Vector
    print("Aes key that I created: ", aes_key)
    print("Iv that I created: ", iv)
    return aes_key, iv



# The data encrypt by AES
# The aes key encrypt by RSA
# Hybrid encryption: Combines RSA and AES
def encrypt_combined_data(user_code, user_public_key, server_public_key):
    user_public_key_pem = key_to_bytes(user_public_key).decode("utf-8")

    # Prepare the data to encrypt
    data = {
        "user_code": user_code,
        "user_public_key": user_public_key_pem
    }
    combined_data = json.dumps(data).encode('utf-8')

    aes_key, iv = generate_aes_key_and_iv()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(combined_data) + encryptor.finalize()

    # Encrypt the AES key using RSA (asymmetric encryption)
    encrypted_key = encrypt_message(aes_key ,server_public_key)
    encrypted_iv = encrypt_message(iv ,server_public_key)
   
    data_to_send = {
    "encrypted_data": encrypted_data.hex(), 
    "encrypted_key": encrypted_key.hex(),
    "encrypted_iv": encrypted_iv.hex()
}
    json_data = json.dumps(data_to_send)

    # Return encrypted data, AES key, and IV
    return json_data, aes_key, iv

#Decrypts hybrid encrypted data (AES) using the corresponding RSA keys.
def decrypt_combined_data(encrypted_data, aes_key, iv, private_key):

    # Step 2: Decrypt the data using the AES key
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Step 3: Parse the decrypted JSON data
    combined_data = json.loads(decrypted_data.decode())

    return combined_data.get("user_code"), combined_data.get("user_public_key")


#Encrypts an initial message for Bob using a shared secret and asymmetric RSA encryption.
def encrypt_initial_message(message_to_bob, shared_secret, iv, bob_public_key_bytes):

    # change key from bytes to key type
    bob_public_key = serialization.load_pem_public_key(bob_public_key_bytes) 

    #encrypt message
    cipher = Cipher(algorithms.AES(shared_secret), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message_to_bob.encode()) + encryptor.finalize()

    #encrypt shared_secret
    encrypted_key = encrypt_message(shared_secret, bob_public_key)

    #encrypt iv
    encrypted_iv = encrypt_message(iv, bob_public_key)

    data_to_send = {
    "encrypted_message": encrypted_message.hex(), 
    "encrypted_key": encrypted_key.hex(),
    "encrypted_iv": encrypted_iv.hex()
}
    json_data = json.dumps(data_to_send)
    
    # Return encrypted data, AES key, and IV
    return json_data.encode()

#Decrypts an initial encrypted message sent to Bob using RSA and AES.
def decrypt_initial_message(encrypted_message, aes_key, iv):
    # Decrypt the data using the AES key
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    message = decrypted_message.decode()

    return message

#Encrypts a message for Bob using symmetric AES encryption with a shared secret.
def encrypt_message_to_bob(message_to_Bob, peer_aes_key, peer_iv):
    encrytped_message_to_bob = encrypt_message_sym(message_to_Bob.encode(), peer_aes_key, peer_iv)
    return encrytped_message_to_bob

#Encrypts a message symmetrically using AES with a provided key and IV.
def encrypt_message_sym(message, aes_key, iv):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
   
    return ciphertext

#Decrypts a message symmetrically using AES with a provided key and IV.
def decrypt_message_sym(encrypted_message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()
    message = unpadded_data.decode()
    return message

#Converts a public RSA key into PEM byte format for encryption purposes.
def key_to_bytes(key):
    key_bytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) 
    return key_bytes
