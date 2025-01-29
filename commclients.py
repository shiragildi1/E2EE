import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import cryptography.exceptions

from encrdecr import key_to_bytes, encrypt_message_sym
from authentication import clients_db, Client

#The function check if recipient exist in DB
def checks_if_the_recipient_is_in_the_DB(phone, clients_db, message_to):
    if message_to not in clients_db:
        Client.get_socket(phone).send("You are trying to send a message to a client that does not exist".encode())
        return False
    print(f"Found client with phone {message_to}.")
    
    return True

# The function return respnse with recipient's public key + signed of server on public key
def recipient_public_key(message_to):
    public_key_bob = Client.get_public_key(message_to)
    return public_key_bob

# Create the digital signature
def Create_digital_signature(message, private_key_server):
    try:
        # Creating the signature using the private key of the server
        signature = private_key_server.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature created: ", signature)
        return signature
    
    except Exception as e:
        print("Error creating signature:", e)
        print(f"Type: {type(e)}")
        print(f"Message: {str(e)}")
        return None

# Aouthentication of digital signature
def check_digital_signature(public_key_server, public_key_bob, signature):
    try:
        # Verify if the signature is valid
        public_key_server.verify(
            signature,
            public_key_bob,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
    
    except Exception as e:
        print("Signature verification failed:", e)
        print(f"Type: {type(e)}")
        print(f"Message: {str(e)}")
        
        # Check if the error is InvalidSignature
        if isinstance(e, cryptography.exceptions.InvalidSignature):
            print("Invalid signature: the key or data do not match.")
        
        # If the error is a different type
        else:
            print("Other error during verification")
        
        return False

#Alice decrypt the pubic key of bob
def decrypt_public_key_of_bob( encrypted_public_key_bob, aes_key, iv):
    
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_public_key_bob = decryptor.update(encrypted_public_key_bob) + decryptor.finalize()

        # Remove padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_public_key_bob) + unpadder.finalize()

        return unpadded_data

def send_initial_message_to_bob(encrypted_message_payload, to_phone, private_key, from_phone):
    aes_key, iv = Client.get_aes_key(to_phone)

    alice_public_key = Client.get_public_key(from_phone)
    alice_public_key_bytes = key_to_bytes(alice_public_key)
    encrypt_public_key_alice = encrypt_message_sym(alice_public_key_bytes, aes_key, iv)
    encrypted_alice_key_signature = Create_digital_signature(encrypt_public_key_alice, private_key)

    alice_phone = encrypt_message_sym(from_phone.encode(), aes_key, iv)

    payload_to_bob = {
        "encrypted_message": encrypted_message_payload,
        "alice_public_key": base64.b64encode(encrypt_public_key_alice).decode('utf-8'),
        "alice_phone": base64.b64encode(alice_phone).decode('utf-8'),
        "alice_key_signature": encrypted_alice_key_signature.hex(),
    }
    payload_json_to_bob = json.dumps(payload_to_bob)

    if Client.get_connectivity(to_phone) == False:
        print("Server added Alice's information to Bob's pending message: ", payload_json_to_bob)
        Client.add_message(to_phone, payload_json_to_bob.encode())
    else:
        print("Server added Alice's information to Bob's message: ", payload_json_to_bob)
        Client.get_socket(to_phone).send(payload_json_to_bob.encode())
    print(f"Message forwarded to {to_phone}." )

def send_message_to_bob(encrypted_message_payload, to_phone, from_phone):
    aes_key, iv = Client.get_aes_key(to_phone)
    
    alice_phone = encrypt_message_sym(from_phone.encode(), aes_key, iv)

    payload_to_bob = {
        "encrypted_message": encrypted_message_payload,
        "alice_phone": base64.b64encode(alice_phone).decode('utf-8'),
    }
    payload_json_to_bob = json.dumps(payload_to_bob)

    if Client.get_connectivity(to_phone) == False:
        print("Server added Alice's phone to Bob's pending message: ", payload_json_to_bob)
        Client.add_message(to_phone, payload_json_to_bob.encode())
    else:
        print("Server added Alice's phone to Bob's message: ", payload_json_to_bob)
        Client.get_socket(to_phone).send(payload_json_to_bob.encode())
    print(f"Message forwarded to {to_phone}." )
