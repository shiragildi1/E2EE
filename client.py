import base64
import queue
import json
import re
import socket
import threading
from cryptography.hazmat.primitives import serialization
from keys import Extract_server_pub_key, Extract_client_pub_key, gen_keys_for_client, remove_keys
from encrdecr import decrypt_message, encrypt_message, encrypt_combined_data, encrypt_initial_message, decrypt_initial_message, decrypt_message_sym, encrypt_message_to_bob, generate_aes_key_and_iv
from commclients import check_digital_signature, decrypt_public_key_of_bob, Create_digital_signature
from authentication import validate_number

SERVER_HOST = "localhost"
SERVER_PORT = 12345
phone = None
flag = 0
condition = threading.Condition()
lock = threading.Lock()
reconnect_flag = False
reconnect_condition = threading.Condition()
connected = True
message_queue= queue.Queue()

def create_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = SERVER_HOST
    port = SERVER_PORT
    client.connect((host, port))
    print("Connected to the server.")

    return client  # return the client object

symmetric_keys = {}

def client_connection(client):
    global phone 
    global connected
    global flag
    global symmetric_keys
    global reconnect_flag
    while True:
        phone = input("Please enter a valid phone number (one digit): ")
        if not validate_number(phone):
            print("Please enter a valid phone number (one digit).")
        else:
            private_key = gen_keys_for_client(phone)
            #Bring me the public user and server_key
            user_public_key = Extract_client_pub_key(phone)
            server_public_key = Extract_server_pub_key()
            
            break

    # create the connection with the server

    try:
        # Encrypt phone
        phone_encrypt = encrypt_message(phone.encode(), server_public_key)
        print("User phone number encrypted sent to server: ", phone_encrypt)

        # Send the encrypted message
        client.send(phone_encrypt)
        
        #get the authentication code
        auth_code = client.recv(1024).decode()
        print(auth_code)

        #the user press your code
        user_code = input("Please enter your code: ")

        #If authentication failed the connection close with client
        match = re.search(r"\d+", auth_code)#Extruct only the auth code from the sentences.
        auth_code = match.group(0) if match else None
       
        if user_code != auth_code:
            print("Authentication failed. Closing the connection...")
            client.close()  # Close the connection
            return 
        
        combain_data, aes_key, iv = encrypt_combined_data(user_code, user_public_key, server_public_key)
        print("User authentication code, public key, aes key and iv sent to server (all encrypted): ", combain_data)

        #save aes_key to dictionary
        symmetric_keys["server"] = (aes_key, iv)
        client.send(combain_data.encode())
        
        listen_thread = threading.Thread(target=receive_messages, args=(client, private_key, server_public_key))
        listen_thread.start()

        # Send messages loop
        while True:
            message_to = input("Please enter phone number to send message: ")
            if connected == False:
                message_queue.put(message_to)
                with reconnect_condition: 
                    reconnect_flag = True
                    reconnect_condition.notify_all()
            else:
                if not validate_number(message_to):
                    print("Invalid phone number")
                    continue
                
                with lock:
                    flag = 1
                    if symmetric_keys.get(message_to) is None:
                        initial_message_to =f"-{message_to}"
                        client.send(initial_message_to.encode()) # dash marks new number, need public key
                        bob_public_key = receive_bob_public_key(client, server_public_key, aes_key, iv)
                        send_initial_message(client, message_to, bob_public_key, private_key)
                    else:
                        client.send(message_to.encode())
                        send_message(client, message_to)
                    
                with condition: 
                    flag = 0
                    condition.notify_all()
                
                client.settimeout(None)
        client.recv(1024).decode()  # Prevent connection from closing 
   
    except Exception as e:
        print("Error:", e)
    finally:
        remove_keys(phone)
        client.close()
        print("Connection closed.")

def send_message(client, bob_phone):
    client.settimeout(None)
    message_to_Bob = input(f"Please enter a message to {bob_phone}: ")

    peer_aes_key, peer_iv = symmetric_keys[bob_phone]

    encrypted_message_to_bob = encrypt_message_to_bob(message_to_Bob, peer_aes_key, peer_iv)
    payload = {
            "encrypted_message": base64.b64encode(encrypted_message_to_bob).decode('utf-8'),
        }
    payload_json = json.dumps(payload)
    print("Message from Alice to Bob: ", payload_json)
    client.send(payload_json.encode())

def send_initial_message(client, bob_phone, bob_public_key, private_key):
    message_to_Bob = input(f"Please enter a message to {bob_phone}: ")

    peer_aes_key, peer_iv = generate_aes_key_and_iv()
    symmetric_keys[bob_phone] = (peer_aes_key, peer_iv)

    encrypted_initial_message = encrypt_initial_message(message_to_Bob, peer_aes_key, peer_iv, bob_public_key)
    signature = Create_digital_signature(encrypted_initial_message, private_key)

    payload = {
            "encrypted_message": encrypted_initial_message.decode('utf-8'),
            "signature": signature.hex()
        }
    payload_json = json.dumps(payload)
    print("Message from Alice to Bob(server will add Alice's public key): ", payload_json)
    client.send(payload_json.encode())

def receive_bob_public_key(client, server_public_key, aes_key, iv):
    client.settimeout(None)
    signed_key = client.recv(2048)
    received_data = json.loads(signed_key.decode('utf-8'))
    signature = base64.b64decode(received_data["signature"])
    encrypt_public_key_bob = base64.b64decode(received_data["encrypt_public_key_bob"])

    if check_digital_signature(server_public_key, encrypt_public_key_bob, signature):
        print("Server signature on Bob's public key verified")
        public_key_of_bob = decrypt_public_key_of_bob(encrypt_public_key_bob, aes_key, iv)
        print("Public key of peer to send message to: ", public_key_of_bob)

        return public_key_of_bob

def receive_messages(client, private_key, server_public_key):
    global connected
    global flag
    global symmetric_keys
    global reconnect_flag
    while True: 
        with condition: 
            condition.wait_for(lambda: flag == 0) 
            try:
                with lock:
                    client.settimeout(3.0)
                    payload_data = client.recv(4096)
                    client.settimeout(None)

                    if payload_data == "No activity detected, enter your phone number to reconnect".encode(): #message received that client is offline 
                        print(payload_data.decode())
                        connected = False
                        with reconnect_condition:
                            reconnect_condition.wait_for(lambda: reconnect_flag == True) 
                            message = message_queue.get()
                            reconnect_flag = False
                            request_to_reconnect(client, private_key, server_public_key)
                    else:
                        open_message(client, payload_data.decode(), private_key, server_public_key, flag_ack_all = False)
                    
                    print("Please enter phone number to send message: ")
            except TimeoutError:
                client.settimeout(None)
                continue
            
            threading.Event().wait(1)

def open_message(client, payload_data, private_key, server_public_key, flag_ack_all):
    payload = json.loads(payload_data)
    print("Message received before unpacking and decryption: ", payload)
    encrypted_message = payload["encrypted_message"].encode('utf-8')

    alice_phone = base64.b64decode(payload["alice_phone"])

    server_aes_key, server_iv = symmetric_keys["server"]
    
    alice_phone = decrypt_message_sym(alice_phone, server_aes_key, server_iv )
    if symmetric_keys.get(alice_phone) is None:
        open_initial_message(client, encrypted_message, payload, alice_phone, private_key, server_public_key, flag_ack_all)
    else:
        alice_aes_key, alice_iv = symmetric_keys[alice_phone]

        open_message_2(client, encrypted_message, alice_phone, alice_aes_key, alice_iv, flag_ack_all)

def open_message_2(client, encrypted_message, alice_phone, alice_aes_key, alice_iv, flag_ack_all):
    
    payload_message = json.loads(encrypted_message)
   
    encrypted_message = base64.b64decode(payload_message["encrypted_message"])

    message = decrypt_message_sym(encrypted_message, alice_aes_key, alice_iv)
    print("\n")
    print("Incoming message from: ", alice_phone)
    print(message)
    if  not message == f"{alice_phone} received message": 
        if flag_ack_all == False:
            send_acknowledgment(client, alice_phone)
        else:
            return alice_phone

def open_initial_message(client, encrypted_message, payload, alice_phone, private_key, server_public_key, flag_ack_all):
   
    payload_message = json.loads(encrypted_message)
    encrypted_message = payload_message["encrypted_message"].encode()
    signature = bytes.fromhex(payload_message["signature"])
    
    server_aes_key, server_iv = symmetric_keys["server"]

    alice_public_key_encrypted = base64.b64decode(payload["alice_public_key"])
    alice_public_key_bytes = decrypt_message_sym(alice_public_key_encrypted, server_aes_key, server_iv)
    alice_public_key = serialization.load_pem_public_key(alice_public_key_bytes.encode(),) 

    encrypted_alice_key_signature = bytes.fromhex(payload["alice_key_signature"])
    server_signature_verification = check_digital_signature(server_public_key, alice_public_key_encrypted, encrypted_alice_key_signature)

    if server_signature_verification:
        print("Server signature on alice public key verified")

        signature_verification = check_digital_signature(alice_public_key, encrypted_message, signature)
        if signature_verification:
            print("ALice's signature on AES key verified")
            alice_message = json.loads(encrypted_message.decode())
            encrypted_message = bytes.fromhex(alice_message["encrypted_message"])
            encrypted_key = bytes.fromhex(alice_message["encrypted_key"])
            encrypted_iv = bytes.fromhex(alice_message["encrypted_iv"])

            alice_aes_key = decrypt_message(encrypted_key, private_key)
            alice_iv = decrypt_message(encrypted_iv, private_key)
            symmetric_keys[alice_phone] = (alice_aes_key, alice_iv)

            message = decrypt_initial_message(encrypted_message, alice_aes_key, alice_iv)
            print("\n")
            print("Incoming message from: ", alice_phone)
            print(message)
            if flag_ack_all == False:
                send_acknowledgment(client, alice_phone)
            else:
                return alice_phone
        else:
            print("Invalid signature. Message discarded.")

def send_acknowledgment(client, to_phone):
    global phone
    #first will send phone than acknowledgment, that way will be
    # received in the server like a regular message
    client.send(to_phone.encode())
    ack_message = f"{phone} received message" 
    alice_aes_key, alice_iv = symmetric_keys[to_phone]
    encrypted_ack_message = encrypt_message_to_bob(ack_message, alice_aes_key, alice_iv)

    payload_ack = {
        "encrypted_message": base64.b64encode(encrypted_ack_message).decode('utf-8'),
    }

    payload_ack_json = json.dumps(payload_ack)

    client.send(payload_ack_json.encode())
    
def request_to_reconnect(client, private_key, server_public_key):
    global connected
    alice_phone = None
    connected = True
    request = "1".encode()
    client.send(request)
    while True:
        message = client.recv(4096).decode()
        if message == "Null":
            if alice_phone is not None:
                send_acknowledgment(client, alice_phone)
            break
        else:
            alice_phone = open_message(client, message, private_key, server_public_key, flag_ack_all = True)

def main():
    client = create_client()
    # Create the connection of client
    client_connection(client)
    
if __name__ == "__main__":
    main()
