import base64
import json
import os
import socket
import threading
import time

from authentication import authenticate,check_user_authenticate_code, if_user_already_exists, clients_db, Client
from encrdecr import decrypt_message, decrypt_combined_data, key_to_bytes, encrypt_message_sym
from keys import gen_keys_for_server, Extract_client_pub_key
from commclients import checks_if_the_recipient_is_in_the_DB, recipient_public_key, Create_digital_signature, send_initial_message_to_bob, send_message_to_bob

MAX_CLIENT = 10
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345


timeout =  600

# Start server and wait for connections
def start_server(private_key):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = SERVER_HOST
        port = SERVER_PORT
        
        server.bind((host, port))
        server.listen(MAX_CLIENT)
        print("Server is listening.")

        threading.Thread(target=check_client_activity, daemon=True).start() # Background thread to check client activity
    except Exception as e:
        print(f"Error starting server: {e}")
        server.close()

    while True:
        try:
            client, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client, addr, private_key))
            client_thread.start()
            print("Connected with", addr)
        except Exception as e:
            print("Error:", e)

# Handle all client
def handle_client(client, addr, private_key):
    try:
        while True:
            try:
                phone_number = client.recv(1024)
                phone = decrypt_message(phone_number, private_key)
                phone = phone.decode()
               
                if not phone_number:
                    raise ConnectionResetError("Client disconnected.")                
                
                #Check if user alredy exist
                if if_user_already_exists(phone, client):
                    message = "Already connected, one connection permitted at a time."
                    client.send(message.encode())
                    break

                # authentication from user
                auth_code, expires = authenticate(client)
                #To check
                data_received = client.recv(4096).decode()
                print(f"Client {phone} sent autentication code, public key and aes key (encrytped):", data_received)

                if not data_received.strip():  # Validate non-empty JSON data
                    break  # Skip if data is empty
                data = json.loads(data_received)

                encrypted_data = bytes.fromhex(data["encrypted_data"])
                encrypted_key = bytes.fromhex(data["encrypted_key"])
                aes_key = decrypt_message(encrypted_key, private_key)
                encrypted_iv = bytes.fromhex(data["encrypted_iv"])
                iv = decrypt_message(encrypted_iv, private_key)

                user_code, user_public_key = decrypt_combined_data(encrypted_data, aes_key, iv, private_key)

                global clients_db
                #check auth code
                #if user pass the authentication code I insert you to db
                if check_user_authenticate_code(user_code, auth_code, expires):
                    user_public_key = Extract_client_pub_key(phone)
                    Client.set_user(client, phone, user_public_key, aes_key, iv, time.time())
                    

                #If alice want send the message to bob, the function checks if bob there is in the DB and return
                # Receive messages loop
                while True:
                    new_connection_flag = False
                    message_to = client.recv(1).decode()
                    Client.set_last_active(phone, time.time()) #update that user was active
                    if is_request(phone):
                        continue
                    
                    if message_to == "-": # new connection, send public key of other user
                        message_to = client.recv(1).decode()
                        Client.set_last_active(phone, time.time())  #update that user was active
                        new_connection_flag = True
                        if checks_if_the_recipient_is_in_the_DB(phone, clients_db, message_to) == False:
                            continue
                        send_bob_public_key(client, message_to, aes_key, iv, private_key)
                    else: # public key doesn't have to be sent
                        if checks_if_the_recipient_is_in_the_DB(phone, clients_db, message_to) == False:
                            continue

                    # receive message from alice to bob (includes either initial message or regular message)   
                    payload_data = client.recv(2048).decode()
                    Client.set_last_active(phone, time.time())  #update that user was active

                    if is_request(phone):
                        continue
                    
                    print("Received encrypted message and signature.")

                    if new_connection_flag == True:
                        send_initial_message_to_bob(payload_data, message_to, private_key, phone)
                    else:
                        send_message_to_bob(payload_data, message_to, phone)

                            
            except ConnectionResetError as e:
                print(f"Client {addr} disconnected: {e}")
                break
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                break     
    finally:
        client.close()
        print(f"Connection with client {addr} closed.")

def send_bob_public_key(client, bob_phone, aes_key, iv, private_key):
    public_key_Bob = recipient_public_key(bob_phone)# first message only from here#!#!#
    public_key = key_to_bytes(public_key_Bob)# extract key as bytes
    encrypt_public_key_bob = encrypt_message_sym(public_key, aes_key, iv) #encrypt key
    signature = Create_digital_signature(encrypt_public_key_bob, private_key) #sign key

    data_to_send = {
        "signature": base64.b64encode(signature).decode('utf-8'),
        "encrypt_public_key_bob": base64.b64encode(encrypt_public_key_bob).decode('utf-8'),
    }
    json_data = json.dumps(data_to_send)
    print("Bob's public key sent to Alice: ", data_to_send)
    client.send(json_data.encode('utf-8'))
    print("Data sent successfully.")

def check_client_activity():
    while True:
        current_time = time.time()
        for key in clients_db:
            if current_time - Client.get_last_active(key) > timeout and Client.get_connectivity(key) == True:
                Client.set_offline(key) #set offline
                Client.get_socket(key).send("No activity detected, enter your phone number to reconnect".encode())

        time.sleep(60) # Check every minute 

def is_request(phone):
    if Client.get_connectivity(phone) == True:
        return False
    else:
        Client.set_online(phone) #set online
        send_pending_messages(phone)
        return True
    
def send_pending_messages(phone):
    Client.get_messages(phone)
    Client.get_socket(phone).send("Null".encode())


def main():
    private_key = gen_keys_for_server()
    start_server(private_key)
    if os.path.exists("pubic_key.pem"):
        os.remove("pubic_key.pem")
    else:
        print("file does not exist")

if __name__ == "__main__":
    main()
