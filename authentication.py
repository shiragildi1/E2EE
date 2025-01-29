import secrets
import time

NUMBER_OF_SECRET_CODE = 6
AUTH_CODE_EXPIRY = 5 * 60

# Client class for storing client data
class Client:
    def __init__(self, socket, public_key, aes_key, iv, last_active):
        self.socket = socket
        self.public_key = public_key
        self.pending_messages = []
        self.aes_key = aes_key
        self.iv = iv
        self.connectivity = True
        self.last_active = last_active

    def __repr__(self):
        return f"Client(aes_key={self.aes_key})"

    def add_message(phone, message):
        client = clients_db.get(phone)
        client.pending_messages.append(message)

    def get_socket(phone):
        client = clients_db.get(phone)
        if client:
            return client.socket
        else:
            return None
        
    def get_aes_key(phone):
        client = clients_db.get(phone)
        if client:
            return client.aes_key, client.iv
        else:
            return None
              
    def get_public_key(phone):
        client = clients_db.get(phone)
        if client:
            return client.public_key
        else:
            return None
    
    def get_connectivity(phone):
        client = clients_db.get(phone)
        if client:
            return client.connectivity
        else:
            return None
    
    def get_messages(phone):
        client = clients_db.get(phone)
        for message in client.pending_messages:
            if message is not None:
                (client.socket).send(message)
                time.sleep(0.2)
        client.pending_messages = [] # clear pending messages

    def get_last_active(phone):
        client = clients_db.get(phone)
        if client:
            return client.last_active
        else:
            return None
         
    def set_aes_key(phone, aes_key, iv):
        client = clients_db.get(phone)
        client.aes_key = aes_key
        client.iv = iv
  
    def set_offline(phone):
        client = clients_db.get(phone)
        client.connectivity = False

    def set_online(phone):
        client = clients_db.get(phone)
        client.connectivity = True

    def set_last_active(phone, last_active):
        client = clients_db.get(phone)
        client.last_active = last_active

    def set_user(client_socket, user_phone, user_public_key, aes_key, iv, last_active):
        insert_user(client_socket, user_phone, user_public_key, aes_key, iv, last_active)

    

# Clients_db structure
clients_db = {}

#check if user's phone is validate
def validate_number(phone):
    return len(phone) == 1 and phone.isdigit()

#The server generate a authentication code by 6 digit
def generate_authentication_code():
    secret_code = secrets.randbelow(10**NUMBER_OF_SECRET_CODE)
    return f"{secret_code:0{NUMBER_OF_SECRET_CODE}d}"

# The function check if code from the user equal to the generate code from the server
def authenticate(client_socket):
    auth_code = generate_authentication_code()
    expires = time.time() + AUTH_CODE_EXPIRY
    message = f"Your authentication code is: {auth_code}"
    client_socket.send(message.encode())
    return auth_code, expires
    
#The function check if user code fit to authenticate code(by the server)
def check_user_authenticate_code(user_code, auth_code, expires):
    if user_code == auth_code and expires > time.time():
        print("Authentication successful.")
        return True
    print("Authentication failed.")
    return False

#The function checks by user phone if user already in database
def if_user_already_exists(user_phone, client_socket):
        global clients_db
        if user_phone in clients_db:
            return True

# Insert user to the dictionary
def insert_user(client_socket, user_phone, user_public_key, user_aes_key, user_iv, last_active):
    global clients_db
    clients_db[user_phone] = Client(socket = client_socket, public_key=user_public_key, aes_key=user_aes_key, iv=user_iv, last_active = last_active) #update public key of client
   
    return clients_db

