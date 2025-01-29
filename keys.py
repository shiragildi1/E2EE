import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#creating keys for clients and saving them
def gen_keys_for_client(phone):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PublicFormat.SubjectPublicKeyInfo)
   
    print("USER PRIVATE KEY: ", private_key)
    print("USER PUBLIC KEY: ", public_key)
      
    fname = f"public_key_{phone}.pem"
    with open(fname, "wb") as f:
        f.write(public_pem)
    return private_key

#generation keys for server and saving them
def gen_keys_for_server():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("SERVER PRIVATE KEY: ", private_key)
    print("SERVER PUBLIC KEY: ", public_key)

    with open("public_key.pem", "wb") as f:
        f.write(public_pem)
    return private_key

#Read te public key from pem file
def load_public_key_from_file(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


# Extracting the client's public key from the file
def Extract_client_pub_key(phone):
    filename = f"public_key_{phone}.pem"
    try:
        with open(filename, "rb") as key_file:
            user_public_key = serialization.load_pem_public_key(key_file.read())
        
        # Return the public key in PEM format as bytes
        return user_public_key
    
    except Exception as e:
        raise ValueError(f"Error reading public key file '{filename}': {e}")

# Extracting the server's public key from the file
def Extract_server_pub_key():
    filename = "public_key.pem"
    
    if not os.path.exists(filename):
        print(f"Public key file '{filename}' not found. Generating keys...")
        gen_keys_for_server()
    
    try:
        with open(filename, "rb") as key_file:
            server_public_key = serialization.load_pem_public_key(key_file.read())
        return server_public_key
    
    except Exception as e:
        raise ValueError(f"Error reading public key file '{filename}': {e}")

def remove_keys(phone):
    filename = f"public_key_{phone}.pem"
    if os.path.exists(filename):
        os.remove(filename)
    else:
        print("file does not exist")
