import sys  # Used to successfully exit client code when server crashes
import socket  # Import socket library for network communication
import time  # Import time library for timing
import hashlib  # Hash library to help with message content verification
import secrets  # Used for diffie hellman key exchange
from Crypto.Cipher import AES  # The encryption standard I am using for network traffic
from Crypto.Util.Padding import pad  # Padding for the encryption


# Constants for client configuration
HEADER = 64  # Size of message header
PORT = 5051  # Port to connect to
SERVER = socket.gethostbyname(socket.gethostname())  # Get the IP address of the server
ADDR = (SERVER, PORT)  # Combine IP and port into a single address

FORMAT = 'utf-8'  # Message format for encoding/decoding
DISCONNECT_MESSAGE = "DISCONNECT"  # Message to disconnect from the server
GET_LOGS = "RETRIEVE"  # Message to match server which gets message logs
AES_KEY = b'\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef'
# AES encryption/decryption key
p = 23
g = 5  # Base and prime numbers used in diffie hellman key exchange
shared_secret = None


def compute_shared_secret(server_public_key1, client_private_key1):
    return pow(server_public_key1, client_private_key1, p)  # Calculate g^(client_private_key * server_private_key) mod p


def generate_dh_keys(p1, g1):
    private_key = secrets.randbelow(p)
    public_key = pow(g1, private_key, p1)
    return private_key, public_key


def encrypt_message(e_message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(e_message.encode(FORMAT), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes  # Prepend the IV to the ciphertext


def receive_response():
    response = client.recv(1024).decode(FORMAT)  # Assuming the response won't be longer than 1024 bytes
    print("[SERVER] -", response)  # User info


def send(msg):
    if shared_secret:
        diffie_key = hashlib.sha256(str(shared_secret).encode()).digest()  # Obtain diffie key
        encrypted_message = encrypt_message(msg, diffie_key)  # Encrypt the message
        message_hash = hashlib.sha256(encrypted_message).hexdigest()  # Compute the hash of the encrypted message
    else:
        encrypted_message = encrypt_message(msg, AES_KEY)  # Encrypt the message using the shared secret key
        message_hash = hashlib.sha256(encrypted_message).hexdigest()  # Compute the hash of the encrypted message

    # Combine the encrypted message and its hash, separated by a unique separator
    combined_message = encrypted_message + b'||' + message_hash.encode()

    msg_length = len(combined_message)  # Get the length of the combined message
    send_length = str(msg_length).encode(FORMAT)  # Encode the length of the message
    send_length += b' ' * (HEADER - len(send_length))  # Pad the length to the header size

    try:
        client.send(send_length)  # Send the length of the combined message
        client.send(combined_message)  # Send the combined message (encrypted message + hash)
    except:
        print("[SERVER ERROR - PLEASE RESTART]")  # Exception handled if message can't send
        sys.exit(0)


def message():
    connected = True  # Infinite message loop for connected client
    while connected:
        time.sleep(1.5)
        msg = input(f"Enter your message to server {SERVER}: ")
        time.sleep(1)
        if msg.lower() == "q":  # Different state depending on user input
            print("[DISCONNECTING...]")
            time.sleep(1)
            connected = False  # Ends loops as user wants to disconnect
            send(DISCONNECT_MESSAGE)  # Tells server to enter the disconnect client state
        elif msg.lower() == 'v':
            print("Retrieving Message Logs... ")
            time.sleep(1)
            send(GET_LOGS)  # Sends get logs request to server
            receive_response()  # Shows servers response confirming message received
        else:  # Second state if user stays connected
            send(msg)  # Send msg
            receive_response()  # Shows servers response confirming message received


# Create a client socket using IPv4 and TCP protocol
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect(ADDR)  # Connects client to server
    print(f"Welcome to '{SERVER}', please enter 'q' if you wish to disconnect or press 'v' to view past messages.")

    # Diffie-Hellman Key Exchange
    client_private_key, client_public_key = generate_dh_keys(p, g)
    client.send(str(client_public_key).encode(FORMAT))  # Send client's public key
    server_public_key = int(client.recv(1024).decode(FORMAT))  # Receive server's public key
    shared_secret = compute_shared_secret(server_public_key, client_private_key)

    # Convert the shared secret into a format suitable for AES encryption
    # (e.g., hash it to get a fixed-size key)
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

    # Continue with the message loop
    message()

except:
    print("[SERVER OFFLINE]")
    sys.exit(0)
