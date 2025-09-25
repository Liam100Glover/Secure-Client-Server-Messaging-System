import socket  # Import socket library for network communication
import threading  # Import threading for handling multiple clients
import time  # Imports time to add time between what happens purely to make it easier to read
import hashlib  # Used for message content verification
import secrets  # Used for diffie hellman key exchange
import json  # Used for storing messages between previous sessions
from datetime import datetime  # Used to date mark each message log
from Crypto.Cipher import AES  # Standard used to encrypt messages with key
from Crypto.Util.Padding import unpad  # Allows to un pad encrypted message


# Constants for server configuration
HEADER = 64  # Size of message header
PORT = 5051  # Port to listen on
SERVER = socket.gethostbyname(socket.gethostname())  # Get the IP address of the server
ADDR = (SERVER, PORT)  # Combine IP and port into a single address

FORMAT = 'utf-8'  # Message format for encoding/decoding
DISCONNECT_MESSAGE = "DISCONNECT"  # Message indicating client disconnection
GET_LOGS = "RETRIEVE"  # Message to match client which gets message logs
confirmation_message = "Message received - Content Verified"  # Server response to getting a message
AES_KEY = b'\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef'
# AES encryption/decryption key
p = 23
g = 5  # Base and prime numbers used in diffie hellman key exchange

# Initialize a counter for active connections and a lock for thread-safe operations
active_connections = 0
active_connections_lock = threading.Lock()

# Create a server socket using IPv4 and TCP protocol
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)  # Bind the server to the address


def append_to_json_file(data, filename="logs.json"):
    try:
        # Try to open the log file and load existing data
        with open(filename, 'r') as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        # If file doesn't exist, start with an empty list
        existing_data = []

    # Append the new data entry to the list
    existing_data.append(data)

    # Write the updated data back to the file
    with open(filename, 'w') as file:
        json.dump(existing_data, file, indent=4)


def get_logs(filename="logs.json", last_n=5):
    try:
        # Open the log file and load all logs
        with open(filename, 'r') as file:
            logs = json.load(file)
            # Return the last `last_n` entries as a JSON string
            return json.dumps(logs[-last_n:])
    except FileNotFoundError:
        # If the file is not found, print an error message and return an empty list
        print("[LOG ERROR]")
        return json.dumps([])
    except Exception as e:
        # Handle any other exceptions and return an empty list
        print(f"[ERROR] Failed to read logs: {e}")
        return json.dumps([])


def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # Extract the first 16 bytes as the IV
    ct = ciphertext[16:]  # The remaining bytes are the actual ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Initialize the AES cipher in CBC mode with the IV
    pt = unpad(cipher.decrypt(ct), AES.block_size)  # Decrypt the ciphertext and un pad it
    return pt.decode(FORMAT)  # Convert the decrypted plaintext from bytes to a string


def generate_dh_keys():
    private_key = secrets.randbelow(p)  # Generate a private key as a random number below p
    public_key = pow(g, private_key, p)  # Calculate the public key using g^private_key mod p
    return private_key, public_key  # Return both private and public keys


def compute_shared_secret(client_public_key, server_private_key):
    return pow(client_public_key, server_private_key, p)  # Calculate g^(client_private_key * server_private_key) mod p


def handle_client(conn, addr):
    global active_connections
    with active_connections_lock:
        active_connections += 1

    # Diffie-Hellman Key Exchange
    server_private_key, server_public_key = generate_dh_keys()
    conn.send(str(server_public_key).encode(FORMAT))  # Send server's public key
    try:
        client_public_key = int(conn.recv(1024).decode(FORMAT))  # Receive client's public key
        shared_secret = compute_shared_secret(client_public_key, server_private_key)
        aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
    except Exception as e:
        print(f"[ERROR] Diffie-Hellman exchange failed with {addr}: {e}")
        aes_key = AES_KEY  # Fallback to pre-shared key

    # Flag to keep the connection loop running
    connected = True
    try:
        while connected:
            # Receive the length of the incoming message
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if not msg_length:
                break  # If no message length is received, break the loop
            msg_length = int(msg_length)

            # Receive the actual message based on the received length
            combined_msg = conn.recv(msg_length)
            if not combined_msg:
                break  # If no message is received, break the loop

            # Split the received message into the encrypted part and its hash
            encrypted_msg, received_hash = combined_msg.rsplit(b'||', 1)
            received_hash = received_hash.decode()  # Decode the hash from bytes to string

            # Compute the hash of the encrypted message for verification
            computed_hash = hashlib.sha256(encrypted_msg).hexdigest()

            # Verify if the computed hash matches the received hash
            if computed_hash == received_hash:
                # Decrypt the message using the AES key
                msg = decrypt_message(encrypted_msg, aes_key)

                # Get the current timestamp for logging
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Prepare the data to be saved in the log
                data_to_save = {
                    "client": str(addr),
                    "message": msg,
                    "time": current_time
                }

                # Append the log entry to the JSON file
                append_to_json_file(data_to_save)

                # Handle specific messages such as disconnection or log retrieval
                if msg == DISCONNECT_MESSAGE:
                    connected = False  # Stop the connection loop
                elif msg == GET_LOGS:
                    logs = get_logs()  # Retrieve the last 5 logs
                    conn.send(logs.encode(FORMAT))  # Send the logs back to the client

                # Print the decrypted message for server-side logging
                print(f"[{addr}] - {msg}")

                # Send a confirmation message back to the client
                conn.send(confirmation_message.encode(FORMAT))
            else:
                # If the hash does not match, print an error message
                print(f"[ERROR] Hash mismatch for message from {addr}")

    # Handle exceptions such as unexpected client disconnection
    except ConnectionResetError:
        print(f"[CLIENT] {addr} disconnected unexpectedly.")
    except Exception as e:
        # Print any other exceptions that occur during the connection
        print(f"[EXCEPTION] An error occurred with {addr}: {e}")
    finally:
        # After handling the client, decrement the active connection counter
        with active_connections_lock:
            active_connections -= 1
        # Close the client connection and log the disconnection
        conn.close()
        print(f"[{addr}] disconnected. [ACTIVE CONNECTIONS] - {active_connections}")


def start():
    server.listen()  # Puts server into a listen state waiting for connections, switches states once connected
    print(f"[LISTENING] Server is listening on {SERVER}")  # Info for user
    while True:
        conn, addr = server.accept()  # Accepts incoming connections
        thread = threading.Thread(target=handle_client, args=(conn, addr))  # Sends instance of target and address to
        # handle client function and switches states
        thread.start()


# Start the server
print(f"[STARTING SERVER]")
time.sleep(1)
start()
