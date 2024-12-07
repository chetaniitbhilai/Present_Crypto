import socket
import threading
from software.present import present_encrypt, present_decrypt

KEY = 0x00000000000000000001  # 80-bit key

# List to keep track of all connected clients
clients = []

def handle_client(client_socket, client_address):
    print(f"Client {client_address} connected.")
    while True:
        try:
            # Receive data from client
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break
            ciphertext = int.from_bytes(encrypted_data, 'big')
            
            # Decrypt the data
            plaintext = present_decrypt(ciphertext, KEY)
            print(f"Received encrypted: {hex(ciphertext)}")
            print(f"Decrypted message: {plaintext}")
            
            # Broadcast the decrypted message to all clients
            message_to_broadcast = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
            broadcast(message_to_broadcast, client_socket)
        except Exception as e:
            print(f"Error with client {client_address}: {e}")
            break

    # Remove client from list when done
    clients.remove(client_socket)
    client_socket.close()
    print(f"Client {client_address} disconnected.")

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except Exception as e:
                print(f"Error broadcasting to a client: {e}")
                client.close()
                clients.remove(client)

def start_server(host='0.0.0.0', port=1195):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_server()
