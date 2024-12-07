import socket
from software.present import present_encrypt, present_decrypt
import threading

KEY = 0x00000000000000000001  # 80-bit key

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            plaintext = int.from_bytes(data, 'big')
            print(f"\nBroadcasted message: {plaintext}")
        except Exception as e:
            print(f"Error receiving broadcast: {e}")
            break

def start_client(server_ip='127.0.0.1', port=1195):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, port))
    print(f"Connected to server at {server_ip}:{port}")

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    try:
        while True:
            # Get message from user
            message = input("Enter an integer to send: ")
            try:
                plaintext = int(message)  # Ensure it is an integer
                if plaintext.bit_length() > 64:
                    print("Integer too large! Please enter a smaller number.")
                    continue
            except ValueError:
                print("Invalid input! Please enter a valid integer.")
                continue
            
            # Encrypt the integer
            ciphertext = present_encrypt(plaintext, KEY)
            print(f"Sending encrypted: {hex(ciphertext)}")
            client_socket.send(ciphertext.to_bytes(8, 'big'))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
