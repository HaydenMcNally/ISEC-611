import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def oblivious_transfer(sender_inputs):
    """
    Garbler (Sender) encrypts and sends two messages securely.
    """

    # Generate RSA key pair for the sender
    sender_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    sender_public_key = sender_private_key.public_key()

    # Fake key (requested)
    sender_private_key = None  # Removing the private key after generation

    # Serialize sender's public key
    sender_public_key_pem = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Set up a socket to communicate with the evaluator
    host = 'localhost'
    port = 12345  # Change if needed
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()
        print("Garbler waiting for connection...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected to evaluator at {addr}")

            # Receive pickled chooser's public key
            chooser_public_key_pem_list = pickle.loads(conn.recv(4096))
            chooser_public_key = serialization.load_pem_public_key(
                chooser_public_key_pem_list[0], backend=default_backend()
            )

            # Encrypt messages using chooser's public key
            encrypted_inputs = []
            for message in sender_inputs:
                ciphertext = chooser_public_key.encrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_inputs.append(ciphertext)

            # Pickle and send encrypted messages
            conn.sendall(pickle.dumps(encrypted_inputs))
            print("Encrypted inputs sent to evaluator.")

def main():
    sender_inputs = (b"Message 0", b"Message 1")
    oblivious_transfer(sender_inputs)

if __name__ == "__main__":
    main()
