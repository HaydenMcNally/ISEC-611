import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def oblivious_transfer(chooser_bit):
    """
    Evaluator (Receiver) selects one of the encrypted messages securely.
    """

    # Generate RSA key pair for evaluator
    chooser_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    chooser_public_key = chooser_private_key.public_key()

    # Serialize evaluator's public key and place it in a list for pickling
    chooser_public_key_pem_list = [
        chooser_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ]

    # Connect to the Garbler
    host = 'localhost'
    port = 12345  # Change if needed
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("Connected to garbler.")

        # Send pickled public key list
        client_socket.sendall(pickle.dumps(chooser_public_key_pem_list))

        # Receive pickled encrypted inputs
        encrypted_inputs = pickle.loads(client_socket.recv(4096))
        print("Received encrypted inputs from garbler.")

    # Choose encrypted message based on chooser_bit
    chosen_encrypted_message = encrypted_inputs[chooser_bit]

    # Decrypt chosen message with evaluator's private key
    chosen_message = chooser_private_key.decrypt(
        chosen_encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return chosen_message

def main():
    chooser_bit = 1  # Chooser wants the second message
    result = oblivious_transfer(chooser_bit)
    print(f"Chosen message: {result.decode()}")

if __name__ == "__main__":
    main()
