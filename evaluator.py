from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import socket
import secrets
import pickle

# Derive a 32-byte key from a password (for AES-256)
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def aes_decrypt(encrypted_text: str, password1: str , password2: str):
    encrypted_data = base64.b64decode(encrypted_text)
    
    salt = encrypted_data[:16]  # Extract salt
    iv = encrypted_data[16:32]  # Extract IV
    ciphertext = encrypted_data[32:]  # Extract ciphertext

    key = derive_key(password1 + password2, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length].decode()

    return plaintext

def evaluateCircuit(gates, EvalWires , GarWires, Anskey):
    gate1Eval = EvalWires[0]
    gate1Garb = GarWires[0]

    gate2Eval = EvalWires[1]
    gate2Garb = GarWires[1]

    gate1point0 = gate1Garb[-1]
    gate1point1 = gate1Eval[-1]

    gate2point0 = gate2Garb[-1]
    gate2point1 = gate2Eval[-1]

    gate1 = gates[0]
    gate2 = gates[1]
    gate3 = gates[2]

    for rows in gate1:
        if gate1point0 == rows[0] and gate1point1 == rows[1]:
            print("Gate1 Decrypt", rows[2],gate1Garb,gate1Eval)
            gate1Ans = aes_decrypt(rows[2],gate1Garb,gate1Eval)

    for rows in gate2:
        if gate2point0 == rows[0] and gate2point1 == rows[1]:
            print("Gate2 Decrypt", rows[2],gate2Garb,gate2Eval)
            gate2Ans = aes_decrypt(rows[2],gate2Garb,gate2Eval)

    gate3point0 = gate1Ans[-1]
    gate3point1 = gate2Ans[-1]

    for rows in gate3:
        if gate3point0 == rows[0] and gate3point1 == rows[1]:
            print("Gate3 Decrypt", rows[2],gate1Ans,gate2Ans)
            gate3Ans = aes_decrypt(rows[2],gate1Ans,gate2Ans)

    for index,ans in enumerate(Anskey):
        if ans == gate3Ans:
            answer = index
    print(answer)
    return answer

def oblivious_transfer(bit,socket_s):
    response = socket_s.recv(4096).decode()  # Receive response from the server
    print(f"Oblivious_transfer: {response}")
    socket_s.send("R".encode())
    return response

def getCircuit():
    # Server details
    HOST = '127.0.0.1'  # Server IP (localhost for testing)
    PORT = 12345        # Must match the server port

    # Create a socket (IPv4, TCP)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))  # Connect to the server

    message = "Hello, Server!"
    client_socket.send(message.encode())  # Send data

    response = client_socket.recv(1024).decode()  # Receive response from the server
    print(f"Server response: {response}")


    random_bit1 = secrets.randbelow(2)
    random_bit2 = secrets.randbelow(2)
    print("Gate 1 random bit is ", random_bit1, "Gate 2 random bit is ", random_bit2)
    gate1Eval = oblivious_transfer(random_bit1,client_socket)
    gate2Eval = oblivious_transfer(random_bit2,client_socket)
    EvalWires = [gate1Eval,gate2Eval]

    print("recieved gate")
    gate_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())
    print("recieved garwires")
    GarWires_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())
    print("recieved anskey")
    Anskey_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())

    gates = pickle.loads(gate_pickled)
    print("gate: ", gates)
    GarWires = pickle.loads(GarWires_pickled)
    print("garwire: ", GarWires)
    Anskey = pickle.loads(Anskey_pickled)
    print("Anskey: ", Anskey)
    print("EvalWires: ", EvalWires)
    return gates, EvalWires , GarWires, Anskey ,client_socket

def sendAnswer(answer,client_socket):
    client_socket.send(str(answer).encode())
    client_socket.close()
    pass

def main():
    gates, EvalWires , GarWires, Anskey ,client_socket = getCircuit()
    answer = evaluateCircuit(gates, EvalWires , GarWires, Anskey)
    sendAnswer(answer,client_socket)
    pass


if __name__ == "__main__":
    main()