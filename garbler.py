import secrets
import hashlib
from cryptography.fernet import Fernet 
import random
import pickle
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64

def shuffle_list(lst):
    """
    Shuffles the order of elements in a list.

    Args:
        lst: The list to be shuffled.

    Returns:
        A new list with the elements shuffled.
    """
    shuffled_list = lst.copy()  # Create a copy to avoid modifying the original list
    random.shuffle(shuffled_list)
    return shuffled_list


def getWireValuePair():
    random_bytes = secrets.token_bytes(4)
    g1 = 1
    g0 = 0

    random_Add = secrets.randbelow(2)
   # print(random_Add)
    data = g0 + int.from_bytes(random_bytes, byteorder='big')
    hash_object = hashlib.sha1(str(data).encode()) 
    g0 = hash_object.hexdigest()
    g0 = g0 + str(random_Add)

    flip_random_Add = random_Add ^ 1
    #print(flip_random_Add)
    data = g1 + int.from_bytes(random_bytes, byteorder='big')
    hash_object = hashlib.sha1(str(data).encode()) 
    g1 = hash_object.hexdigest()
    g1 = g1 + str(flip_random_Add)

    print(g1,g0)
    return g1 , g0

# Generate a random 16-byte IV (Initialization Vector)
def generate_iv():
    return os.urandom(16)

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

def encyptAnswer(password1: str, password2: str, plaintext: str):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password1+password2, salt)
    iv = generate_iv()  # Generate a random IV

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to be multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + chr(padding_length) * padding_length

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode()



def makeCircuit():
    encyptedAnswers = []

    gate1Gar0,gate1Gar1  = getWireValuePair()
    gate1Eval0,gate1Eval1  = getWireValuePair()
    gate1Ans0,gate1Ans1  = getWireValuePair()


    gate2Gar0,gate2Gar1  = getWireValuePair()
    gate2Eval0,gate2Eval1  = getWireValuePair()
    gate2Ans0,gate2Ans1  = getWireValuePair()

    gate3Ans0,gate3Ans1  = getWireValuePair()

    Anskey = [gate3Ans0,gate3Ans1]

    gate1AND = [[gate1Gar0[-1],gate1Eval0[-1],encyptAnswer(gate1Gar0,gate1Eval0,gate1Ans0)],[gate1Gar1[-1],gate1Eval0[-1],encyptAnswer(gate1Gar1,gate1Eval0,gate1Ans0)],[gate1Gar0[-1],gate1Eval1[-1],encyptAnswer(gate1Gar0,gate1Eval1,gate1Ans0)],[gate1Gar1[-1],gate1Eval1[-1],encyptAnswer(gate1Gar1,gate1Eval1,gate1Ans1)]]
    gate1AND = shuffle_list(gate1AND)

    gate2OR = [[gate2Gar0[-1],gate2Eval0[-1],encyptAnswer(gate2Gar0,gate2Eval0,gate2Ans0)],[gate2Gar1[-1],gate2Eval0[-1],encyptAnswer(gate2Gar1,gate2Eval0,gate2Ans1)],[gate2Gar0[-1],gate2Eval1[-1],encyptAnswer(gate2Gar0,gate2Eval1,gate2Ans1)],[gate2Gar1[-1],gate2Eval1[-1],encyptAnswer(gate2Gar1,gate2Eval1,gate2Ans1)]]
    gate2OR = shuffle_list(gate2OR)

    gate3XOR = [[gate1Ans0[-1],gate2Ans0[-1],encyptAnswer(gate1Ans0,gate2Ans0,gate3Ans0)],[gate1Ans1[-1],gate2Ans0[-1],encyptAnswer(gate1Ans1,gate2Ans0,gate3Ans1)],[gate1Ans0[-1],gate2Ans1[-1],encyptAnswer(gate1Ans0,gate2Ans1,gate3Ans1)],[gate1Ans1[-1],gate2Ans1[-1],encyptAnswer(gate1Ans1,gate3Ans1,gate1Ans0)]]
    gate3XOR = shuffle_list(gate3XOR)

    gates = [gate1AND,gate2OR,gate3XOR]
    EvalWires = [[gate1Eval0,gate1Eval1],[gate2Eval0,gate2Eval1]]

    random_bit1 = secrets.randbelow(2)
    random_bit2 = secrets.randbelow(2)
    print("Gate 1 random bit is ", random_bit1, "Gate 2 random bit is ", random_bit2)
    GarWires = []
    if random_bit1 == 0:
        GarWires.append(gate1Gar0)
    else:
        GarWires.append(gate1Gar1)
    if random_bit2 == 0:
        GarWires.append(gate2Gar0)
    else:
        GarWires.append(gate2Gar1)
    print("EvalWires: \n", EvalWires)
    print("GarWires: \n", GarWires)
    print("Gates: \n", gates)


    return gates, EvalWires , GarWires , Anskey

def oblivious_transfer(EvalWires,socket_C):
    gate1 = EvalWires[0]
    print(f"Oblivious_transfer: {gate1}")
    socket_C.send(gate1.encode())
    r = socket_C.recv(1024).decode()
    pass

def sendCircuit(gates, EvalWires , GarWires , AnsKey):
    HOST = '127.0.0.1'  # Listen on localhost
    PORT = 12345        # Port to listen on

    # Create a socket (IPv4, TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))  # Bind the socket to the address
    server_socket.listen(5)

    print(f"Server listening on {HOST}:{PORT}")

    client_socket, client_address = server_socket.accept()  # Accept a new connection
    print(f"Connection from {client_address}")

    data = client_socket.recv(1024).decode()  # Receive data from the client
    print(f"Received: {data}")

    response = "Message received!"
    client_socket.send(response.encode())  # Send a response back

    oblivious_transfer(EvalWires[0],client_socket)
    oblivious_transfer(EvalWires[1],client_socket)
    print("Sending gate")
    serialized_data_gates = pickle.dumps(gates)
    print("Sending garbled wires")
    serialized_data_GarWires = pickle.dumps(GarWires)
    print("Sending anskey")
    serialized_data_Anskey = pickle.dumps(AnsKey)

    client_socket.sendall(serialized_data_gates)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_GarWires)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_Anskey)
    data = client_socket.recv(1024).decode()

    return client_socket

def getAnswer(client_socket):

    data = client_socket.recv(1024).decode()  # Receive data from the client
    print(f"Answer: {data}")
    client_socket.close()
    pass

def main():



    gates, EvalWires , GarWires , Anskey = makeCircuit()
    client_socket = sendCircuit(gates, EvalWires , GarWires , Anskey)
    getAnswer(client_socket)




    pass


if __name__ == "__main__":
    main()