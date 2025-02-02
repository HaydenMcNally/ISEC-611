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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

"""Note used chatgpt to edit comments for grammmar and spelling unedited comment can be found in ogcommentgar.py file in ogcomment folder"""

"""The example consists of two participants: the Garbler (this program) and the Evaluator (the other program).
The Garbler creates the circuit and 'garbles' all the inputs (encrypts them), then sends them to the Evaluator.
The Evaluator processes the garbled circuits to obtain the final result.

We begin in the Garbler with the makeCircuit function. The logic circuit being created consists of:

Gate 1: AND  
Gate 2: OR  
Gate 3: XOR  
The outputs of Gate 1 and Gate 2 feed into Gate 3.
"""


def oblivious_transfer(sender_inputs):
    #Network talk with the evaluator to get the public keys


    #Encyption code from evaluator


    #Send the encyptions back



    pass


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

"""This function creates wire values using the BLAKE2 hash algorithm to generate secure 128-bit hashes, 
which is the recommended wire value size. We also create a random 1 or 0 to append to the end of the hash as a point value. 
This value is unrelated to the input value the hash represents and is used to guide the Evaluator in determining which logic gate 
output to decrypt.

Inputs: None  
Outputs: Two 128-bit hashes representing 0 and 1"""
def getWireValuePair():
    """Start by generating 4 bytes of random data and defining 0 and 1 as base values."""
    random_bytes = secrets.token_bytes(4)
    g1 = 1
    g0 = 0
    """Generate a random point value (0 or 1)."""
    random_point = secrets.randbelow(2)
    """Concatenate the random bytes with the original value, hash it, and append the point value to the end."""
    data = g0 + int.from_bytes(random_bytes, byteorder='big')
    hash_object = hashlib.blake2s(str(data).encode(),digest_size=16) 
    g0 = hash_object.hexdigest()
    g0 = g0 + str(random_point)

    """Use XOR to flip the point bit so the opposite original value has the opposite point value"""
    flip_random_point = random_point ^ 1
    """Hash the other original value."""
    data = g1 + int.from_bytes(random_bytes, byteorder='big')
    hash_object = hashlib.blake2s(str(data).encode(),digest_size=16) 
    g1 = hash_object.hexdigest()
    g1 = g1 + str(flip_random_point)

    return g0 , g1

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


"""Standard AES encryption function. A notable change is that we use two passwords (the two input wire values) as keys, 
concatenating them together to derive the encryption key.

Inputs: Password 1, Password 2, and the plaintext  
Output: Encrypted output"""
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



"""This function generates all the components required for the garbled circuit, including:  
- The Garbler's input wire values  
- The Evaluator's input wire values  
- The logic gates  
- The answer key for the wire values of the final gate  

All wire values are generated using a hash of random inputs, and outputs are encrypted using the input wire values as keys.  

The logic circuit being created consists of:  
Gate 1: AND  
Gate 2: OR  
Gate 3: XOR  
The outputs of Gate 1 and Gate 2 feed into Gate 3.  

Inputs: None  
Outputs: A tuple containing the gates, Garbler's wires, Evaluator's wires, and the answer key.
"""
def makeCircuit():

    """First, we create the wire values using getWireValuePair().  
    Note that we only generate the output wire values for Gate 3, as the outputs from Gate 1 and Gate 2 will be used as inputs to Gate 3."""
    gate1Gar0,gate1Gar1  = getWireValuePair()
    gate1Eval0,gate1Eval1  = getWireValuePair()
    gate1Ans0,gate1Ans1  = getWireValuePair()


    gate2Gar0,gate2Gar1  = getWireValuePair()
    gate2Eval0,gate2Eval1  = getWireValuePair()
    gate2Ans0,gate2Ans1  = getWireValuePair()

    gate3Ans0,gate3Ans1  = getWireValuePair()

    """Store the answer wire values in a list for returning."""
    Anskey = [gate3Ans0,gate3Ans1]


    """Construct a 2D list for each logic gate, where each row represents a truth table entry,  
    containing the two input wire values and the encrypted output.  

    To guide the Evaluator, we store the point values as inputs, and the outputs are AES-encrypted.  
    This ensures that the Evaluator can only decrypt the correct output value and not both possible values.  

    After constructing the gate, we shuffle the list so that no information is leaked based on row indices.
    """
    gate1AND = [[gate1Gar0[-1],gate1Eval0[-1],encyptAnswer(gate1Gar0,gate1Eval0,gate1Ans0)],[gate1Gar1[-1],gate1Eval0[-1],encyptAnswer(gate1Gar1,gate1Eval0,gate1Ans0)],[gate1Gar0[-1],gate1Eval1[-1],encyptAnswer(gate1Gar0,gate1Eval1,gate1Ans0)],[gate1Gar1[-1],gate1Eval1[-1],encyptAnswer(gate1Gar1,gate1Eval1,gate1Ans1)]]
    gate1AND = shuffle_list(gate1AND)

    gate2OR = [[gate2Gar0[-1],gate2Eval0[-1],encyptAnswer(gate2Gar0,gate2Eval0,gate2Ans0)],[gate2Gar1[-1],gate2Eval0[-1],encyptAnswer(gate2Gar1,gate2Eval0,gate2Ans1)],[gate2Gar0[-1],gate2Eval1[-1],encyptAnswer(gate2Gar0,gate2Eval1,gate2Ans1)],[gate2Gar1[-1],gate2Eval1[-1],encyptAnswer(gate2Gar1,gate2Eval1,gate2Ans1)]]
    gate2OR = shuffle_list(gate2OR)

    gate3XOR = [[gate1Ans0[-1],gate2Ans0[-1],encyptAnswer(gate1Ans0,gate2Ans0,gate3Ans0)],[gate1Ans1[-1],gate2Ans0[-1],encyptAnswer(gate1Ans1,gate2Ans0,gate3Ans1)],[gate1Ans0[-1],gate2Ans1[-1],encyptAnswer(gate1Ans0,gate2Ans1,gate3Ans1)],[gate1Ans1[-1],gate2Ans1[-1],encyptAnswer(gate1Ans1,gate3Ans1,gate1Ans0)]]
    gate3XOR = shuffle_list(gate3XOR)

    """After constructing all gate lists, we store them in a list to send to the Evaluator,  
    along with the Evaluator's wire values."""
    gates = [gate1AND,gate2OR,gate3XOR]
    EvalWires = [[gate1Eval0,gate1Eval1],[gate2Eval0,gate2Eval1]]

    """Generate random bits to determine which wire values the Garbler uses for the circuit,  
    then add the corresponding wire values to a list."""
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

    return gates, EvalWires , GarWires , Anskey

"""This function performs Oblivious Transfer (OT) to securely send the Evaluator's wire values  
without revealing both wire values to the Evaluator or revealing the Evaluator's choice to the Garbler.  

This is achieved using RSA key pairs:  
- The Evaluator generates two key pairs and discards one private key.  
- The Evaluator sends both public keys to the Garbler.  
- The Garbler encrypts each wire value with the corresponding public key and sends them back.  
- The Evaluator can only decrypt the value corresponding to the private key they kept.  

This ensures that the Garbler does not know which wire value the Evaluator received.

Inputs:  
- sender_inputs: The wire values to send  
- socket_c: A network socket connected to the Evaluator  

Outputs: None  
"""
def oblivious_transfer(sender_inputs,socket_c):
    """Receive the public keys from the Evaluator and deserialize them."""
    chooser_public_key_pem_list = pickle.loads(socket_c.recv(4096))
    chooser_public_key_0 = serialization.load_pem_public_key(
        chooser_public_key_pem_list[0], backend=default_backend()
    )
    chooser_public_key_1 = serialization.load_pem_public_key(
        chooser_public_key_pem_list[1], backend=default_backend()
    )

    """Encrypt the two wire values with the corresponding public keys.  
    The Evaluator selects which value to receive by controlling the order of public keys sent."""
    encrypted_inputs = []
    message = sender_inputs[0]
    ciphertext_0 = chooser_public_key_0.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_inputs.append(ciphertext_0)
    message = sender_inputs[1]
    ciphertext_1 = chooser_public_key_1.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_inputs.append(ciphertext_1)
    """Send the encrypted wire values back to the Evaluator."""
    socket_c.sendall(pickle.dumps(encrypted_inputs))
    pass


"""This function sends all parts of the circuit to the Evaluator.

Inputs:  
- gates: The logic gates in the circuit  
- EvalWires: The Evaluator's wire values  
- GarWires: The Garbler's wire values  
- AnsKey: The final gate's output wire values  

Outputs:  
- A socket connection to the Evaluator"""
def sendCircuit(gates, EvalWires , GarWires , AnsKey):

    """First, create a socket connection with the Evaluator and confirm that data can be sent and received."""
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

    """To prevent information leakage, we use Oblivious Transfer to securely send the Evaluator's wire values."""
    oblivious_transfer(EvalWires[0],client_socket)
    oblivious_transfer(EvalWires[1],client_socket)

    """Serialize the circuit components to facilitate network transmission."""
    print("Sending gate")
    serialized_data_gates = pickle.dumps(gates)
    print("Sending garbled wires")
    serialized_data_GarWires = pickle.dumps(GarWires)
    print("Sending Answer key")
    serialized_data_Anskey = pickle.dumps(AnsKey)


    """Send each component of the circuit to the Evaluator."""
    client_socket.sendall(serialized_data_gates)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_GarWires)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_Anskey)
    data = client_socket.recv(1024).decode()

    return client_socket

"""This function receives the Evaluator's computed result from the garbled circuit.

Inputs:  
- client_socket: A socket connection to the Evaluator  

Outputs:  
- None (prints the received answer)"""
def getAnswer(client_socket):
    data = client_socket.recv(1024).decode()  # Receive data from the client
    print(f"Answer: {data}")
    client_socket.close()
    pass

def main():


    """The first step is for the Garbler to create the circuit and garble all inputs."""
    gates, EvalWires , GarWires , Anskey = makeCircuit()
    """Next, we send the circuit to the Evaluator."""
    client_socket = sendCircuit(gates, EvalWires , GarWires , Anskey)
    """Once the Evaluator processes the circuit, they send the result back."""
    getAnswer(client_socket)




    pass


if __name__ == "__main__":
    main()