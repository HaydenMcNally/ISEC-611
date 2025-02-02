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


"""The example consists of two participants the Garbler this program and the Evaluator the other program.
The Garbler will create the circuit and 'garble' all the inputs (encrypted them) and then send them to the 
Evaluator. Who then evaluates all circuits to get the final answer. We first start in the Garbler with the makeCircuit function.
The logic circuit being created is Gate 1 - AND, Gate 2 - OR, Gate 3 - XOR. Gate 1 and 2 feed into Gate 3.

"""


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

"""This function is used to create wire values using the blake2 hash alrogithm to create secure 128 bit hashes, which is the
recommend wire value size. We also create a random 1 or 0 to add to the end of the hash as a point value. This value has no
connection to the value the hash is repersenting and is use to tell the evaluators which answer in a logic gate to decrypt.

This function takes no inputs
Outputs two 128 bit hashes repersenting 0 and 1"""
def getWireValuePair():
    """Start by getting 4 bytes of random data and out 0 and 1"""
    random_bytes = secrets.token_bytes(4)
    g1 = 1
    g0 = 0
    """Getting the random point value"""
    random_point = secrets.randbelow(2)
    """Add the random bytes to the original value and hash it, concatinating the point value on the end at the end"""
    data = g0 + int.from_bytes(random_bytes, byteorder='big')
    hash_object = hashlib.blake2s(str(data).encode(),digest_size=16) 
    g0 = hash_object.hexdigest()
    g0 = g0 + str(random_point)

    """Use XOR to flip the point bit so the opposite original value has the opposite point value"""
    flip_random_point = random_point ^ 1
    """Hash the other original value"""
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


"""Standard AES encyption function, notable changes are we take two passwords(The two input wire values) as keys which are concatinated together to
create the key.

Inputs: Password 1, Password 2, and the plaintext
Output: encypted output"""
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



"""This function creates all the components needed for the garbled circuit that being the garblers wires(inputs),
the evaluators wires(inputs), the logic gates themselves and the answer key for the wire values of the last gate.
All the wire values are made using a hash of a random input and the outputs are encypted using the input wire values as keys

The logic circuit being created is Gate 1 - AND, Gate 2 - OR, Gate 3 - XOR. Gate 1 and 2 feed into Gate 3.

This function takes no inputs.
This function outputs are the gates,garblers wires, evaluators wires, and answer key as described above.
"""
def makeCircuit():

    """To start we create the wire values with the function getWireValuePair(), note here we only create the answer
    wire values for gate3 since the answers from gate 1 and 2 are the inputs to gate3"""
    gate1Gar0,gate1Gar1  = getWireValuePair()
    gate1Eval0,gate1Eval1  = getWireValuePair()
    gate1Ans0,gate1Ans1  = getWireValuePair()


    gate2Gar0,gate2Gar1  = getWireValuePair()
    gate2Eval0,gate2Eval1  = getWireValuePair()
    gate2Ans0,gate2Ans1  = getWireValuePair()

    gate3Ans0,gate3Ans1  = getWireValuePair()

    """Putting the answer wire values in a list to return"""
    Anskey = [gate3Ans0,gate3Ans1]


    """With the wire values we create a 2D list of each logic gate where the items in the first list are rows of the turth table and the items in the second list are the two inputs and the output of that row.
    To direct the evaluator in decrpytion we add the point values as the inputs for each row and the answers are encypted with AES so the evaluator can only learn the wire value of the answer and not both values.
    Note that when creating the gate we are manually putting the correct wire values to create the correct logic gate.
    After the whole gate is created we shuffle the list so that no information is given based on the index of a row."""
    gate1AND = [[gate1Gar0[-1],gate1Eval0[-1],encyptAnswer(gate1Gar0,gate1Eval0,gate1Ans0)],[gate1Gar1[-1],gate1Eval0[-1],encyptAnswer(gate1Gar1,gate1Eval0,gate1Ans0)],[gate1Gar0[-1],gate1Eval1[-1],encyptAnswer(gate1Gar0,gate1Eval1,gate1Ans0)],[gate1Gar1[-1],gate1Eval1[-1],encyptAnswer(gate1Gar1,gate1Eval1,gate1Ans1)]]
    gate1AND = shuffle_list(gate1AND)

    gate2OR = [[gate2Gar0[-1],gate2Eval0[-1],encyptAnswer(gate2Gar0,gate2Eval0,gate2Ans0)],[gate2Gar1[-1],gate2Eval0[-1],encyptAnswer(gate2Gar1,gate2Eval0,gate2Ans1)],[gate2Gar0[-1],gate2Eval1[-1],encyptAnswer(gate2Gar0,gate2Eval1,gate2Ans1)],[gate2Gar1[-1],gate2Eval1[-1],encyptAnswer(gate2Gar1,gate2Eval1,gate2Ans1)]]
    gate2OR = shuffle_list(gate2OR)

    gate3XOR = [[gate1Ans0[-1],gate2Ans0[-1],encyptAnswer(gate1Ans0,gate2Ans0,gate3Ans0)],[gate1Ans1[-1],gate2Ans0[-1],encyptAnswer(gate1Ans1,gate2Ans0,gate3Ans1)],[gate1Ans0[-1],gate2Ans1[-1],encyptAnswer(gate1Ans0,gate2Ans1,gate3Ans1)],[gate1Ans1[-1],gate2Ans1[-1],encyptAnswer(gate1Ans1,gate3Ans1,gate1Ans0)]]
    gate3XOR = shuffle_list(gate3XOR)

    """Once all the Gate list are constructed we put them in a list to send to the evaluator, same with the evaluators wire values"""
    gates = [gate1AND,gate2OR,gate3XOR]
    EvalWires = [[gate1Eval0,gate1Eval1],[gate2Eval0,gate2Eval1]]

    """We get some random bits to decide what values the garble is using for the circuit and add the corrisponding wire values to a list"""
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

"""This function is for oblivious transfer sending the evaluators wires values to them without them learning both wire values
and for the garbler not to learn which wire value their using. This is done with RSA key pairs the evaluator creates two key pairs
and gets rid of one of the private keys. They send both public keys and the garbler encypts the wire values with the corrisponding public key
and send encypted wire values back. The Evaluator can then only decrypt the one they still have the private key two and the garbler
doesn't know which public key still has the private key so hence doesn't learn which wire the evaluator has.

Inputs: sender_inputs - wire values to send
        socket_c - network socket connected with the evaluator

Outputs: None
"""
def oblivious_transfer(sender_inputs,socket_c):
    """
    Garbler (Sender) encrypts and sends two messages securely.
    """
   
    #print(sender_inputs)
    # Receive pickled chooser's public key
    """Recieve the public keys and unserialize them"""
    chooser_public_key_pem_list = pickle.loads(socket_c.recv(4096))
    chooser_public_key_0 = serialization.load_pem_public_key(
        chooser_public_key_pem_list[0], backend=default_backend()
    )
    chooser_public_key_1 = serialization.load_pem_public_key(
        chooser_public_key_pem_list[1], backend=default_backend()
    )

    """Encypt the two wire values with the corrisponding(Matching indexes of wire and public key,Evaluator can choose
    which value to get by changing the order of public keys) public keys."""
    # Encrypt messages using chooser's public key
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
    """Sending the encypted wire values back"""
    # Pickle and send encrypted messages
    socket_c.sendall(pickle.dumps(encrypted_inputs))
    pass


"""This function is for sending all parts of the circuit to the evaluator.

Inputs: Gates- logic gate in the circuit
        EvalWires - Evaluator wire values
        GarWires - Garblers wire values
        Anskey - wires of the last gates answers
        
Outputs: Socket - network socket connected with the evaluator"""
def sendCircuit(gates, EvalWires , GarWires , AnsKey):

    """First we create a socket with the evaluator and confirm we can send and recieve"""
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

    """The to not leak information to the garbler when giving the evaluators wire value we use an oblivious transfer to send them the values"""
    oblivious_transfer(EvalWires[0],client_socket)
    oblivious_transfer(EvalWires[1],client_socket)

    """We serialize the circuits information to easily send it over the network"""
    print("Sending gate")
    serialized_data_gates = pickle.dumps(gates)
    print("Sending garbled wires")
    serialized_data_GarWires = pickle.dumps(GarWires)
    print("Sending Answer key")
    serialized_data_Anskey = pickle.dumps(AnsKey)


    """Sending each componet to the evaluator"""
    client_socket.sendall(serialized_data_gates)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_GarWires)
    data = client_socket.recv(1024).decode()
    client_socket.sendall(serialized_data_Anskey)
    data = client_socket.recv(1024).decode()

    return client_socket

"""Function to recive back the garbled circuit answer from the evaluator.

Input: Socket connected with evaluator
Output: None"""
def getAnswer(client_socket):
    data = client_socket.recv(1024).decode()  # Receive data from the client
    print(f"Answer: {data}")
    client_socket.close()
    pass

def main():


    """The first step is for the Garbler to make the circuit and garble all the inputs"""
    gates, EvalWires , GarWires , Anskey = makeCircuit()
    """Next we send the circuit to the Evaluator"""
    client_socket = sendCircuit(gates, EvalWires , GarWires , Anskey)
    """Once the evaluator evaluates the circuit they send us the answer back"""
    getAnswer(client_socket)




    pass


if __name__ == "__main__":
    main()