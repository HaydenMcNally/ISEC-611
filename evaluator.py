from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import socket
import secrets
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

"""Note used chatgpt to edit comments for grammmar and spelling unedited comment can be found in ogcommenteval.py file in ogcomment folder"""


"""The example consists of two participants: the Garbler (the other program) and the Evaluator (this program).
The Garbler creates the circuit and 'garbles' all the inputs (encrypts them), then sends them to the Evaluator.
The Evaluator processes the garbled circuits to obtain the final result.

We begin in the Garbler with the makeCircuit function. The logic circuit being created consists of:

Gate 1: AND  
Gate 2: OR  
Gate 3: XOR  
The outputs of Gate 1 and Gate 2 feed into Gate 3.
"""


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

"""Standard AES decryption function. A notable change is that we take two passwords (the two input wire values) as keys,
which are concatenated together to create the decryption key.

Inputs: Encrypted text, Password 1, Password 2
Output: Decrypted output"""
def aes_decrypt(encrypted_text: str, password1: str, password2: str):
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



"""This function evaluates the garbled circuit. Using the decrypted wire values, we determine the correct output 
for each gate, ultimately leading to the final circuit answer.

Inputs:
- gates: The logic gates in the circuit
- EvalWires: Evaluator wire values
- GarWires: Garbler wire values
- Anskey: Wires of the final gate's answers

Output: The circuit's final answer"""
def evaluateCircuit(gates, EvalWires, GarWires, Anskey):
    """Extracting wire values, point values, and gates from input lists."""
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

    """Looping through each row in gate one to find the matching input point values
    and determine which row to decrypt for the gate's answer."""
    for rows in gate1:
        if gate1point0 == rows[0] and gate1point1 == rows[1]:
            gate1Ans = aes_decrypt(rows[2], gate1Garb, gate1Eval)

    """Repeating the process for gate two."""
    for rows in gate2:
        if gate2point0 == rows[0] and gate2point1 == rows[1]:
            gate2Ans = aes_decrypt(rows[2], gate2Garb, gate2Eval)

    """Extracting point values of gate 1 and 2 results for use as input to gate 3."""
    gate3point0 = gate1Ans[-1]
    gate3point1 = gate2Ans[-1]

    """Finding the result for gate 3."""
    for rows in gate3:
        if gate3point0 == rows[0] and gate3point1 == rows[1]:
            gate3Ans = aes_decrypt(rows[2], gate1Ans, gate2Ans)

    """Matching the final wire value with the answer key to determine the circuit's final output."""
    for index, ans in enumerate(Anskey):
        if ans == gate3Ans:
            answer = index
    
    print("Answer: ", answer)
    return answer


"""This function performs Oblivious Transfer (OT) to securely send the Evaluator's wire values
without revealing both wire values to the Evaluator or exposing the Evaluator's choice to the Garbler.

Process:
- The Evaluator generates two RSA key pairs and discards one private key.
- The Evaluator sends both public keys to the Garbler.
- The Garbler encrypts each wire value with the corresponding public key and sends them back.
- The Evaluator can decrypt only the value corresponding to the private key they retained.

This ensures that the Garbler does not know which wire value the Evaluator received.

Inputs: chooser_bit - the bit indicating which value to receive
        socket_c - network socket connected to the Evaluator

Output: chosen wire value"""
def oblivious_transfer(chooser_bit, socket_c):
    """Generate two RSA key pairs; keep one private key and discard the other."""
    chooser_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    chooser_public_key = chooser_private_key.public_key()
    
    chooser_public_key_pem_list = [
        chooser_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ]
    
    """Create a fake key pair and discard its private key."""
    fake_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    fake_public_key = fake_private_key.public_key()
    fake_private_key = None  # Remove private key after generation

    fake_public_key_pem = fake_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    """Ensure the desired wire value is encrypted with the retained private key."""
    if chooser_bit == 0:
        chooser_public_key_pem_list.append(fake_public_key_pem)
    else:
        chooser_public_key_pem_list.insert(0, fake_public_key_pem)
    
    socket_c.sendall(pickle.dumps(chooser_public_key_pem_list))
    encrypted_inputs = pickle.loads(socket_c.recv(4096))
    
    """Decrypt the chosen message."""
    chosen_encrypted_message = encrypted_inputs[chooser_bit]
    chosen_message = chooser_private_key.decrypt(
        chosen_encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return chosen_message

"""This function receives the garbled circuit from the Garbler, sets up a network socket connection,
performs oblivious transfer to retrieve the Evaluator's wire values, and receives additional data required to evaluate the circuit.

Inputs: None
Outputs:
- gates: Logic gates in the circuit
- EvalWires: Evaluator wire values
- GarWires: Garbler wire values
- AnsKey: Output wire values of the final gate"""
def getCircuit():
    """Establishing a network socket connection with the Garbler."""
    HOST = '127.0.0.1'  # Server IP (localhost for testing)
    PORT = 12345        # Must match the server port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    message = "Hello, Server!"
    client_socket.send(message.encode())
    response = client_socket.recv(1024).decode()
    print(f"Server response: {response}")

    """Randomly selecting bits for the Evaluator and retrieving the corresponding wire values using oblivious transfer."""
    random_bit1 = secrets.randbelow(2)
    random_bit2 = secrets.randbelow(2)
    print("Gate 1 random bit:", random_bit1, "Gate 2 random bit:", random_bit2)
    gate1Eval = oblivious_transfer(random_bit1, client_socket).decode()
    gate2Eval = oblivious_transfer(random_bit2, client_socket).decode()
    EvalWires = [gate1Eval, gate2Eval]

    """Receiving and deserializing the garbled circuit components."""
    print("Received gates")
    gates = pickle.loads(client_socket.recv(4096))
    client_socket.send("R".encode())
    
    print("Received Garbler's wires")
    GarWires = pickle.loads(client_socket.recv(4096))
    client_socket.send("R".encode())
    
    print("Received answer key")
    Anskey = pickle.loads(client_socket.recv(4096))
    client_socket.send("R".encode())

    return gates, EvalWires, GarWires, Anskey, client_socket

"""Function to sending back the garbled circuit answer from the garbler.

Input: answer of circuit
Socket connected with garbler

Output: None"""
def sendAnswer(answer,client_socket):
    client_socket.send(str(answer).encode())
    client_socket.close()
    pass

def main():
    """Retrieve the garbled circuit, evaluate it, and send the result back to the Garbler."""
    gates, EvalWires, GarWires, Anskey, client_socket = getCircuit()
    answer = evaluateCircuit(gates, EvalWires, GarWires, Anskey)
    sendAnswer(answer, client_socket)
    pass


if __name__ == "__main__":
    main()