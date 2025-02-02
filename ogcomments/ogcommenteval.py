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


"""The example constists of two participantes the Garbler the other program and the Evaluator this program.
The Garbler will create the circuit and 'garble' all the inputs (encypted them) and then send them to the 
Evaluator. Who then evaluates all circuits to get the final answer. We first start in the Garbler with the makeCircuit function"""



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

"""Standard AES decyption function, notable changes are we take two passwords(The two input wire values) as keys which are concatinated together to
create the key.

Inputs: the plaintext, Password 1, Password 2
Output: encypted output"""
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



"""This function is for evalutaing the garblerd circuit, using the point values we decrypted the correct answer wire and get
the answer for each gate giving us the answer to the whole circuit.

Inputs: Gates- logic gate in the circuit
        EvalWires - Evaluator wire values
        GarWires - Garblers wire values
        Anskey - wires of the last gates answers
        
Output: Answer to circuit"""
def evaluateCircuit(gates, EvalWires , GarWires, Anskey):
    """Grabbing out each wire,point values, and gate from their input lists"""
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

    """Loop through each row in gate one looking for the matching input point values to tell us which row to decrypt to get the answer to the gate"""
    for rows in gate1:
        if gate1point0 == rows[0] and gate1point1 == rows[1]:
            gate1Ans = aes_decrypt(rows[2],gate1Garb,gate1Eval)

    """Doing the same for gate 2"""
    for rows in gate2:
        if gate2point0 == rows[0] and gate2point1 == rows[1]:
            gate2Ans = aes_decrypt(rows[2],gate2Garb,gate2Eval)

    """Getting the point values of gate 1 and 2 answers to use for input of gate 3"""
    gate3point0 = gate1Ans[-1]
    gate3point1 = gate2Ans[-1]

    """Looping through the gate same as gate 1 and 2 to get result"""
    for rows in gate3:
        if gate3point0 == rows[0] and gate3point1 == rows[1]:
            gate3Ans = aes_decrypt(rows[2],gate1Ans,gate2Ans)

    """Looping through the answer key to decifer what the final wire value repersent to get circuit answer"""
    for index,ans in enumerate(Anskey):
        if ans == gate3Ans:
            answer = index
    print("Answer: ",answer)
    return answer


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

Outputs: Wire values
"""
def oblivious_transfer(chooser_bit,socket_c):
    
    """We create two RSA key pairs one we'll keep the private key for and the other we get rid of. """
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
    """Creating fake key"""
    # Generate RSA key pair for the sender
    fake_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    fake_public_key = fake_private_key.public_key()

    # Fake key (requested)
    fake_private_key = None  # Removing the private key after generation

    # Serialize sender's public key
    fake_public_key_pem = fake_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    """Based off which bit we want we add the fake key in the other index so that the wire value we want gets encrypted with
    the public key we have the private key for"""
    if chooser_bit == 0:
        chooser_public_key_pem_list.append(fake_public_key_pem)
    else:
        chooser_public_key_pem_list.insert(0,fake_public_key_pem)


    """Send pickled public key list"""
    socket_c.sendall(pickle.dumps(chooser_public_key_pem_list))

    # Receive pickled encrypted inputs
    encrypted_inputs = pickle.loads(socket_c.recv(4096))

    """With the encypted inputs we grab the input we have the corrisponding private key for and decrypted it"""
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

"""This function is used to all the parts of the garbled circuit needed to evaluate it, first we create a network socket 
with the garbler and then perform oblivious transfer to get the evaluators wire values, we then recieve and deserialize the 
other information.

Inputs: None
Outputs:
- gates: The logic gates in the circuit  
- EvalWires: The Evaluator's wire values  
- GarWires: The Garbler's wire values  
- AnsKey: The final gate's output wire values"""
def getCircuit():
    """Creating a network socket connection with the garbler"""
    HOST = '127.0.0.1'  # Server IP (localhost for testing)
    PORT = 12345        # Must match the server port

    # Create a socket (IPv4, TCP)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))  # Connect to the server

    message = "Hello, Server!"
    client_socket.send(message.encode())  # Send data

    response = client_socket.recv(1024).decode()  # Receive response from the server
    print(f"Server response: {response}")

    """Randomly choosing which bits the evaluator is using for the circuit and using oblivious transfer to get the corrisponding wire value"""
    random_bit1 = secrets.randbelow(2)
    random_bit2 = secrets.randbelow(2)
    print("Gate 1 random bit is ", random_bit1, "Gate 2 random bit is ", random_bit2)
    gate1Eval = oblivious_transfer(random_bit1,client_socket).decode()
    gate2Eval = oblivious_transfer(random_bit2,client_socket).decode()
    EvalWires = [gate1Eval,gate2Eval]

    """Recieving each element of the garbled circuit we need"""
    print("Recieved gates")
    gate_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())
    print("Recieved garblers wires")
    GarWires_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())
    print("Recieved Answer key")
    Anskey_pickled = client_socket.recv(4096)
    client_socket.send("R".encode())

    """Deserializing the information"""
    gates = pickle.loads(gate_pickled)
    GarWires = pickle.loads(GarWires_pickled)
    Anskey = pickle.loads(Anskey_pickled)

    return gates, EvalWires , GarWires, Anskey ,client_socket

"""Function to sending back the garbled circuit answer from the garbler.

Input: answer of circuit
Socket connected with garbler

Output: None"""
def sendAnswer(answer,client_socket):
    client_socket.send(str(answer).encode())
    client_socket.close()
    pass

def main():
    """First we need to recieve the garbled circuit from the garbler with getCircuit function"""
    gates, EvalWires , GarWires, Anskey ,client_socket = getCircuit()
    """Once we have all the parts of the circuit we can evalute it to get the answer"""
    answer = evaluateCircuit(gates, EvalWires , GarWires, Anskey)
    """Send the answer back to the garblers"""
    sendAnswer(answer,client_socket)
    pass


if __name__ == "__main__":
    main()