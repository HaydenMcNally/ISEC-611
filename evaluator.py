from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

# Oblivious Transfer (1-out-of-2 OT)
def oblivious_transfer(sender_inputs, chooser_bit):
    """
    Perform a 1-out-of-2 Oblivious Transfer (OT).

    Args:
        sender_inputs (tuple): A tuple of two inputs (M0, M1) from the sender.
        chooser_bit (int): The chooser's selection bit (0 or 1).

    Returns:
        bytes: The chosen message (M[chooser_bit]) securely transferred to the chooser.

    """
    # Generate RSA key pairs for sender and chooser
    # Sender's key pair (used for encrypting messages)
    ##Change sender private key to fake key and make it wrong after making the public key
    sender_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    sender_public_key = sender_private_key.public_key()
    ##Fake_key = 0
    # Chooser's key pair (used for encryption and decryption during OT)
    chooser_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    chooser_public_key = chooser_private_key.public_key()

    ##Network code to talk to the garbler and send your two public keys. if statement to put the chooser bit in the right spot

    # Step 1: Sender prepares encrypted messages (M0, M1)
    #Put this on the garbler side
    encrypted_inputs = []
    for message in sender_inputs:
        if not isinstance(message, bytes):
            raise ValueError("All sender inputs must be in bytes format.")

        ciphertext = sender_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_inputs.append(ciphertext)

    ##Network code to get the encrypted messages 

    # Step 2: Chooser generates a random key (R) and blinds it
    ##Delete this
    chooser_random_key = os.urandom(32)

    blinded_key = chooser_public_key.encrypt(
        chooser_random_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Sender sends the blinded key and the encrypted inputs back
    # Simulate network transfer (blinded_key, encrypted_inputs)
    
    ##Decrypt the messages
    
    # Step 4: Chooser decrypts the blinded key
    decrypted_key = chooser_private_key.decrypt(
        blinded_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ##return the output

    # Derive a shared key from the decrypted key for message decryption
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"OT key derivation",
        backend=default_backend()
    ).derive(decrypted_key)

    # Step 5: Chooser picks the desired encrypted message
    chosen_encrypted_message = encrypted_inputs[chooser_bit]

    # Step 6: Chooser decrypts the chosen message using their private key
    chosen_message = sender_private_key.decrypt(
        chosen_encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return chosen_message

# Example usage
if __name__ == "__main__":
    sender_inputs = (b"Message 0", b"Message 1")
    chooser_bit = 1  # Chooser wants the second message

    ##Split theses inputs between both programs sender_inputs on garbler and chooser bit on evaluator
    result = oblivious_transfer(sender_inputs, chooser_bit)
    print(f"Chosen message: {result.decode()}")



def main():
    pass


if __name__ == "__main__":
    main()