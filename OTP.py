# -*- coding: utf-8 -*-
"""
Created on Sun Jan 28 14:13:44 2024

@author: hadaw
"""
import numpy as np
import secrets

class OTP:
    def __init__(self, string):
        """
        Initialize OTP object with the input string.

        Parameters:
        - string (str): The input string for OTP encryption.
        """
        super().__init__()

        # Store the input string and generate a random key.
        self.string = string
        self.key = ''.join([chr(secrets.randbelow(912)) for _ in range(len(string))])

    def encrypt(self):
        """
        Perform OTP encryption on the input string.

        Returns:
        - tuple: A tuple containing the ciphertext (str) and the encrypted array (numpy.ndarray).
        """
        # Create arrays with ASCII values, using None for spaces.
        array_A = np.array([ord(char) for char in self.string])

        # Remove None values (spaces) from the array.
        array_A = array_A[array_A != None]

        # Convert the key to an array of ASCII values.
        array_key = np.array([ord(char) for char in self.key])

        # Calculate the required padding for both arrays.
        padding_A = np.zeros(max(0, len(array_key) - len(array_A)), dtype=array_key.dtype)
        padding_key = np.zeros(max(0, len(array_A) - len(array_key)), dtype=array_A.dtype)

        # Perform XOR operation
        encrypted_array = np.bitwise_xor(np.concatenate((array_A, padding_A)), np.concatenate((array_key, padding_key)))

        # Convert the result back to a string
        ciphertext = ''.join([chr(char) for char in encrypted_array])

        return ciphertext, encrypted_array

    def decrypt(self, ciphertext, key):
        """
        Perform OTP decryption on the input ciphertext using the given key.

        Parameters:
        - ciphertext (str): The ciphertext to be decrypted.
        - key (str): The key used for decryption.

        Returns:
        - str: The decrypted plaintext.
        """
        # Convert ciphertext and key to arrays of ASCII values
        array_ciphertext = np.array([ord(char) for char in ciphertext])
        array_key = np.array([ord(char) for char in key])

        # Calculate the required padding for both arrays
        padding_ciphertext = np.zeros(max(0, len(array_key) - len(array_ciphertext)), dtype=array_key.dtype)
        padding_key = np.zeros(max(0, len(array_ciphertext) - len(array_key)), dtype=array_ciphertext.dtype)

        # Perform XOR operation for decryption
        decrypted_array = np.bitwise_xor(np.concatenate((array_ciphertext, padding_ciphertext)),
                                         np.concatenate((array_key, padding_key)))

        # Convert the result back to a string
        decrypted_text = ''.join([chr(char) for char in decrypted_array])

        del padding_ciphertext, padding_key, array_ciphertext, array_key

        return decrypted_text, decrypted_array



    def crib_walk(self, ciphertext, crib):
        """
        Perform crib-walking on the given ciphertext with the provided crib.

        Parameters:
        - ciphertext (str): The ciphertext to be analyzed.
        - crib (str): The known plaintext or guess (crib).

        Returns:
        - str: The potential decrypted text.
        """
        potential_keys = []

        # Convert ciphertext and crib to arrays of ASCII values
        array_ciphertext = np.array([ord(char) for char in ciphertext])
        array_crib = np.array([ord(char) for char in crib])

        # Iterate through different positions for crib-walking
        for i in range(len(array_ciphertext) - len(array_crib) + 1):
            # Extract a portion of the ciphertext for XOR with the crib
            portion_ciphertext = array_ciphertext[i:i+len(array_crib)]

            # Perform XOR operation with the crib
            potential_key = np.bitwise_xor(portion_ciphertext, array_crib)

            # Convert the potential key back to a string
            potential_key_str = ''.join([chr(char) for char in potential_key])

            potential_keys.append((i, potential_key_str))

        return potential_keys



# Example usage
otp_instance = OTP("hello world")
ciphertext, _ = otp_instance.encrypt()
crib = "hello world"  # Known plaintext or guess

# Perform crib-walking
potential_keys = otp_instance.crib_walk(ciphertext, crib)

# Display potential decrypted texts
for position, potential_key in potential_keys:
    decrypted_text = otp_instance.decrypt(ciphertext, potential_key)
    print(f"Position {position}: Potential Key: {potential_key}, Decrypted Text: {decrypted_text}")
