# Source:
from sys import argv
from Cipher import block_encryptor, encryptor, decryptor, block_decryptor
from Formater import bit_list_to_string, text_to_8bit_list, bit_string_to_bit_list, bit_list_to_text
from Key_Schedule import get_roundkeys


def mainencryption(): # Main Encryption, runs ECB and CBC mode accordingly, reads and writes to specified files
    plaintext_file = open(argv[2], "r")
    plaintext = plaintext_file.read()
    if len(plaintext) == 16:  # If plaintext is 128 bits, it runs in ECB mode
        encrypted_message = bit_list_to_string(block_encryptor(text_to_8bit_list(plaintext), roundkeys))
    else:                    # Else it runs in CBC
        encrypted_message = encryptor(plaintext, roundkeys)
    plaintext_file.close()

    ciphertext_file = open(argv[3], "w")
    ciphertext_file.write(encrypted_message)
    ciphertext_file.close()


def maindecryption(): # Main Decryption, runs ECB and CBC mode accordingly, reads and writes to specified files
    ciphertext_file = open(argv[2], "r")
    ciphertext = ciphertext_file.read()
    if len(ciphertext) == 128:  # If plaintext is 128 bits, it runs in ECB mode
        decrypted_message = bit_list_to_text(block_decryptor(bit_string_to_bit_list(ciphertext), roundkeys))
    else:                     # Else it runs in CBC
        decrypted_message = decryptor(ciphertext, roundkeys)
    ciphertext_file.close()

    plaintext_file = open(argv[3], "w")
    plaintext_file.write(decrypted_message)
    plaintext_file.close()


if __name__ == '__main__':
    cipherkey = input("Enter your sixteen character ASCII key: ")      # Takes key for encrypting/decrypting
    roundkeys = get_roundkeys(cipherkey)  # Generates roundkeys for given key

    if argv[1] == "encrypt":          # Runs encryption or decryption accordingly to args
        mainencryption()
    elif argv[1] == "decrypt":
        maindecryption()
