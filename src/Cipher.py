from Operators import calculate_padding, get_kth_block, add_padding, amount_of_blocks, xor, remove_padding, matrix_xor, sub_bytes_matrix, shift_rows, mix_columns, inv_shift_rows, inv_mix_columns, inv_sub_bytes_matrix
from Formater import text_to_8bit_list, bit_list_to_string, dec_to_6bit_string, bit_string_to_bit_list, bit_list_to_dec, bit_list_to_text, list_to_matrix, matrix_to_list

# Example initial vector
iv = [0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0,
      1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0,
      0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0,
      1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0]


def encryptor(plaintext, roundkeys):
    bit_plaintext = text_to_8bit_list(plaintext)
    padded_amount = calculate_padding(bit_plaintext)  # Calculates padding to apply on the last block
    bit_plaintext = add_padding(bit_plaintext)  # Applies padding on the last block unless it is 64 bits

    encrypted_message = ""
    for k in range(0, amount_of_blocks(bit_plaintext)):  # Takes all blocks and applies IV
        block = get_kth_block(bit_plaintext, k)

        global iv
        block = xor(iv, block)  # Applies IV XOR on block
        iv = block_encryptor(block, roundkeys)  # Updates IV to new encrypted block

        encrypted_message += bit_list_to_string(iv)  # Adds together all blocks to ciphertext

    return encrypted_message + dec_to_6bit_string(padded_amount)  # Returns ciphertext with 7 extra bits for
    # for padded amount


def decryptor(ciphertext, roundkeys):
    bit_ciphertext = bit_string_to_bit_list(ciphertext)
    padded_amount = bit_list_to_dec(
        bit_ciphertext[-7:])  # Gets padded amount on the last block from last 6 bits
    del bit_ciphertext[-7:]  # Removes last six bits

    bit_plaintext = []
    for k in range(0, amount_of_blocks(ciphertext)):  # Takes all blocks and applies IV
        block = get_kth_block(bit_ciphertext, k)

        global iv
        bit_plaintext += xor(iv, block_decryptor(block, roundkeys))  # Applies IV XOR on decrypted block
        iv = block  # Updates IV to new XORed block

    remove_padding(bit_plaintext, padded_amount)  # Removed padded amount from last block
    return bit_list_to_text(bit_plaintext)  # Returns original plaintext


def block_encryptor(byte_plaintext, roundkeys):  # Standard AES encryption of a 128 bit block
    byte_plaintext = list_to_matrix(byte_plaintext)

    state = matrix_xor(byte_plaintext, roundkeys[0])
    for i in range(1, 11):
        state = sub_bytes_matrix(state)
        state = shift_rows(state)
        if i != 10:
            state = mix_columns(state)
        state = matrix_xor(state, roundkeys[i])

    return matrix_to_list(state)


def block_decryptor(byte_ciphertext, roundkeys):  # Standard AES decryption of a 128 bit block
    byte_ciphertext = list_to_matrix(byte_ciphertext)
    inv_roundkeys = roundkeys[::-1]

    state = matrix_xor(byte_ciphertext, inv_roundkeys[0])
    for i in range(1, 11):
        if i != 1:
            state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes_matrix(state)
        state = matrix_xor(state, inv_roundkeys[i])

    return matrix_to_list(state)
