from Tables import AES_Poly, Inv_M, Inv_S_Box, S_Box, M
from Formater import bit_list_to_dec


def xor(value1, value2):  # XORs two bit lists
    return list(value1[x] ^ value2[x] for x in range(0, len(value1)))


def list_xor(list1, list2):
    for x in range(0, 4):
        list1[x] = xor(list1[x], list2[x])

    return list1


def matrix_xor(m1, m2):  # XORs two matrices
    for y in range(0, 4):
        for x in range(0, 4):
            m1[y][x] = xor(m1[y][x], m2[y][x])

    return m1


def matrix_column_update(m, l, column):
    for row in range(0, 4):
        m[row][column] = l[row]

    return m


def add_padding(values):  # Applies padding on a block based on calculated amount to achieve a full 128 bit block
    if len(values) % 128 != 0:
        for i in range(0, (128 - (len(values) % 128))):
            values.append(0)
    return values


def remove_padding(bit_plaintext, padded_amount):  # Removes applied padding on a block based on calculated amount
    if padded_amount != 0:
        del bit_plaintext[-padded_amount:]


def right_shift(partition):
    return partition[-1:] + partition[:-1]


def double_right_shift(partition):
    return right_shift(right_shift(partition))


def triple_right_shift(partition):
    return right_shift(right_shift(right_shift(partition)))


def left_shift(partition):        # Applies a left shift to a partition
    partition.append(partition.pop(0))
    return partition


def double_left_shift(partition):  # Applies two left shifts to a partition
    return left_shift(left_shift(partition))


def triple_left_shift(partition):  # Applies three left shifts to a partition
    return left_shift(left_shift(left_shift(partition)))


def get_kth_block(bit_list, k):  # Finds kth 128 bit block in a bit list
    return bit_list[k * 128: k * 128 + 128]


def calculate_padding(text):  # Calculates padding to apply to achieve a full 64 bit block
    return 128 - len(text) % 128 if len(text) % 128 > 0 else 0


def amount_of_blocks(arr):  # Calculates how many 64 bit blocks are in a bit list (plaintext/ciphertext)
    return int(len(arr) / 128)


def polymul(u, v):  # Done
    u = u[::-1]
    v = v[::-1]
    max_exp = (len(u) - 1) + (len(v))
    product = [x * 0 for x in range(0, max_exp)]
    highest_exp = 0
    for i in range(0, len(u)):
        for j in range(0, len(v)):
            exponent = i + j
            coefficient = (u[i] * v[j] + product[exponent]) % 2

            product[exponent] = coefficient

            if exponent > highest_exp and coefficient != 0:
                highest_exp = exponent

    product = product[:highest_exp + 1]
    return product[::-1]


def polysub(u, v):  # Works
    u = [i * 0 for i in range(0, len(v) - len(u))] + u
    v = [i * 0 for i in range(0, len(u) - len(v))] + v

    max_len = len(u)
    difference = [x * 0 for x in range(0, max_len)]

    max_exp = max_len
    for exponent in range(0, max_len):
        coefficient = (u[exponent] - v[exponent]) % 2
        difference[exponent] = coefficient

        if -exponent > -max_exp and coefficient != 0:
            max_exp = exponent
    difference = difference[-(max_len - max_exp):]
    return difference


def polymul_mod(u, v):  # Done?
    u = polymul(u, v)
    v = AES_Poly
    for exponent in range(0, len(u)):
        if len(u) < len(v):
            break

        diff_exponent = (len(u) - 1) - (len(v) - 1)
        quotient_sub = v + [x * 0 for x in range(0, diff_exponent)]
        u = polysub(u, quotient_sub)

    return [i * 0 for i in range(0, 8 - len(u))] + u


def sub_bytes_list(state):
    for i in range(0, 4):
        x = bit_list_to_dec(state[i][0:4])
        y = bit_list_to_dec(state[i][4:8])
        state[i] = S_Box[x][y]
    return state


def sub_bytes_matrix(state):
    for row in range(0, 4):
        for column in range(0, 4):
            x = bit_list_to_dec(state[row][column][0:4])
            y = bit_list_to_dec(state[row][column][4:8])
            state[row][column] = S_Box[x][y]

    return state


def inv_sub_bytes_matrix(state):
    for row in range(0, 4):
        for column in range(0, 4):
            x = bit_list_to_dec(state[row][column][0:4])
            y = bit_list_to_dec(state[row][column][4:8])
            state[row][column] = Inv_S_Box[x][y]

    return state


def shift_rows(state):
    left_shift(state[1])
    double_left_shift(state[2])
    triple_left_shift(state[3])

    return state


def inv_shift_rows(state):
    state[1] = right_shift(state[1])
    state[2] = double_right_shift(state[2])
    state[3] = triple_right_shift(state[3])

    return state


def mix_columns(state):
    mixed = [[0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00]]

    for y in range(0, 4):
        for x in range(0, 4):
            mixed[x][y] = xor(
                            xor(polymul_mod(state[0][y], M[x][0]),
                                polymul_mod(state[1][y], M[x][1])),
                            xor(polymul_mod(state[2][y], M[x][2]),
                                polymul_mod(state[3][y], M[x][3]))
                            )
    return mixed


def inv_mix_columns(state):
    mixed = [[0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00],
             [0x00, 0x00, 0x00, 0x00]]

    for y in range(0, 4):
        for x in range(0, 4):
            mixed[x][y] = xor(
                            xor(polymul_mod(state[0][y], Inv_M[x][0]),
                                polymul_mod(state[1][y], Inv_M[x][1])),
                            xor(polymul_mod(state[2][y], Inv_M[x][2]),
                                polymul_mod(state[3][y], Inv_M[x][3]))
                            )
    return mixed
