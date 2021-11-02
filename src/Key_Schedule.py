from Tables import Rcon
from copy import deepcopy
from Operators import left_shift, sub_bytes_list, list_xor, matrix_column_update
from Formater import list_to_matrix


def rotword(m, r):
    rotword = [m[i][3] for i in range(0, 4)]
    rotword = left_shift(rotword)
    rotword = sub_bytes_list(rotword)
    rotword = list_xor(list_xor(rotword, [Rcon[i][r] for i in range(0, 4)]), [m[i][0] for i in range(0, 4)])
    return rotword


def get_roundkeys(cipherkey):
    cipherkey = list_to_matrix(list(map(int, ''.join(format(ord(i), 'b').zfill(8) for i in cipherkey))))
    matrix_cipherkey = cipherkey
    key = deepcopy(cipherkey)

    roundkeys = [key]
    for roundkey in range(0, 10):
        key = matrix_column_update(matrix_cipherkey, rotword(key, roundkey), 0)
        for column in range(1, 4):
            key = matrix_column_update(
                key,
                list_xor(
                    [key[i][column - 1] for i in range(0, 4)],
                    [key[i][column] for i in range(0, 4)]
                ),
                column
            )

        roundkeys.append(deepcopy(matrix_cipherkey))

    return roundkeys


