def column_in_dec(bit_list, k):
    return int(''.join(str(bit_list[i]) for i in range(k * 6 + 1, k * 6 + 5)), 2)


def text_to_8bit_list(text):
    return list(map(int, ''.join(format(ord(i), 'b').zfill(8) for i in text)))


def bit_list_to_dec(arr):
    return int(''.join(map(str, arr)), 2)


def bit_list_to_string(bit_list):
    return ''.join(map(str, bit_list))


def dec_to_6bit_string(dec):
    return "{0:06b}".format(dec)


def bit_string_to_bit_list(string):
    return list(map(int, string))


def bit_list_to_text(arr):
    decrypted_message = ""
    for n in range(0, int(len(arr) / 8)):
        decrypted_message += chr(int(''.join(map(str, arr[n * 8: n * 8 + 8])), 2))
    return decrypted_message


def list_to_matrix(bit_list):
    m = [[0x00, 0x00, 0x00, 0x00],
         [0x00, 0x00, 0x00, 0x00],
         [0x00, 0x00, 0x00, 0x00],
         [0x00, 0x00, 0x00, 0x00]]

    k = 0
    for column in range(0, 4):
        for row in range(0, 4):
            m[row][column] = bit_list[k * 8: (k + 1) * 8]
            k += 1

    return m


def matrix_to_list(bit_matrix):
    l = []

    for column in range(0, 4):
        for row in range(0, 4):
            l += bit_matrix[row][column]

    return l