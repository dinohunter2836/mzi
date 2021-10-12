import typing as tp

from bitarray import bitarray
from bitarray.util import ba2int, int2ba

from functions import left_cycle_shift


class MD5:
    s = [7, 12, 17, 22, 7, 12, 17, 22,
         7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20,
         5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23,
         4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21,
         6, 10, 15, 21, 6, 10, 15, 21]

    K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
         0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
         0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
         0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
         0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
         0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
         0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
         0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
         0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
         0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
         0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
         0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
         0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
         0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
         0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
         0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

    def __init__(self) -> None:
        self.a_register = bitarray()
        self.b_register = bitarray()
        self.c_register = bitarray()
        self.d_register = bitarray()

    def __reset_registers(self) -> None:
        self.a_register = int2ba(0x01234567, length=32)
        self.b_register = int2ba(0x89ABCDEF, length=32)
        self.c_register = int2ba(0xFEDCBA98, length=32)
        self.d_register = int2ba(0x76543210, length=32)

    def hash_message(self, message: bitarray) -> bitarray:
        extended_message = message.copy()
        extended_message.extend([1])

        if len(extended_message) % 512 != 448:
            bits_to_extend_amount = ((447 + 512) - len(message) % 512) % 512
            extended_message.extend([0] * bits_to_extend_amount)
        extended_message.extend(int2ba(len(message) % (2 ** 64), length=64))

        self.__reset_registers()
        for chunk_no in range(len(extended_message) // 512):
            temp_a_register = self.a_register.copy()
            temp_b_register = self.b_register.copy()
            temp_c_register = self.c_register.copy()
            temp_d_register = self.d_register.copy()

            for i in range(64):
                logical_function_result = bitarray()
                g = 0
                if i < 16:
                    logical_function_result = (temp_b_register & temp_c_register) | (
                            (~temp_b_register) & temp_d_register)
                    g = i
                elif 16 <= i < 32:
                    logical_function_result = (temp_d_register & temp_b_register) | (
                            (~temp_d_register) & temp_c_register)
                    g = (5 * i + 1) % 16
                elif 32 <= i < 48:
                    logical_function_result = temp_b_register ^ temp_c_register ^ temp_d_register
                    g = (3 * i + 5) % 16
                elif 48 <= i < 64:
                    logical_function_result = temp_c_register ^ (temp_b_register | (~temp_d_register))
                    g = (7 * i) % 16
                current_word = extended_message[chunk_no * 512 + g * 32: chunk_no * 512 + (g + 1) * 32]

                function_result = int2ba(
                    (ba2int(logical_function_result) + ba2int(temp_a_register) + self.K[i] + ba2int(current_word)) % (
                                2 ** 32),
                    length=32)
                temp_a_register = temp_d_register
                temp_d_register = temp_c_register
                temp_c_register = temp_b_register
                temp_b_register = int2ba(
                    (ba2int(temp_b_register) + ba2int(left_cycle_shift(function_result, self.s[i]))) % (2 ** 32),
                    length=32)

            self.a_register = int2ba((ba2int(temp_a_register) + ba2int(self.a_register)) % (2 ** 32), length=32)
            self.b_register = int2ba((ba2int(temp_b_register) + ba2int(self.b_register)) % (2 ** 32), length=32)
            self.c_register = int2ba((ba2int(temp_c_register) + ba2int(self.c_register)) % (2 ** 32), length=32)
            self.d_register = int2ba((ba2int(temp_d_register) + ba2int(self.d_register)) % (2 ** 32), length=32)
        return self.a_register + self.b_register + self.c_register + self.d_register

    def hash_file(self, input_file: tp.BinaryIO, output_file: tp.BinaryIO) -> None:
        input_file_message = bitarray()
        input_file_message.fromfile(input_file)
        hashed_input_file_message = self.hash_message(input_file_message)
        hashed_input_file_message.tofile(output_file)


def main() -> None:
    md5 = MD5()
    with open('input_files/input_lab5.txt', 'r') as f:
        message = bitarray()
        message.frombytes(f.read().encode('UTF-8'))
    with open('input_files/input_lab5_wrong.txt', 'r') as f:
        second_message = bitarray()
        second_message.frombytes(f.read().encode('UTF-8'))
    first_hash = md5.hash_message(message)
    second_hash = md5.hash_message(second_message)
    print(first_hash == second_hash)
    with open('output_files/output_lab5.txt', 'wb') as f:
        first_hash.tofile(f)
    with open('output_files/output_lab5_wrong.txt', 'wb') as f:
        second_hash.tofile(f)


if __name__ == '__main__':
    main()
