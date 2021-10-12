import typing as tp

from bitarray import bitarray
from bitarray.util import ba2int, int2ba

from block_cipher import BlockCipher


class Stb(BlockCipher, message_block_length=128):
    _substitution_table = [
        [0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4],
        [0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D],
        [0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B],
        [0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99],
        [0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1],
        [0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F],
        [0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31],
        [0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93],
        [0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47],
        [0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6],
        [0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2],
        [0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11],
        [0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1],
        [0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A],
        [0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21],
        [0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D]
    ]

    def __init__(self, key: bitarray) -> None:
        self._key = key

    @staticmethod
    def _lambda_function(block: bitarray) -> bitarray:
        value = ba2int(block)
        if value < (1 << 31):
            return int2ba((2 * value) % (1 << 32), length=32)
        else:
            return int2ba((2 * value + 1) % (1 << 32), length=32)

    @staticmethod
    def _lambda_r_function(block: bitarray, r: int) -> bitarray:
        result = block.copy()
        for _ in range(r):
            result = Stb._lambda_function(result)
        return result

    @staticmethod
    def _apply_substitution(substitution_table: tp.List[tp.List[int]], block: bitarray) -> bitarray:
        result_block = bitarray()
        for sub_block_no in range(4):
            current_sub_block = block[sub_block_no * 8: (sub_block_no + 1) * 8]
            substitution_table_row_no = ba2int(current_sub_block[:4])
            substitution_table_column_no = ba2int(current_sub_block[4:])
            result_block.extend(
                int2ba(substitution_table[substitution_table_row_no][substitution_table_column_no], length=8))
        return result_block

    @staticmethod
    def _g_r_function(substitution_table: tp.List[tp.List[int]], block: bitarray, r: int) -> bitarray:
        substitution_result = Stb._apply_substitution(substitution_table, block)
        lambda_r_function_result = Stb._lambda_r_function(substitution_result, r)
        return lambda_r_function_result

    @staticmethod
    def _sum_mod(first_block: bitarray, second_block: bitarray) -> bitarray:
        return int2ba((ba2int(first_block) + ba2int(second_block)) % (1 << 32), length=32)

    @staticmethod
    def _diff_mod(first_block: bitarray, second_block: bitarray) -> bitarray:
        return int2ba((ba2int(first_block) - ba2int(second_block)) % (1 << 32), length=32)

    def _get_key_block(self, tact_key_no: int) -> bitarray:
        block_no = tact_key_no % 8
        return self._key[block_no * 32: (block_no + 1) * 32]

    def _encrypt_block(self, message_block: bitarray) -> bitarray:
        a = message_block[:32]
        b = message_block[32:64]
        c = message_block[64:96]
        d = message_block[96:]

        for i in range(8):
            b = b ^ self._g_r_function(self._substitution_table, self._sum_mod(a, self._get_key_block(7 * i - 6)), 5)
            c = c ^ self._g_r_function(self._substitution_table, self._sum_mod(d, self._get_key_block(7 * i - 5)), 21)
            a = self._diff_mod(a, self._g_r_function(self._substitution_table,
                                                     self._sum_mod(b, self._get_key_block(7 * i - 4)), 13))

            e = self._g_r_function(self._substitution_table,
                                   self._sum_mod(self._sum_mod(b, c), self._get_key_block(7 * i - 3)), 21) ^ int2ba(
                i + 1, length=32)
            b = self._sum_mod(b, e)
            c = self._diff_mod(c, e)

            d = self._sum_mod(d, self._g_r_function(self._substitution_table,
                                                    self._sum_mod(c, self._get_key_block(7 * i - 2)), 13))
            b = b ^ self._g_r_function(self._substitution_table, self._sum_mod(a, self._get_key_block(7 * i - 1)), 21)
            c = c ^ self._g_r_function(self._substitution_table, self._sum_mod(d, self._get_key_block(7 * i)), 5)

            a, b = b, a
            c, d = d, c
            b, c = c, b
        return b + d + a + c

    def _decrypt_block(self, message_block: bitarray) -> bitarray:
        a = message_block[:32]
        b = message_block[32:64]
        c = message_block[64:96]
        d = message_block[96:]

        for i in range(7, -1, -1):
            b = b ^ self._g_r_function(self._substitution_table, self._sum_mod(a, self._get_key_block(7 * i)), 5)
            c = c ^ self._g_r_function(self._substitution_table, self._sum_mod(d, self._get_key_block(7 * i - 1)), 21)
            a = self._diff_mod(a, self._g_r_function(self._substitution_table,
                                                     self._sum_mod(b, self._get_key_block(7 * i - 2)), 13))

            e = self._g_r_function(self._substitution_table,
                                   self._sum_mod(self._sum_mod(b, c), self._get_key_block(7 * i - 3)), 21) ^ int2ba(
                i + 1, length=32)
            b = self._sum_mod(b, e)
            c = self._diff_mod(c, e)

            d = self._sum_mod(d, self._g_r_function(self._substitution_table,
                                                    self._sum_mod(c, self._get_key_block(7 * i - 4)), 13))
            b = b ^ self._g_r_function(self._substitution_table, self._sum_mod(a, self._get_key_block(7 * i - 5)), 21)
            c = c ^ self._g_r_function(self._substitution_table, self._sum_mod(d, self._get_key_block(7 * i - 6)), 5)

            a, b = b, a
            c, d = d, c
            a, d = d, a
        return c + a + d + b


def main() -> None:
    key = bitarray(256)
    encoder = Stb(key)
    with open('input_files/input_lab2.txt', 'r') as f:
        message = bitarray()
        message.frombytes(f.read().encode('UTF-8'))
    encoded_message = encoder.encrypt(message)
    with open('output_files/output_lab2_encoded_message.txt', 'wb') as f:
        encoded_message.tofile(f)
    decoded_message = encoder.decrypt(encoded_message)
    with open('output_files/output_lab2_message.txt', 'wb') as f:
        decoded_message.tofile(f)


if __name__ == '__main__':
    main()
