import typing as tp

from bitarray import bitarray
from bitarray.util import int2ba, ba2int

from block_cipher import BlockCipher
from functions import left_cycle_shift


class Gost2814789(BlockCipher, message_block_length=64):
    _default_s_block = [[10, 4, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
                [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
                [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
                [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
                [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
                [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
                [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
                [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]]

    def __init__(self, key: bitarray, s_block: tp.Optional[tp.List[tp.List[int]]] = None) -> None:
        self._key = key
        self._s_block = self._default_s_block if s_block is None else s_block

    def _compute_substitution(self, message_block: bitarray) -> bitarray:
        substituted_message_block = bitarray()
        for i in range(8):
            value = ba2int(message_block[i * 4: (i + 1) * 4])
            substituted_message_block.extend(int2ba(self._s_block[i][value], length=4))
        return substituted_message_block

    def _compute_round(self, message_block: bitarray, subkey: bitarray) -> bitarray:
        right_part_sum = int2ba((ba2int(message_block[32:]) + ba2int(subkey)) % (2 ** 32), length=32)
        next_message_block = left_cycle_shift(self._compute_substitution(right_part_sum), 11) ^ message_block[:32]
        next_message_block.extend(message_block[32:])
        return next_message_block

    def _encrypt_block(self, message_block: bitarray) -> bitarray:
        encrypted_block = message_block.copy()
        for round_series_no in range(7):
            for round_no in range(8):
                if round_series_no == 3:
                    subkey_no = round_no
                else:
                    subkey_no = round_no
                encrypted_block = self._compute_round(encrypted_block.copy(), self._key[subkey_no * 32: (subkey_no + 1) * 32])
        return encrypted_block

    def _decrypt_block(self, message_block: bitarray) -> bitarray:
        decrypted_block = message_block.copy()
        for round_series_no in range(7):
            for round_no in range(8):
                if round_series_no == 0:
                    subkey_no = 7 - round_no
                else:
                    subkey_no = 7 - round_no
                decrypted_block = self._compute_round(decrypted_block.copy(), self._key[subkey_no * 32: (subkey_no + 1) * 32])
        return decrypted_block


def main() -> None:
    key = bitarray(256)
    encoder = Gost2814789(key)
    with open('input_files/input_lab1.txt', 'r') as f:
        message = bitarray()
        message.frombytes(f.read().encode('UTF-8'))
    encoded_message = encoder.encrypt(message)
    with open('output_files/output_lab1_encoded_message_gost.txt', 'wb') as f:
        encoded_message.tofile(f)
    decoded_message = encoder.decrypt(encoded_message)
    with open('output_files/output_lab1_message_gost.txt', 'wb') as f:
        decoded_message.tofile(f)


if __name__ == '__main__':
    main()
