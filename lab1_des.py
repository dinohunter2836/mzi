import typing as tp
import numpy as np
import dataclasses

from bitarray import bitarray
from bitarray.util import ba2int, int2ba

from block_cipher import BlockCipher
from functions import left_cycle_shift


@dataclasses.dataclass
class DesCipherConstParameters:
    ip_permutation: tp.List[int]
    e_permutation: tp.List[int]
    s_boxes: tp.List[tp.List[tp.List[int]]]
    p_permutation: tp.List[int]
    pc_1_permutation: tp.List[int]
    pc_2_permutation: tp.List[int]


class Des(BlockCipher, message_block_length=64):
    def __init__(self, const_parameters: DesCipherConstParameters, key: bitarray) -> None:
        super().__init__()

        self._ip_permutation = const_parameters.ip_permutation
        self._inverse_ip_permutation = self._inverse_permutation(const_parameters.ip_permutation)

        self._e_permutation = const_parameters.e_permutation
        self._s_boxes = const_parameters.s_boxes
        self._p_permutation = const_parameters.p_permutation

        self._pc_1_permutation = const_parameters.pc_1_permutation
        self._pc_2_permutation = const_parameters.pc_2_permutation

        self._key = key

    @staticmethod
    def generate_parameters() -> DesCipherConstParameters:
        ip_permutation = np.random.permutation(64).tolist()
        e_permutation = np.random.randint(0, 32, 48).tolist()
        s_boxes = []

        for _ in range(8):
            table = []
            for _ in range(4):
                table.append(np.random.permutation(16).tolist())
            s_boxes.append(table)

        p_permutation = np.random.permutation(32).tolist()
        pc_1_permutation = np.random.permutation(56).tolist()
        pc_2_permutation = np.random.permutation(48).tolist()

        return DesCipherConstParameters(ip_permutation, e_permutation, s_boxes, p_permutation, pc_1_permutation, ## noqa
                                        pc_2_permutation) ## noqa

    @staticmethod
    def _inverse_permutation(permutation: tp.List[int]) -> tp.List[int]:
        inverse_permutation = [0] * len(permutation)
        for index, element in enumerate(permutation):
            inverse_permutation[element] = index
        return inverse_permutation

    @staticmethod
    def _make_permutation(block: bitarray, permutation: tp.List[int]) -> bitarray:
        result_block = bitarray(len(block))
        for to_position, from_position in enumerate(permutation):
            result_block[to_position] = block[from_position]
        return result_block

    @staticmethod
    def _make_extension(block: bitarray, extension_permutation: tp.List[int]) -> bitarray:
        result_block = bitarray(len(extension_permutation))

        for to_position, from_position in enumerate(extension_permutation):
            result_block[to_position] = block[from_position]
        return result_block

    @staticmethod
    def _make_s_box_conversion(block: bitarray, s_boxes: tp.List[tp.List[tp.List[int]]]) -> bitarray:
        result_bitarray = bitarray()
        for i in range(8):
            current_six_bits = block[i * 6: (i + 1) * 6]
            s_box_conversion_result = int2ba(s_boxes[i][ba2int(current_six_bits[:2])][ba2int(current_six_bits[2:])],
                                             length=4)
            result_bitarray += s_box_conversion_result
        return result_bitarray

    def change_key(self, key: bitarray) -> None:
        self._key = key

    def _feistel_function(self, block_part: bitarray, key: bitarray) -> bitarray:
        extended_block = self._make_extension(block_part, self._e_permutation)
        block_key_xor = key ^ extended_block
        s_box_conversed_block = self._make_s_box_conversion(block_key_xor, self._s_boxes)
        return self._make_permutation(s_box_conversed_block, self._p_permutation)

    def _encryption_cycle(self, block_left_part: bitarray, block_right_part: bitarray,
                          key: bitarray) -> tp.Tuple[bitarray, bitarray]:
        new_block_right_part = block_left_part ^ self._feistel_function(block_right_part, key)
        return block_right_part, new_block_right_part

    def _decryption_cycle(self, block_left_part: bitarray, block_right_part: bitarray,
                          key: bitarray) -> tp.Tuple[bitarray, bitarray]:
        new_block_left_part = block_right_part ^ self._feistel_function(block_left_part, key)
        return new_block_left_part, block_left_part

    def _make_keys(self, left_key_part: bitarray, right_key_part: bitarray, round_no: int) -> \
            tp.Tuple[bitarray, bitarray, bitarray]:

        new_left_key_part: bitarray = left_cycle_shift(left_key_part, round_no % 2 + 1)
        new_right_key_part: bitarray = left_cycle_shift(right_key_part, round_no % 2 + 1)
        feistel_key = self._make_extension(new_left_key_part + new_right_key_part, self._pc_2_permutation)

        return new_left_key_part, new_right_key_part, feistel_key

    def _encrypt_block(self, block: bitarray) -> bitarray:
        initial_block_permutation = self._make_permutation(block, self._ip_permutation)
        block_current_left_part = initial_block_permutation[:32]
        block_current_right_part = initial_block_permutation[32:]

        initial_key_permutation = self._make_permutation(self._key, self._pc_1_permutation)
        key_current_left_part = initial_key_permutation[:28]
        key_current_right_part = initial_key_permutation[28:]

        for round_no in range(16):
            key_current_left_part, key_current_right_part, feistel_key = self._make_keys(key_current_left_part,
                                                                                         key_current_right_part,
                                                                                         round_no)
            block_current_left_part, block_current_right_part = self._encryption_cycle(block_current_left_part,
                                                                                       block_current_right_part,
                                                                                       feistel_key)
        return self._make_permutation(block_current_left_part + block_current_right_part,
                                      self._inverse_ip_permutation)

    def _decrypt_block(self, block: bitarray) -> bitarray:
        initial_key_permutation = self._make_permutation(self._key, self._pc_1_permutation)
        key_current_left_part = initial_key_permutation[:28]
        key_current_right_part = initial_key_permutation[28:]
        inverse_feistel_keys = []
        initial_block_permutation = self._make_permutation(block, self._ip_permutation)
        block_current_left_part = initial_block_permutation[:32]
        block_current_right_part = initial_block_permutation[32:]

        for round_no in range(16):
            key_current_left_part, key_current_right_part, feistel_key = self._make_keys(key_current_left_part,
                                                                                         key_current_right_part,
                                                                                         round_no)
            inverse_feistel_keys.append(feistel_key)

        for feistel_key in reversed(inverse_feistel_keys):
            block_current_left_part, block_current_right_part = self._decryption_cycle(block_current_left_part,
                                                                                       block_current_right_part,
                                                                                       feistel_key)
        return self._make_permutation(block_current_left_part + block_current_right_part,
                                      self._inverse_ip_permutation)


def main() -> None:
    key = bitarray(56)
    encoder = Des(Des.generate_parameters(), key)
    with open('input_files/input_lab1.txt', 'r') as f:
        message = bitarray()
        message.frombytes(f.read().encode('UTF-8'))
    encoded_message = encoder.encrypt(message)
    with open('output_files/output_lab1_encoded_message_des.txt', 'wb') as f:
        encoded_message.tofile(f)
    decoded_message = encoder.decrypt(encoded_message)
    with open('output_files/output_lab1_message_des.txt', 'wb') as f:
        decoded_message.tofile(f)


if __name__ == '__main__':
    main()
