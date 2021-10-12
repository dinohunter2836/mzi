from bitarray import bitarray

from lab1_des import Des, DesCipherConstParameters
from block_cipher import BlockCipher


class TripleDes(BlockCipher, message_block_length=64):
    def __init__(self, const_parameters: DesCipherConstParameters, first_key: bitarray, second_key: bitarray) -> None:
        self._des_cipher = Des(const_parameters, first_key)
        self._first_key = first_key
        self._second_key = second_key

    def _encrypt_block(self, message_block: bitarray) -> bitarray:
        self._des_cipher.change_key(self._first_key)
        firstly_encrypted_message_block = self._des_cipher._encrypt_block(message_block)

        self._des_cipher.change_key(self._second_key)
        firstly_decrypted_message_block = self._des_cipher._decrypt_block(firstly_encrypted_message_block)

        self._des_cipher.change_key(self._first_key)
        secondly_encrypted_message_block = self._des_cipher._encrypt_block(firstly_decrypted_message_block)

        return secondly_encrypted_message_block

    def _decrypt_block(self, message_block: bitarray) -> bitarray:
        self._des_cipher.change_key(self._first_key)
        firstly_decrypted_message_block = self._des_cipher._decrypt_block(message_block)

        self._des_cipher.change_key(self._second_key)
        firstly_encrypted_message_block = self._des_cipher._encrypt_block(firstly_decrypted_message_block)

        self._des_cipher.change_key(self._first_key)
        secondly_decrypted_message_block = self._des_cipher._decrypt_block(firstly_encrypted_message_block)

        return secondly_decrypted_message_block


def main() -> None:
    keys = bitarray(56), bitarray(56)
    encoder = TripleDes(Des.generate_parameters(), *keys)
    with open('input_files/input_lab1.txt', 'r') as f:
        message = bitarray()
        message.frombytes(f.read().encode('UTF-8'))
    encoded_message = encoder.encrypt(message)
    with open('output_files/output_lab1_encoded_message_triple_des.txt', 'wb') as f:
        encoded_message.tofile(f)
    decoded_message = encoder.decrypt(encoded_message)
    with open('output_files/output_lab1_message_triple_des.txt', 'wb') as f:
        decoded_message.tofile(f)


if __name__ == '__main__':
    main()
