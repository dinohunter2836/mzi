import typing as tp

from abc import abstractmethod
from bitarray import bitarray


class BlockCipher:
    def __init_subclass__(cls, /, message_block_length: int, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        cls._message_block_length = message_block_length

    @abstractmethod
    def _encrypt_block(self, message: bitarray) -> bitarray:
        pass

    @abstractmethod
    def _decrypt_block(self, message: bitarray) -> bitarray:
        pass

    def encrypt(self, message: bitarray) -> bitarray:
        encrypted_message = bitarray()
        for i in range(len(message) // self._message_block_length):
            encrypted_message.extend(
                self._encrypt_block(message[i * self._message_block_length: (i + 1) * self._message_block_length]))
        if len(message) % self._message_block_length != 0:
            last_block = message[(len(message) // self._message_block_length) * self._message_block_length:]
            last_block.extend([0] * (self._message_block_length - (len(message) % self._message_block_length)))
            encrypted_message.extend(self._encrypt_block(last_block))
        return encrypted_message

    def decrypt(self, message: bitarray) -> bitarray:
        decrypted_message = bitarray()
        for i in range(len(message) // self._message_block_length):
            decrypted_message.extend(
                self._decrypt_block(message[i * self._message_block_length: (i + 1) * self._message_block_length]))
        return decrypted_message

    def encrypt_file(self, input_file: tp.BinaryIO, output_file: tp.BinaryIO) -> int:
        input_file_message = bitarray()
        input_file_message.fromfile(input_file)
        encrypted_file_message = self.encrypt(input_file_message)
        encrypted_file_message.tofile(output_file)
        return len(input_file_message)

    def decrypt_file(self, input_file: tp.BinaryIO, output_file: tp.BinaryIO,
                     initial_message_length: tp.Optional[int] = None) -> None:
        input_file_message = bitarray()
        input_file_message.fromfile(input_file)
        decrypted_file_message = self.decrypt(input_file_message)
        decrypted_file_message[slice(None, initial_message_length)].tofile(output_file)
