import typing as tp

from numpy.random import randint
from functions import is_prime, are_relatively_prime


class RSA:
    def __init__(self, private_key: tp.Tuple[int, int], public_key: tp.Tuple[int, int]):
        self._public_key = public_key
        self._private_key = private_key

    @staticmethod
    def generate_key_pair(p: int, q: int) -> tp.Tuple[tp.Tuple[int, int], tp.Tuple[int, int]]:
        assert is_prime(p)
        assert is_prime(q)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = randint(1, n)
        while not are_relatively_prime(d, phi):
            d = randint(1, n)
        e = pow(d, -1, phi)
        return (d, n), (e, n)

    @staticmethod
    def slice_into_chunks(array: bytes, chunk_size: int) -> tp.Generator[tp.SupportsBytes, None, None]:
        """
        Allows to slice bytes array into evenly sized chunks
        :param array: array to slice
        :param chunk_size: size of each chunk
        :return: yields chunks one by one
        """
        for i in range(0, len(array) - chunk_size, chunk_size):
            yield list(array[i: i + chunk_size])
        output = list(reversed(array[len(array) - len(array) % chunk_size: len(array)]))
        while len(output) % chunk_size > 0:
            output.append(0x00)
        yield list(reversed(output))

    @staticmethod
    def _int_to_str(num: int) -> str:
        result = ''
        while num > 0:
            result += chr(num & 255)
            num >>= 8
        return ''.join(reversed(result))

    @staticmethod
    def encode_message(message: str) -> tp.List[int]:
        return [int.from_bytes(chunk, byteorder='big', signed=False)
                for chunk in RSA.slice_into_chunks(message.encode('UTF-8'), 4)]

    @staticmethod
    def decode_message(encoded_message: tp.List[int]) -> str:
        return ''.join(map(RSA._int_to_str, encoded_message))

    def encrypt(self, message: str) -> tp.List[int]:
        return [pow(m, *self._public_key) for m in RSA.encode_message(message)]

    def decrypt(self, message: tp.List[int]) -> str:
        return RSA.decode_message([pow(m, *self._private_key) for m in message])


def main() -> None:
    p, q = 68963, 66047
    private_key, public_key = RSA.generate_key_pair(p, q)
    encoder = RSA(private_key, public_key)

    with open('input_files/input_lab3.txt', 'r') as f:
        message = f.read()
    encoded_message = encoder.encrypt(message)
    with open('output_files/output_lab3_encoded_message', 'w') as f:
        f.writelines([str(value) + '\n' for value in encoded_message])

    with open('output_files/output_lab3_message', 'w') as f:
        f.write(encoder.decrypt(encoded_message))


if __name__ == '__main__':
    main()
