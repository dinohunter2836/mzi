import typing as tp
from numpy.random import randint
from functions import factorize, is_prime


class ElGamal:
    def __init__(self, p: int) -> None:
        """
        :param p: random prime number, larger than 2
        """
        assert is_prime(p)
        self.p = p
        self.session_key = randint(1, self.p)
        self.x = randint(1, self.p)
        self.g = self.find_primitive_root()
        assert self.g is not None
        self.y = pow(self.g, self.x, self.p)

    def find_primitive_root(self) -> tp.Optional[int]:
        """
        For prime numbers primitive root can generate any element of multiplicative
        group of integers modulo p (except 0) by raising it into some power
        :return: smallest primitive root if there's any. For primes above 2 there's always at least one
        (more precisely phi(p - 1))
        """
        for i in range(2, self.p - 1):
            flag = False
            for key in factorize(self.p - 1).keys():
                if pow(i, (self.p - 1) // key, self.p) == 1:
                    flag = True
                    break
            if not flag:
                return i

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
                for chunk in ElGamal.slice_into_chunks(message.encode('UTF-8'), 4)]

    @staticmethod
    def decode_message(encoded_message: tp.List[int]) -> str:
        return ''.join(map(ElGamal._int_to_str, encoded_message))

    def encrypt(self, message: str) -> tp.Tuple[int, tp.List[int]]:
        first = pow(self.g, self.session_key, self.p)
        second = [(item * pow(self.y, self.session_key, self.p)) % self.p
                  for item in ElGamal.encode_message(message)]
        return first, second

    def decrypt(self, first: int, second: tp.List[int]) -> str:
        return ElGamal.decode_message([item * pow(first, -self.x, self.p) % self.p for item in second])


def main() -> None:
    prime = 4294969633
    encoder = ElGamal(prime)
    with open('input_files/input_lab4.txt', 'r') as f:
        message = f.read()
    a, b = encoder.encrypt(message)
    with open('output_files/output_lab4_encoded_message', 'w') as f:
        f.write(str(a) + '\n\n')
        f.writelines([str(value) + '\n' for value in b])

    with open('output_files/output_lab4_message', 'w') as f:
        f.write(encoder.decrypt(a, b))


if __name__ == '__main__':
    main()
