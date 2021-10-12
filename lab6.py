import typing as tp
from numpy.random import randint
from functions import is_prime, modular_multiplicative_inverse, get_message_hash, factorize


class DigitalSignature:
    def __init__(self, p: int, q: int) -> None:
        """
        These are preferable sizes, though not required
        :param p: prime number
        :param q: prime number, divider of p - 1
        """
        assert is_prime(p)
        assert is_prime(q)
        if (p - 1) % q != 0:
            raise ValueError('q should be a divider of p - 1')
        self.p = p
        self.q = q
        self.g = pow(modular_multiplicative_inverse(q, p), (p - 1) // q, p)
        self.r = 0
        self.s = 0
        self._private_key = randint(1, q)
        self._session_key = randint(1, q)
        self.public_key = pow(self.g, self._private_key, self.p)

    def get_signature(self, message: str) -> tp.Tuple[int, int]:
        hashed_message = get_message_hash(message) % self.p
        self.r = pow(self.g, self._session_key, self.p) % self.q
        self.s = (self._session_key * hashed_message + self._private_key * self.r) % self.q
        return self.r, self.s

    def verify_signature(self, message: str) -> bool:
        hashed_message = get_message_hash(message) % self.p
        w = pow(hashed_message, -1, self.q)
        u1 = w * self.s % self.q
        u2 = (self.q - self.r) * w % self.q
        v = pow(self.g, u1, self.p) * pow(self.public_key, u2, self.p) % self.p % self.q
        return v == self.r


def main() -> None:
    # prime = 33703
    # also_prime = 137
    prime = 4294977287
    also_prime = 2147488643
    ds = DigitalSignature(prime, also_prime)
    with open('input_files/input_lab6.txt') as f:
        message = f.readline()
        wrong_message = f.readline()
    r, s = ds.get_signature(message)
    print(f'r = {r}, s = {s}')
    print(f'Signature verification result for correct message: {ds.verify_signature(message)}')
    print(f'Signature verification result for incorrect message: {ds.verify_signature(wrong_message)}')


if __name__ == '__main__':
    main()
