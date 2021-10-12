import typing as tp

from collections import defaultdict
from hashlib import sha256
from bitarray import bitarray


def factorize(n: int) -> tp.Dict[int, int]:
    """
    Factorizes number into primes
    :param n: some integer
    :return: dict with primes as keys and powers as values
    """
    d = 2
    result = defaultdict(int)
    while d * d <= n:
        while n % d == 0:
            result[d] += 1
            n //= d
        if d == 2:
            d = 3
        else:
            d += 2
    if n != 1:
        result[n] = 1
    return result


def phi(num: int) -> int:
    """
    Calculates Euler's totient function for given inteder
    :param num: some integer
    :return: phi(num)
    """
    assert num > 1
    result = 1
    for key, value in factorize(num).items():
        result *= key ** (value - 1) * (key - 1)
    return result


def is_prime(n: int) -> bool:
    """
    :param n: some integer
    :return: True/False whether n is prime or not
    """
    d = 2
    while d * d <= n:
        if n % d == 0:
            return False
        if d == 2:
            d = 3
        else:
            d += 2
    return True


def extended_euclidean(a: int, b: int) -> tp.Tuple[int, int, int]:
    """
    solves ax + by = gcd(a, b)
    :param a: some integer
    :param b: some integer
    :return: Tuple[x, y, gcd(a, b)]
    """
    r1, r2 = a, b
    s1, s2 = 1, 0
    t1, t2 = 0, 1
    while r2 > 0:
        q = r1 // r2
        r1, r2 = r2, r1 - q * r2
        s1, s2 = s2, s1 - q * s2
        t1, t2 = t2, t1 - q * t2
    return s1, t1, r1


def are_relatively_prime(first: int, second: int) -> bool:
    _, _, residue = extended_euclidean(first, second)
    return residue == 1


def modular_multiplicative_inverse(a: int, b: int) -> int:
    """
    solves ax = 1 (mod b)
    :param a: some integer
    :param b: some integer
    :return: x
    """
    result, _, residue = extended_euclidean(a, b)
    assert residue == 1
    return result % b


def get_message_hash(message: str) -> int:
    """
    :param message: some string
    :return: hash of given string, converted to string
    """
    hashed_message = sha256(message.encode('UTF-8')).digest()
    return int.from_bytes(hashed_message, byteorder='big', signed=False)


def left_cycle_shift(array: bitarray, bits_amount: int) -> bitarray:
    """
    Performs cycle shift of a byte array
    :param array: bitarray to perform cycle shift on
    :param bits_amount: amount of bits to shift right
    :return: array after shift
    """
    return array[bits_amount:] + array[:bits_amount]
