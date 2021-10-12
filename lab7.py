import typing as tp
from secrets import randbelow

import tinyec.ec as ec
from tinyec import registry

from functions import get_message_hash


# making classes Point and Inf from tinyec hashable
# so they can be used as a dict key in encoder
ec.Point.__hash__ = lambda self: hash(self.x) ^ hash(self.y)
ec.Inf.__hash__ = lambda self: hash(self.x) ^ hash(self.y)


class BaseEllipticCurveClass:
    """
    Base class for signature and encoder
    Implements key pair generation needed for both classes
    """
    def __init__(self, curve: ec.Curve) -> None:
        self.curve = curve

    def generate_key_pair(self) -> tp.Tuple[int, ec.Point]:
        private_key = randbelow(self.curve.field.n - 1) + 1
        public_key = self.curve.g * private_key
        return private_key, public_key


class DigitalSignature(BaseEllipticCurveClass):
    def __init__(self, curve: ec.Curve) -> None:
        super().__init__(curve)
        self._private_key = 0

    def get_signature(self, message: str) -> tp.Tuple[int, int, ec.Point]:
        key, public_key = self.generate_key_pair()
        r, s = 0, 0
        hashed_message = get_message_hash(message)
        while r == 0 or s == 0:
            self._private_key = randbelow(self.curve.field.n - 1) + 1
            point = self.curve.g * self._private_key
            r = point.x % self.curve.field.n
            try:
                s = pow(self._private_key, -1, self.curve.field.n) * (hashed_message + key * r) % \
                    self.curve.field.n
                pow(s, -1, self.curve.field.n)
            except ValueError:
                s = 0
        return r, s, public_key

    def verify_signature(self, message: str, r: int, s: int, public_key: ec.Point) -> bool:
        hashed_message = get_message_hash(message)
        w = pow(s, -1, self.curve.field.n)
        u1 = hashed_message * w % self.curve.field.n
        u2 = r * w % self.curve.field.n
        point = self.curve.g * u1 + public_key * u2
        return point.x == r


class Encoder(BaseEllipticCurveClass):
    def __init__(self, curve: ec.Curve):
        super().__init__(curve)
        multiplier = randbelow(self.curve.field.n - 1) + 1
        self._encoding_table = {
            i: curve.g * multiplier * i for i in range(256)
        }
        self._decoding_table = {
            curve.g * multiplier * i: i for i in range(256)
        }

    def _message_to_points(self, message: str) -> tp.List[ec.Point]:
        """
        This method allows to convert string into points on the elliptic curve.
        It is required for encrypting, as only curve points can be encrypted
        :param message: message for further encoding
        :return: message, converted to points
        """
        result: tp.List[ec.Point] = []
        for byte in message.encode('UTF-8'):
            result.append(self._encoding_table[byte])
        return result

    def _points_to_message(self, points: tp.List[ec.Point]) -> str:
        """
        Inverse of the previous method
        :param points: decrypted sequence of points
        :return: decrypted message
        """
        message: tp.List[str] = []
        for point in points:
            message.append(self._decoding_table[point])
        return ''.join(map(chr, message))

    def encode(self, message: str, public_key: ec.Point) -> tp.Tuple[tp.List[ec.Point], ec.Point]:
        assert self.curve == public_key.curve
        assert len(message)
        points = self._message_to_points(message)
        k = randbelow(self.curve.field.n - 1) + 1
        encoded_message = [point + public_key * k for point in points]
        return encoded_message, self.curve.g * k

    def decode(self, encoded_message: tp.List[ec.Point], private_key: int, public_key: ec.Point) -> str:
        assert self.curve == encoded_message[0].curve
        assert self.curve == public_key.curve
        return self._points_to_message([encoded_char - public_key * private_key
                                       for encoded_char in encoded_message])


def test_signature() -> None:
    curve = registry.get_curve('secp256r1')
    ds = DigitalSignature(curve)
    with open('input_files/input_lab7_signature.txt', 'r') as f:
        message = f.readline()
        wrong_message = f.readline()
    r, s, public_key = ds.get_signature(message)
    print(f'r = {r}, s = {s}')
    print(f'Signature verification result for correct message: {ds.verify_signature(message, r, s, public_key)}')
    print(f'Signature verification result for incorrect message: {ds.verify_signature(wrong_message, r, s, public_key)}')
    print(f'Signature verification result for wrong values r and s: {ds.verify_signature(wrong_message, r - 1, s + 5, public_key)}')


def test_encoder() -> None:
    curve = registry.get_curve('secp256r1')
    encoder = Encoder(curve)
    first_private_key, first_public_key = encoder.generate_key_pair()
    with open('input_files/input_lab7_cipher.txt', 'r') as f:
        message = f.read()
    encoded_message, public_key = encoder.encode(message, first_public_key)
    with open('output_files/output_lab7_encoded_message', 'w') as f:
        f.write('public key: ' + str(public_key) + '\n\n')
        f.writelines([str(point) + '\n' for point in encoded_message])
    decoded_message = encoder.decode(encoded_message, first_private_key, public_key)
    with open('output_files/output_lab7_message', 'w') as f:
        f.write(decoded_message)


def main() -> None:
    test_signature()
    test_encoder()


if __name__ == '__main__':
    main()
