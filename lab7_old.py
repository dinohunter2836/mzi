import typing as tp

from numpy.random import randint
from functions import is_prime, modular_multiplicative_inverse, factorize, are_relatively_prime


class Point:
    def __init__(self, ec: 'EllipticCurve', x: tp.Optional[int], y: tp.Optional[int]) -> None:
        self.ec = ec
        self.x = x
        self.y = y
        assert not (x is None) ^ (y is None)
        assert ec.point_belongs_elliptic_curve(self)

    def __neg__(self) -> 'Point':
        return Point(self.ec, self.x, -self.y)

    def __add__(self, other: 'Point') -> 'Point':
        if self.is_infinite():
            return other
        elif other.is_infinite():
            return self
        elif other == -self:
            return Point(self.ec, None, None)
        try:
            if self != other:
                l = (other.y - self.y) * modular_multiplicative_inverse(other.x - self.x, self.ec.p)
            else:
                l = (3 * self.x ** 2 + self.ec.a) * modular_multiplicative_inverse(2 * self.y, self.ec.p)
            x = (l ** 2 - self.x - other.x) % self.ec.p
            y = (l * (self.x - x) - self.y) % self.ec.p
            return Point(self.ec, x, y)
        except ZeroDivisionError:
            return Point(self.ec, None, None)
        except AssertionError:
            return Point(self.ec, None, None)

    def __mul__(self, n: int) -> 'Point':
        if n == 0:
            return Point(self.ec, None, None)
        result = self
        n -= 1
        current = self
        while n > 0:
            if n % 2 == 0:
                current += current
                n //= 2
            else:
                result += current
                n -= 1
        return result

    def is_infinite(self) -> bool:
        return self.x is None

    def __eq__(self, other) -> bool:
        return self.x == other.x and self.y == other.y

    def __str__(self) -> str:
        return f'({self.x}, {self.y})'

    def __repr__(self) -> str:
        return self.__str__()


class EllipticCurve:
    def __init__(self, a: int, b: int, p: int, g: tp.Tuple[int, int]) -> None:
        assert is_prime(p)
        self.a = a
        self.b = b
        self.p = p
        self.g = Point(self, *g)
        self.finite_field = self._get_finite_field()
        # self.g = self.finite_field[randint(0, len(self.finite_field))]
        self.n = list(factorize(EllipticCurve._get_point_order(self.g) + 1).keys())[-1]
        # print(self.g, self.n)
        # self.n = EllipticCurve._get_point_order(self.g) + 1
        self._private_key = 0
        assert (4 * a ** 3 + 27 * b ** 2) % p != 0

    def _get_finite_field(self) -> tp.List[Point]:
        """
        Used to find suitable points for elliptic curve
        :return: list of all points (except infinite point)
        """
        result: tp.List = []
        for x in range(self.p):
            for y in range(self.p):
                try:
                    point = Point(self, x, y)
                    result.append(point)
                except AssertionError:
                    pass

        return result

    @staticmethod
    def _get_point_order(point: Point) -> int:
        order = 2
        while not (point * order).is_infinite():
            order += 1
        return order

    def point_belongs_elliptic_curve(self, point: Point) -> bool:
        return point.is_infinite() or \
               (point.x ** 3 + self.a * point.x + self.b - point.y ** 2) % self.p == 0

    def generate_key_pair(self) -> tp.Tuple[int, Point]:
        key = randint(1, self.n)
        return key, self.g * key

    def get_signature(self, message: int) -> tp.Tuple[int, int, Point]:
        r, s = 0, 0
        d, public_key = self.generate_key_pair()
        print(d)
        while r == 0 or s == 0:
            self._private_key = randint(1, self.n)
            point = self.g * self._private_key
            r = point.x
            if r is None:
                r = 0
                continue
            try:
                s = pow(self._private_key, -1, self.n) * (message + d * r) % self.n
                pow(s, -1, self.n)
            except ValueError:
                s = 0
            if not are_relatively_prime(s, self.n):
                s = 0
        print(self._private_key)
        return r, s, public_key


    def verify_signature(self, message: int, r: int, s: int, public_key: Point) -> bool:
        w = pow(s, -1, self.n)
        print(w)
        u1 = message * w % self.n
        u2 = r * w % self.n
        print(u1, u2)
        point = self.g * u1 + public_key * u2
        print(point)
        return point.x == r


"""
Elliptic curve I used: 
    p = 1019
    a = 5
    b = 173
    g = (11, 349)
"""

def main():
    ec = EllipticCurve(a=5, b=173, p=1019, g=(11, 349))
    # ec = EllipticCurve(5, 173, 997, (551, 809))
    # ec = EllipticCurve(0, 7, 17, (15, 13))
    first, second, public_key = ec.get_signature(19)
    print(first, second, public_key)
    # for i in range(100, 200):
    #     print(i, ec.verify_signature(i, first, second, public_key))
    print(ec.verify_signature(19, first, second, public_key))


if __name__ == '__main__':
    # ec = EllipticCurve(5, 173, 1019, (796, 555))
    # print(len(ec.finite_field))
    ec = EllipticCurve(0, 7, 17, (15, 13))
    # main()


# (693, 890), (695, 252), (695, 769), (699, 6), (699, 1015), (700, 142), (700, 879)
