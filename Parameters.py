import math, random
from Crypto.Hash import SHAKE256
from ECPoint import ECPoint
from FP import FP


class Parameters:
    def __init__(self, xa=None, ya=None, xb=None, yb=None):

        self.p = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1
        self.a = FP(-3, self.p)
        self.b = FP(
            41058363725152142129326129780047268409114441015993725554835256314039467401291,
            self.p,
        )

        x = FP(
            48439561293906451759052585252797914202762949526041747995844080717082404635286,
            self.p,
        )

        y = FP(
            36134250956749795798585127919587881956611106672985015071877198253568414405109,
            self.p,
        )

        self.q = 2 ** 256 - 2 ** 224 + 2 ** 192 - 89188191075325690597107910205041859247
        self.G = ECPoint(self.a, self.b, x, y)

        self.n = math.ceil(math.log2(self.q))

        if xa != None and ya != None and xb != None and yb != None:
            self.A = ECPoint(self.a, self.b, FP(xa, self.p), FP(ya, self.p))
            self.B = ECPoint(self.a, self.b, FP(xb, self.p), FP(yb, self.p))

        else:
            self.A = None
            self.B = None

    @staticmethod
    def get_public_element():
        param = Parameters()
        c = random.randint(1, param.q - 1)
        return param.G.point_multiplication(c)

    def isECPointValid(self, point):
        # Verify U
        y_r = point.y ** 2
        x_r = (
            (point.x ** 3) + (self.a * point.x) + self.b
        )  # since a=-3, then we just +(a*x_u)

        areEqual = x_r == y_r
        isNone = ECPoint(self.a, self.b, x=x_r, y=y_r).is_identity()

        return areEqual and not isNone

    def get_k(self, pw, n=256):
        h_256 = SHAKE256.new()
        string = b"fixedString"

        h_256.update(string + pw)

        k = int.from_bytes(h_256.read(n), "big")
        return k % self.q

    def Hk(self, k, params, n=32):
        h_256 = SHAKE256.new()
        fixed = bytes(f"fixedString#{k}", 'utf-8')

        h_256.update(fixed)

        [h_256.update(param) for param in params]

        return h_256.read(n)

    def H(self, pw, idp, idq, ubytes, vbytes, wbytes, n=32):
        h_256 = SHAKE256.new()
        h_256.update(pw)
        h_256.update(idp)
        h_256.update(idq)
        h_256.update(ubytes)
        h_256.update(vbytes)
        h_256.update(wbytes)
        return h_256.read(n)
