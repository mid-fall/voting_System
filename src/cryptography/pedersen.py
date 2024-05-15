"""
Adapted from:
https://asecuritysite.com/encryption/ped
"""

from Crypto import Random
from Crypto.Util import number

class Pedersen:
    @staticmethod
    def parse_param(param):
        return param['q'], param['g'], param['h']

    @staticmethod
    def generate_param(security):
        p = number.getPrime(2*security, Random.new().read)
        q = 2 * p + 1
        g = number.getRandomRange(1, q-1)
        s = number.getRandomRange(1, q-1)
        h = pow(g, s, q)
        param = {
            'q': q,
            'g': g,
            'h': h,
        }
        return param

    @staticmethod
    def add(param, l_commitments):
        addCm = 1
        for x in l_commitments:
            addCm *= x
        q = param['q']
        addCm = addCm % q
        return addCm

    @staticmethod
    def open(c, m, r, param):
        q, g, h = Pedersen.parse_param(param)
        if r is list:
            sum = 0
            for x in r:
                sum += x
        else:
            sum = r
        res = (pow(g, m, q) * pow(h, sum, q) % q)
        return c == res

    @staticmethod
    def commit(m, param):
        q, g, h = Pedersen.parse_param(param)
        r = number.getRandomRange(1, q-1)
        c = (pow(g, m, q) * pow(h, r, q) % q)
        return c, r