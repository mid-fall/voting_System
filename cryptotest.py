import ecdsa
import hashlib
import random
from gmpy2 import mpz
from Crypto.PublicKey import ECC
from Crypto.Util.number import long_to_bytes
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.numbertheory import inverse_mod
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from coincurve import PrivateKey, PublicKey
from ecpy.curves     import Curve, Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA
from ecpy.curves     import Curve,Point

# 生成SECP256K1椭圆曲线
curve = ecdsa.curves.SECP256k1

# 创建椭圆曲线对象
sk = ecdsa.SigningKey.generate(curve=curve)

# 获取对应的验证密钥
vk = sk.get_verifying_key()

# 获取基点（也称为生成元）
base_point = curve.generator

order = curve.order

private_key_int = int.from_bytes(sk.to_string(), byteorder="big")
public_key_int = int.from_bytes(vk.to_string(), byteorder="big")

private_key_hex = sk.to_string().hex()
public_key_hex = vk.to_string().hex()

# 将十六进制字符串转换为字节串
received_private_key_bytes = bytes.fromhex(private_key_hex)
received_public_key_bytes = bytes.fromhex(public_key_hex)

# 从字节串中还原私钥和公钥对象
received_sk = ecdsa.SigningKey.from_string(received_private_key_bytes, curve=ecdsa.SECP256k1)
received_vk = ecdsa.VerifyingKey.from_string(received_public_key_bytes, curve=ecdsa.SECP256k1)

print(private_key_hex, '\n', public_key_hex)

if received_sk == sk:
    print('AAAAAAAA')

if received_vk == vk:
    print('BBBBBBBB')

r = random.randint(1, order-1)
R = base_point * r


print('vk_string:', vk, '\n')

x = R.x()
y = R.y()
x_digits = x.digits()                         # 使用16进制字符串表示大整数
y_digits = y.digits()
R_str = x_digits + y_digits

pk_str = vk.to_string().hex()

hash_input = pk_str + R_str
c = int.from_bytes(hashlib.sha256(hash_input.encode()).digest(), byteorder="big")

sk_int = int.from_bytes(sk.to_string(), byteorder="big")

pk_point = sk_int * base_point          # 这是什么类型？
z = r + c * sk_int

left = z * base_point
left_x = left.x()
letf_x_str = left_x.digits(16)
left_y = left.y()

pk_x = vk.pubkey.point.x()
pk_y = vk.pubkey.point.y()
pk_z = 1
pk_jacobi = PointJacobi(curve, pk_x, pk_y, pk_z)

cv   = Curve.get_curve('secp256k1')

R_point = Point(x, y, cv)
pk_point = Point(pk_x, pk_y, cv)
right = R_point + c * pk_point

print("Point Object:", pk_point)
if left_x == right.x and left_y == right.y:
    print('Success!')
# right = curve.add_points(R, c * pk_jacobi)
# if left == right:
#     print("Success!")
class test():
    def __init__(self):
        self.curve = ecdsa.curves.SECP256k1  # 获取标准椭圆曲线SECP256K1
        self.base_point = self.curve.generator  # 获取椭圆曲线的基点
        self.order = self.curve.order  # 获取椭圆曲线的阶
        self.cv = Curve.get_curve('secp256k1')  # 使用ecpy库获取椭圆曲线SECP256K1

    def generate_signature(self, data: str, sk: ecdsa.SigningKey):
        received_sk_int = int.from_bytes(sk.to_string(), byteorder="big")

        k = random.randint(1, self.order - 1)
        K = self.base_point * k
        signature_hash_input = data
        Hash = int.from_bytes(hashlib.sha256(signature_hash_input.encode()).digest(), byteorder="big")

        K_x = K.x()
        r = K_x % self.order
        k_inverse = inverse_mod(k, self.order)
        s = (Hash + r * received_sk_int) * k_inverse % self.order

        return r, s

    def confirm_signature(self, data: str, signature: tuple, pk: ecdsa.VerifyingKey):
        confirm_signature_hash_input = data
        ConfirmHash = int.from_bytes(hashlib.sha256(confirm_signature_hash_input.encode()).digest(), byteorder="big")
        w = inverse_mod(signature[1], self.order)

        # 使用pow计算
        u1 = int(pow(ConfirmHash * w, 1, self.order))
        u2 = int(pow(signature[0] * w, 1, self.order))

        R_1 = u1 * self.base_point
        R_1_point = Point(R_1.x(), R_1.y(), self.cv)
        pk_point = Point(pk.pubkey.point.x(), pk.pubkey.point.y(), self.cv)
        R_point = R_1_point + u2 * pk_point
        v = R_point.x % self.order

        if v == signature[0]:
            print('Signature Success!')


test = test()
data = 'asdfaoewjgfoljo;aweifqqfj;wqeofkqwoejfqwer'
signature = test.generate_signature(data, sk)
test.confirm_signature(data, signature, vk)

