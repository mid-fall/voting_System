import ecdsa
import hashlib
import random
import gmpy2
from ecdsa.numbertheory import inverse_mod
from ecpy.curves import Curve, Point


class Generator():
    Elliptic_curve_type = 'SECP256k1'

    def __init__(self):
        self.curve = ecdsa.curves.SECP256k1  # 获取标准椭圆曲线SECP256K1
        self.base_point = self.curve.generator  # 获取椭圆曲线的基点
        self.order = self.curve.order  # 获取椭圆曲线的阶

    def generate_secret_keys(self):
        sk = ecdsa.SigningKey.generate(curve=self.curve)
        vk = sk.get_verifying_key()

        private_key_hex = sk.to_string().hex()
        public_key_hex = vk.to_string().hex()

        cert = {'sk': private_key_hex, 'pk': public_key_hex}
        return cert


class cryptofunction():
    ZKProof_CONFIRM_SUCCESS = 0
    ZKProof_CONFIRM_FAILED = 1
    Signature_CONFIRM_SUCCESS = 0
    Signature_CONFIRM_FAILED = 1

    def __init__(self):
        self.curve = ecdsa.curves.SECP256k1  # 获取标准椭圆曲线SECP256K1
        self.base_point = self.curve.generator  # 获取椭圆曲线的基点
        self.order = self.curve.order  # 获取椭圆曲线的阶
        self.cv = Curve.get_curve('secp256k1')  # 使用ecpy库获取椭圆曲线SECP256K1

    def Str2SigningKey(self, sk: str):
        sk_bytes = bytes.fromhex(sk)
        sk_SigningKey = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
        return sk_SigningKey

    def Str2VerifyingKey(self, pk: str):
        pk_bytes = bytes.fromhex(pk)
        pk_VerifyingKey = ecdsa.VerifyingKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
        return pk_VerifyingKey

    def generate_standard_cert(self, my_cert):
        return self.Str2SigningKey(my_cert['sk']), self.Str2VerifyingKey(my_cert['pk'])
        # rec_private_key_hex = my_cert['sk']
        # rec_public_key_hex = my_cert['pk']
        # received_private_key_bytes = bytes.fromhex(rec_private_key_hex)
        # received_public_key_bytes = bytes.fromhex(rec_public_key_hex)
        #
        # # 从字节串中还原私钥和公钥对象
        # received_sk = ecdsa.SigningKey.from_string(received_private_key_bytes, curve=ecdsa.SECP256k1)
        # received_pk = ecdsa.VerifyingKey.from_string(received_public_key_bytes, curve=ecdsa.SECP256k1)
        #
        # return received_sk, received_pk             # 返回元组，值为ecdsa中的SigningKey对象和VerifyingKey对象

    def generate_ZKProof(self, my_stardard_cert: tuple):
        received_sk_int = int.from_bytes(my_stardard_cert[0].to_string(), byteorder="big")

        # 计算 R = r * G
        r = random.randint(1, self.order - 1)
        R = self.base_point * r
        R_x = int(R.x())
        R_y = int(R.y())

        # 计算哈希值 c = Hash(PK || R)
        hash_input = self.PublicKey2Str(my_stardard_cert[1]) + self.PointJacobi2Str(R)
        c = int.from_bytes(hashlib.sha256(hash_input.encode()).digest(), byteorder="big")

        # 计算 z = r + c * sk
        z = r + c * received_sk_int

        return {'x': R_x, 'y': R_y}, z

    def Confirm_ZKProof(self, ZKProof: tuple, pk: ecdsa.VerifyingKey):
        x_mpz = gmpy2.mpz(ZKProof[0]['x'])
        y_mpz = gmpy2.mpz(ZKProof[0]['y'])
        confirm_hash_input = self.PublicKey2Str(pk) + x_mpz.digits(16) + y_mpz.digits(16)
        e = int.from_bytes(hashlib.sha256(confirm_hash_input.encode()).digest(), byteorder="big")

        # 使用ecdsa库，计算出PointJacobi类型变量
        equal_left = ZKProof[1] * self.base_point
        equal_left_x = equal_left.x()
        equal_left_y = equal_left.y()

        # 使用ecpy库，计算出Point变量
        R_point = Point(ZKProof[0]['x'], ZKProof[0]['y'], self.cv)
        pk_point = Point(pk.pubkey.point.x(), pk.pubkey.point.y(), self.cv)
        equal_right = R_point + e * pk_point

        if equal_left_x == equal_right.x and equal_left_y == equal_right.y:
            print('ZKProof Confirm Success!')
            return self.ZKProof_CONFIRM_SUCCESS
        else:
            print('ZKProof Confirm Failed!')
            return self.ZKProof_CONFIRM_FAILED

    def generate_signature(self, data: str, sk: ecdsa.SigningKey):
        received_sk_int = int.from_bytes(sk.to_string(), byteorder="big")

        k = random.randint(1, self.order-1)
        K = self.base_point * k
        signature_hash_input = data
        Hash = int.from_bytes(hashlib.sha256(signature_hash_input.encode()).digest(), byteorder="big")

        K_x = K.x()
        r = K_x % self.order
        k_inverse = inverse_mod(k, self.order)
        s = (Hash + r * received_sk_int) * k_inverse % self.order
        return int(r), int(s)

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
            return self.Signature_CONFIRM_SUCCESS
        else:
            return self.Signature_CONFIRM_FAILED

    def encrypt_data(self, plaintext: str, pk: ecdsa.VerifyingKey):
        # jiami
        return plaintext

    def decrypt_data(self, ciphertext: str, sk: ecdsa.SigningKey):
        # jiemi
        return ciphertext

    def PointJacobi2Str(self, R: ecdsa.ellipticcurve.PointJacobi):
        x = R.x()
        y = R.y()
        x_str = x.digits(16)
        y_str = y.digits(16)
        R_str = x_str + y_str
        return R_str

    def PublicKey2Str(self, pk: ecdsa.VerifyingKey):
        return pk.to_string().hex()


