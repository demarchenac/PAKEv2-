import json, math, os, random, socket
from threading import *

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from ECPoint import ECPoint
from Parameters import Parameters
from EncondingHelper import EncodingHelper
from Constants import AUTH, OPERATIONS, PARAMETERS, SERVER_CONSTANTS


class SocketClient:
    def __init__(self, sock, identifier, password, host, port, parameters):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock
        self.host = host
        self.port = port

        self.password = password
        self.identifier = identifier
        self.parameters = parameters
        self.config = {}

    def run2(self):
        self.connect(self.host, self.port)

        alpha = random.randint(1, self.parameters.q - 1)
        U1 = self.parameters.G.point_multiplication(alpha)

        pw = bytes(self.password, "utf-8")
        hashed_pw = self.parameters.get_k(pw)
        U2 = self.parameters.A.point_multiplication(hashed_pw)

        U = U1 + U2

        u_as_bytes = U.to_bytes()
        id_client = bytes(self.identifier, "utf-8")

        L = [u_as_bytes, id_client]

        array = EncodingHelper.encodeArray(L)
        array = EncodingHelper.encodeArray([array])
        self.send(array)

        arrayRec = self.receive()

        L = EncodingHelper.decodeArray(arrayRec)

        v_as_bytes = L[0]
        id_server = L[1]

        V = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, v_as_bytes)
        V2 = self.parameters.B.point_multiplication(hashed_pw)
        W = (V - V2).point_multiplication(alpha)
        w_as_bytes = W.to_bytes()

        keyblob = self.parameters.H(
            pw, id_client, id_server, u_as_bytes, v_as_bytes, w_as_bytes, 45
        )

        key = keyblob[:32]
        nonce = keyblob[32:]
        mask = int("0xffffffffffffffffffffffffff", base=16)
        # print(keyblob.hex())
        nonce_as_int = int.from_bytes(nonce, "big")
        cont = True
        while cont:
            print("Escriba un mensaje para enviar: Si escribe 'exit' finaliza")
            message = input()

            data = bytes(message, "utf-8")
            nonce = nonce_as_int.to_bytes(13, byteorder="big")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            print(ciphertext)
            nonce_as_int = (nonce_as_int + 1) & mask
            array = EncodingHelper.encodeArray([tag + ciphertext])
            self.send(array)

            if message == "exit":
                cont = False

        self.sock.close()

    def run(self):
        self.connect(self.host, self.port)
        configExists = self.verifyConfig()
        if configExists:
            config = {}
            with open(f"./.clients/{self.identifier}.json", "r") as jsonDB:
                content = jsonDB.read()
                config = json.loads(content)
            self.config = config
        else:
            self.preRegister()

        print("[Info] Conectado al servidor")
        print(self.config)

    def connect(self, host, port):
        self.sock.connect((host, port))
        # c=self.receive()

    def verifyConfig(self):
        directoryExists = os.path.exists("./.clients")
        if not directoryExists:
            os.mkdir("./.clients")

        configExists = os.path.exists(f"./.clients/{self.identifier}.json")
        return configExists

    def preRegister(self):
        _concat = self.password + self.identifier + SERVER_CONSTANTS["IDENTIFIER"]
        salt = get_random_bytes(16)
        halvedNumBytes = math.ceil(self.parameters.n / 8)

        h = PBKDF2(
            _concat, salt, 2 * halvedNumBytes, count=100000, hmac_hash_module=SHA512
        )
        pi0_prime = int.from_bytes(h[:halvedNumBytes], "big")
        pi1_prime = int.from_bytes(h[halvedNumBytes:], "big")

        pi0 = pi0_prime % self.parameters.q
        pi1 = pi1_prime % self.parameters.q

        C = self.parameters.G.point_multiplication(pi1)  # taken from slides.

        message = [
            bytes(OPERATIONS["PRE_REGISTER"], "utf-8"),
            bytes(self.identifier, "utf-8"),
            pi0.to_bytes(halvedNumBytes, byteorder="big"),
            C.to_bytes(),
        ]

        message = EncodingHelper.encodeArray(message)
        message = EncodingHelper.encodeArray([message])
        self.send(message)

        response = self.receive()
        payload = EncodingHelper.decodeArray(response)
        operation = payload[0].decode("utf-8")
        if OPERATIONS["SERVER_RESPONSE"] in operation and self.identifier in operation:
            isSuccesful = payload[1].decode("utf-8") == "Success"
            if isSuccesful:
                row = {"identifier": self.identifier, "pi0": pi0, "pi1": pi1}
                with open(f"./.clients/{self.identifier}.json", "w") as jsonDB:
                    json.dump(row, jsonDB, indent=2)
                self.config["pi0"] = pi0
                self.config["pi1"] = pi1
            else:
                print("Error de conexion")

    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                self.sock.close()
            totalsent = totalsent + sent

    def receive(self):
        bytes_recd = 0
        chunk = self.sock.recv(4)
        if chunk == b"":
            self.sock.close()

        bytes_recd = 0
        msglen = int.from_bytes(chunk, byteorder="big")
        chunks = []
        while bytes_recd < msglen:
            chunk = self.sock.recv(min(msglen - bytes_recd, 2048))

            if chunk == b"":
                self.sock.close()
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)

        return b"".join(chunks)


def startSocketClient():
    user = input("Usuario: ")
    password = input("Contraseña: ")
    os.system("cls" if os.name == "nt" else "clear")
    print("Estableciendo conexion con el servidor...")

    param = Parameters(
        PARAMETERS["A"]["X"],
        PARAMETERS["A"]["Y"],
        PARAMETERS["B"]["X"],
        PARAMETERS["B"]["Y"],
    )

    client = SocketClient(
        None,
        user,
        password,
        SERVER_CONSTANTS["HOST"],
        SERVER_CONSTANTS["PORT"],
        param,
    )

    client.run()


if __name__ == "__main__":
    startSocketClient()
