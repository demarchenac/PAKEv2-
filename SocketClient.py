import random, socket
from threading import *
from Crypto.Cipher import AES
from ECPoint import ECPoint
from Parameters import Parameters
from EncondingHelper import EncodingHelper
from Constants import AUTH, PARAMETERS, SERVER_CONSTANTS


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

    def run(self):
        self.connect(self.host, self.port)

        alpha = random.randint(1, self.parameters.q - 1)
        U1 = self.parameters.G.point_multiplication(alpha)

        pw = bytes(self.password, "utf-8")
        K = self.parameters.get_k(pw)
        U2 = self.parameters.A.point_multiplication(K)

        U = U1 + U2

        ubytes = U.to_bytes()
        id_client = bytes(self.identifier, "utf-8")

        L = [ubytes, id_client]

        array = EncodingHelper.encodeArray(L)

        array = EncodingHelper.encodeArray([array])

        self.send(array)

        arrayRec = self.receive()

        L = EncodingHelper.decodeArray(arrayRec)

        vbytes = L[0]
        id_server = L[1]

        V = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, vbytes)

        V2 = self.parameters.B.point_multiplication(K)

        W = (V - V2).point_multiplication(alpha)

        wbytes = W.to_bytes()

        keyblob = self.parameters.H(
            pw, id_client, id_server, ubytes, vbytes, wbytes, 45
        )

        key = keyblob[:32]
        nonce = keyblob[32:]
        mask = int("0xffffffffffffffffffffffffff", base=16)
        # print(keyblob.hex())
        vnonce = int.from_bytes(nonce, "big")
        cont = True
        while cont:
            print("Escriba un mensaje para enviar: Si escribe 'exit' finaliza")
            message = input()

            data = bytes(message, "utf-8")
            nonce = vnonce.to_bytes(13, byteorder="big")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            print(ciphertext)
            vnonce = (vnonce + 1) & mask
            array = EncodingHelper.encodeArray([tag + ciphertext])
            self.send(array)

            if message == "exit":
                cont = False

        self.sock.close()

    def connect(self, host, port):
        self.sock.connect((host, port))
        # c=self.receive()

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
    param = Parameters(
        PARAMETERS["A"]["X"],
        PARAMETERS["A"]["Y"],
        PARAMETERS["B"]["X"],
        PARAMETERS["B"]["Y"],
    )

    client = SocketClient(
        None,
        AUTH["USER"],
        AUTH["PASSWORD"],
        SERVER_CONSTANTS["HOST"],
        SERVER_CONSTANTS["PORT"],
        param,
    )

    client.run()


if __name__ == "__main__":
    startSocketClient()
