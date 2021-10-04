import random, socket
from threading import *
from Crypto.Cipher import AES
from ECPoint import ECPoint
from Parameters import Parameters
from EncondingHelper import EncodingHelper
from Constants import DATABASE, PARAMETERS, SERVER_CONSTANTS, SOCKET_CONSTANTS


class client(Thread):
    def __init__(self, socket, address, identifier, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier = identifier
        self.parameters = parameters
        self.start()

    def retrieve(self, ID):
        if ID in DATABASE.keys():
            return DATABASE[ID]
        else:
            raise ValueError("Error con id")

    def run(self):
        try:
            response = self.receive()

            L = EncodingHelper.decodeArray(response)

            ubytes = L[0]
            id_p = L[1]
            id_ps = id_p.decode("utf-8")

            pwst = self.retrieve(id_ps)

            pw = bytes(pwst, "utf-8")

            K = self.parameters.get_k(pw)

            beta = random.randint(1, self.parameters.q - 1)

            V1 = self.parameters.G.point_multiplication(beta)
            V2 = self.parameters.B.point_multiplication(K)

            V = V1 + V2

            vbytes = V.to_bytes()
            id_q = bytes(self.identifier, "utf-8")

            L = [vbytes, id_q]

            array = EncodingHelper.encodeArray(L)

            self.send(EncodingHelper.encodeArray([array]))

            U2 = self.parameters.A.point_multiplication(K)

            U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)

            W = (U - U2).point_multiplication(beta)

            wbytes = W.to_bytes()

            keyblob = self.parameters.H(pw, id_p, id_q, ubytes, vbytes, wbytes, 45)

            key = keyblob[:32]
            nonce = keyblob[32:]
            mask = int("0xffffffffffffffffffffffffff", base=16)
            vnonce = int.from_bytes(nonce, "big")
            cont = True

            while cont:
                data = self.receive()
                try:
                    nonce = vnonce.to_bytes(13, byteorder="big")
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(data[16:], data[:16])
                    vnonce = (vnonce + 1) & mask
                    print(plaintext.decode("utf-8"))
                    if plaintext == "exit":
                        cont = False
                except:
                    raise RuntimeError("Encryption Error")
            self.sock.close()

        except:
            self.sock.close()

    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
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


def startSocketServer():

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((SERVER_CONSTANTS["HOST"], SERVER_CONSTANTS["PORT"]))
    serversocket.listen(SERVER_CONSTANTS["POOL_SIZE"])
    print("server started and listening")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", SOCKET_CONSTANTS["PORT"]))
    s.listen(SOCKET_CONSTANTS["CON_SIZE"])

    param = Parameters(
        PARAMETERS["A"]["X"],
        PARAMETERS["A"]["Y"],
        PARAMETERS["B"]["X"],
        PARAMETERS["B"]["Y"],
    )

    while True:
        clientsocket, address = serversocket.accept()
        client(
            socket=clientsocket,
            address=address,
            identifier=SERVER_CONSTANTS["IDENTIFIER"],
            parameters=param,
        )


if __name__ == "__main__":
    startSocketServer()
