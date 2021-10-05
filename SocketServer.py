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
            id_client = L[1]
            id_client_as_string = id_client.decode("utf-8")

            client_password_as_string = self.retrieve(id_client_as_string)
            client_password = bytes(client_password_as_string, "utf-8")
            hashed_client_password = self.parameters.get_k(client_password)

            beta = random.randint(1, self.parameters.q - 1)

            V1 = self.parameters.G.point_multiplication(beta)
            V2 = self.parameters.B.point_multiplication(hashed_client_password)
            V = V1 + V2

            v_as_bytes = V.to_bytes()
            id_server = bytes(self.identifier, "utf-8")

            L = [v_as_bytes, id_server]

            # encode twice before sending any message.
            array = EncodingHelper.encodeArray(L)
            array = EncodingHelper.encodeArray([array])
            self.send(array)

            U2 = self.parameters.A.point_multiplication(hashed_client_password)

            U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)

            W = (U - U2).point_multiplication(beta)

            wbytes = W.to_bytes()

            keyblob = self.parameters.H(
                client_password, id_client, id_server, ubytes, v_as_bytes, wbytes, 45
            )

            key = keyblob[:32]
            nonce = keyblob[32:]
            mask = int("0xffffffffffffffffffffffffff", base=16)
            nonce_as_int = int.from_bytes(nonce, "big")
            cont = True

            while cont:
                data = self.receive()
                try:
                    nonce = nonce_as_int.to_bytes(13, byteorder="big")
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(data[16:], data[:16])
                    nonce_as_int = (nonce_as_int + 1) & mask
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
