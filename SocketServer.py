import json, os, random, socket, threading, traceback
from Crypto.Cipher import AES
from ECPoint import ECPoint
from FP import FP
from Parameters import Parameters
from EncondingHelper import EncodingHelper
from Constants import (
    DATABASE,
    OPERATIONS,
    PARAMETERS,
    SERVER_CONSTANTS,
    SOCKET_CONSTANTS,
)


class client(threading.Thread):
    def __init__(self, socket, address, identifier, parameters):
        threading.Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier = identifier
        self.parameters = parameters
        self.client_identifier = None
        self.key = None
        self.nonce = None
        self.start()

    def retrieve(self, ID):
        if ID in DATABASE.keys():
            return DATABASE[ID]
        else:
            raise ValueError("Error con id")

    def run(self):
        try:
            continue_listening = True
            while continue_listening:
                payload = self.receiveEnc()
                changeMode = self.processPayload(payload)
                if changeMode:
                    continue_listening = False

            mask = int("0xffffffffffffffffffffff", base=16)
            nonce_as_int = int.from_bytes(self.nonce, "big")
            cont = True

            while cont:
                data = self.receive()
                try:
                    nonce = nonce_as_int.to_bytes(12, byteorder="big")
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(data[16:], data[:16])
                    nonce_as_int = (nonce_as_int + 1) & mask
                    print(plaintext.decode("utf-8"))
                    if plaintext == "exit":
                        cont = False
                except:
                    raise RuntimeError("Encryption Error")
            self.sock.close()
        except Exception as E:
            print("Coms error")
            print(E)
            self.sock.close()

    def processPayload(self, payload):
        if len(payload) == 0:
            print("Empty payload received")
            return

        operation = payload[0].decode("utf-8")

        if len(payload) > 0 and operation == OPERATIONS["PRE_REGISTER"]:
            self.preRegister(payload)
            return False
        elif len(payload) > 0 and operation == OPERATIONS["EXCHANGE"]:
            self.serverClientExchangeKeys(payload)
            return True
        else:
            return False

    def preRegister(self, payload):
        [_operation, id_client_enc, pi0_enc, C_enc] = payload
        id_client = id_client_enc.decode("utf-8")
        pi0 = int.from_bytes(pi0_enc, "big")

        operation = OPERATIONS["SERVER_RESPONSE"]
        parsed = f"{operation}:{id_client}"
        C = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, C_enc)
        print(C)

        try:
            self.saveToDB(id_client, pi0, C)

            message = [bytes(parsed, "utf-8"), b"Success"]

        except Exception as E:
            print(E)
            message = [bytes(parsed, "utf-8"), b"Error"]

        finally:
            self.sendEnc(message)

    def saveToDB(self, id_client, pi0, C):
        directoryExists = os.path.exists("./.server")
        if not directoryExists:
            os.mkdir("./.server")

        configExists = os.path.exists("./.server/config.json")
        if configExists:
            DB = []
            with open("./.server/config.json", "r") as jsonDB:
                content = jsonDB.read()
                DB = json.loads(content)

            result = next(
                (i for i, item in enumerate(DB) if item["identifier"] == id_client),
                None,
            )
            DB[result]["pi0"] = pi0
            DB[result]["c"] = {
                "x": C.x.rep,
                "y": C.y.rep,
            }

            with open("./.server/config.json", "w") as jsonDB:
                json.dump(DB, jsonDB, indent=4)

        else:
            row = {
                "identifier": id_client,
                "pi0": pi0,
                "c": {
                    "x": C.x.rep,
                    "y": C.y.rep,
                },
            }
            with open("./.server/config.json", "w") as jsonDB:
                json.dump([row], jsonDB, indent=4)

    def serverClientExchangeKeys(self, payload):
        try:
            [_operation, u_as_bytes, id_client_enc] = payload

            id_client = id_client_enc.decode("utf-8")

            U = ECPoint.point_from_bytes(
                self.parameters.a, self.parameters.b, u_as_bytes
            )
            isUValid = self.parameters.isECPointValid(U)
            if not isUValid:
                print("ECPoint was not valid")
                return

            pi0, C = self.searchDB(id_client)
            beta = random.randint(1, self.parameters.q - 1)
            V1 = self.parameters.G.point_multiplication(beta)
            V2 = self.parameters.B.point_multiplication(pi0)
            V = V1 + V2

            W = (U - self.parameters.A.point_multiplication(pi0)).point_multiplication(
                beta
            )
            d = C.point_multiplication(beta)

            parsed = f'{OPERATIONS["SERVER_RESPONSE"]}:{id_client}'
            v_as_bytes = V.to_bytes()
            message = [
                bytes(parsed, "utf-8"),
                V.to_bytes(),
                bytes(self.identifier, "utf-8"),
            ]

            self.sendEnc(message)

            W_as_bytes = W.to_bytes()
            d_as_bytes = d.to_bytes()

            k = self.parameters.Hk(
                1,
                [
                    pi0.to_bytes(32, byteorder="big"),
                    u_as_bytes,
                    v_as_bytes,
                    W_as_bytes,
                    d_as_bytes,
                ],
            )

            t_2a = self.parameters.Hk(2, [k])
            t_2b = self.parameters.Hk(3, [k])

            [t_1b] = self.receiveEnc()
            self.sendEnc([t_2a])

            if t_1b != t_2b:
                print("T_1b validation failed")
                return

            keyblob = self.parameters.Hk(4, [k], n=44)
            key = keyblob[:32]
            nonce = keyblob[32:]

            self.client_identifier = id_client
            self.key = key
            self.nonce = nonce

            print(f"[Info] Se ha establecido una conexion con {id_client}")

        except Exception as E:
            print(E)
            print(traceback.format_exc())

    def searchDB(self, id_client):
        DB = []
        with open("./.server/config.json", "r") as jsonDB:
            content = jsonDB.read()
            DB = json.loads(content)

        index = next(
            (i for i, item in enumerate(DB) if item["identifier"] == id_client),
            None,
        )

        Cx = FP(DB[index]["c"]["x"], self.parameters.p)
        Cy = FP(DB[index]["c"]["y"], self.parameters.p)

        C = ECPoint(
            self.parameters.a,
            self.parameters.b,
            Cx,
            Cy,
        )

        return DB[index]["pi0"], C

    def run2(self):
        try:
            response = self.receive()

            payload = EncodingHelper.decodeArray(response)

            u_as_bytes = payload[0]
            id_client = payload[1]
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

            payload = [v_as_bytes, id_server]

            # encode twice before sending any message.
            array = EncodingHelper.encodeArray(payload)
            array = EncodingHelper.encodeArray([array])
            self.send(array)

            U2 = self.parameters.A.point_multiplication(hashed_client_password)

            U = ECPoint.point_from_bytes(
                self.parameters.a, self.parameters.b, u_as_bytes
            )

            W = (U - U2).point_multiplication(beta)

            wbytes = W.to_bytes()

            keyblob = self.parameters.H(
                client_password,
                id_client,
                id_server,
                u_as_bytes,
                v_as_bytes,
                wbytes,
                45,
            )

            key = keyblob[:32]
            nonce = keyblob[32:]
            mask = int("0xffffffffffffffffffffff", base=16)
            nonce_as_int = int.from_bytes(nonce, "big")
            cont = True

            while cont:
                data = self.receive()
                try:
                    nonce = nonce_as_int.to_bytes(12, byteorder="big")
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

    def sendEnc(self, msg):
        array = EncodingHelper.encodeArray(msg)
        array = EncodingHelper.encodeArray([array])
        self.send(array)

    def receiveEnc(self):
        response = self.receive()
        payload = EncodingHelper.decodeArray(response)
        return payload


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
        print(f"New Connection @ {address}")
        client(
            socket=clientsocket,
            address=address,
            identifier=SERVER_CONSTANTS["IDENTIFIER"],
            parameters=param,
        )


if __name__ == "__main__":
    startSocketServer()
