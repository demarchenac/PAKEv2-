class EncodingHelper():
    @staticmethod
    def encodeArray(arrays):    
        L = []
        for array in arrays:
            lt = len(array)
            asBytes = lt.to_bytes(4, byteorder='big') 
            L.append(asBytes +array)
    
        return b''.join(L)
    
    @staticmethod
    def decodeArray(barr):       
        L = []
        i = 0
        while i < len(barr):
            n = int.from_bytes(barr[i:i+4], byteorder='big')
            L.append(barr[i+4:i+4+n])
            i= i +4 +n
        return L