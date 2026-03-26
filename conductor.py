import serial
import hot

ser = serial.Serial("COM3", 115200, timeout=1)

nonce = None
nonce2 = None
distances = []
counter = 0
medianDistance = 0
nonceParity = []

while True:
    data = ser.read_until(expected=b"\r\n")
    if (data.startswith(b'NONCE')):
        a = data.find(b"\r")
        if a != -1:
            nonce = data[6:a]
        ser.write(b"\x01")
    elif (data.startswith(b"STATE")):
        a = data.find(b"\r")
        if a != -1:
            tagPrngState = data[5:a]
        ser.write(b"\x01")
    elif (data.startswith(b"DISTANCE")):
        a = data.find(b"\r")
        if a != -1:
            distances.append(hot.nonce_distancer(int(tagPrngState), int(nonce)))
        ser.write(b"\x01")
        

    elif (data.startswith(b"MEDIAN")):
        distances.sort()
        #len is 15, 15/2 = 7 in C++

        medianDistance = distances[7]   
        distances = [0] * 15
        ser.write(b"\x01")

    elif (data.startswith(b"Nt")):
        a = data.find(b"\r")
        if a != -1:
            Nt = data[2:a]
        ser.write(b"\x01")
        
    elif (data.startswith(b"encNt")):
        a = data.find(b"\r")
        if a != -1:
            encNt = data[5:a]
        ser.write(b"\x01")

    elif (data.startswith(b"StateNt")):
        a = data.find(b"\r")
        if a != -1:
            tagPrngState = data[7:a]
        ser.write(b"\x01")

    elif (data.startswith(b"nonceParity")):
        a = data.find(b"\r")
        if a != -1:
            nonceParity = data[11:a]
            nonceParity = list(str(nonceParity))
            nonceParity = nonceParity[2:-1]
            for x in range(len(nonceParity)):
                nonceParity[x] = int(nonceParity[x])

            
        ser.write(b"\x01")
    elif (data.startswith(b"UID")):
        a = data.find(b"\r")
        if a != -1:
            UID = data[3:a]
        ser.write(b"\x01")
    elif (data.startswith(b"ntF")):
        a = data.find(b"\r")
        if a != -1:
            ntF = data[3:a]
        ser.write(b"\x01")

    elif (data.startswith(b"CALC")):
        if (Nt and tagPrngState and encNt and nonceParity and UID and medianDistance):
            hot.generatePossibleKeys(int(tagPrngState), int(encNt), int(medianDistance), int(UID), bytes(nonceParity))
            ser.write(b"\x01")
        else:
            print("everything not here?")
            ser.write(b"\x02")
    elif (data.startswith(b"FIND")):
        # print("key?------------------------------------------")
        ret = hot.findKey()
        retBytes = ret.to_bytes(6, byteorder='big')
        ser.write(retBytes)



    elif (data.startswith(b"CLEANUP")):
        nonce = None
        nonce2 = None
        distances.clear()
        counter = 0
        medianDistance = 0
        Nt = 0
        encNt = 0
        UID = 0
        nonceParity.clear()
        print(".")
    else:
        if data:
            print("DBG")
            print(data)