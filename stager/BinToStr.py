import binascii
  
# 读取二进制文本并显示为16进制
def readBinfile(binFile_path:str):
    str = ""
    print()
    with open(binFile_path, 'rb') as f:
        num = 0
        while 1:
            a = f.read(1)
            if not a:
                break
            hexstr = binascii.b2a_hex(a)
            str += hexstr.decode().upper()
            num += 1
    print(str[::-1])
    str = str[::-1]
    fileName='shell.txt'
    with open(fileName,'w')as file:
        file.write(str)
    

readBinfile('beacon.bin')
