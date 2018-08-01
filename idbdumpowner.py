import idaapi
import binascii
print(binascii.hexlify(idaapi.netnode('$ original user', 0, False).supval(0)))
