from struct import pack, calcsize

def bof_pack(fstring: str, args: list):
    # Most code taken from: https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
    # Emulates the native Cobalt Strike bof_pack() function.
    # Documented here: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
    #
    # Type 	Description 				Unpack With (C)
    # --------|---------------------------------------|------------------------------
    # b       | binary data 			      |	BeaconDataExtract
    # i       | 4-byte integer 			      |	BeaconDataInt
    # s       | 2-byte short integer 		      |	BeaconDataShort
    # z       | zero-terminated+encoded string 	      |	BeaconDataExtract
    # Z       | zero-terminated wide-char string      |	(wchar_t *)BeaconDataExtract
    buffer = b""
    size = 0
   
    def addshort(short):
        nonlocal buffer
        nonlocal size
        buffer += pack("<h", int(short))
        size += 2

    def addint(dint):
        nonlocal buffer
        nonlocal size
        buffer += pack("<i", int(dint))
        size += 4

    def addstr(s):
        nonlocal buffer
        nonlocal size
        if(isinstance(s, str)):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        buffer += pack(fmt, len(s)+1, s)
        size += calcsize(fmt)

    def addWstr(s):
        nonlocal buffer
        nonlocal size
        if(isinstance(s, str)):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        buffer += pack(fmt, len(s)+2, s)
        size += calcsize(fmt)

    def addbinary(b):
        # Add binary data to the buffer (don't know if this works)
        nonlocal buffer
        nonlocal size
        fmt = "<L{}s".format(len(b) + 1)
        buffer += pack(fmt, len(b)+1, b)
        size += calcsize(fmt)

    if(len(fstring) != len(args)):
        raise Exception(f"Format string length must be the same as argument length: fstring:{len(fstring)}, args:{len(args)}")

    bad_char_exception = "Invalid character in format string: "
    # pack each arg into the buffer
    for i,c in enumerate(fstring):
        if(c == "b"):
            with open(args[i], "rb") as fd:
                addbinary(fd.read())
        elif(c == "c"):
            addbinary(args[i])
        elif(c == "i"):
            addint(args[i])
        elif(c == "s"):
            addshort(args[i])
        elif(c == "z"):
            addstr(args[i])
        elif(c == "Z"):
            addWstr(args[i])
        else:
            raise Exception(f"{bad_char_exception}{fstring}\n{(len(bad_char_exception) + i)*' '}^")
    
    # Pack up the buffer size into the buffer itself
    return pack("<L", size) + buffer

if __name__ == "__main__":
   # Interactive method to use bof_pack()
   import sys
   from binascii import hexlify
   from base64 import b64encode

   if(len(sys.argv) < 3 or "-h" in sys.argv or "--help" in sys.argv):
       print("bof_pack: pack arguments in a format suitable to send to a beacon-object-file")
       print("Usage: bof_pack.py <format_string> <arg1> [arg2] [arg3] [...]")
       print("The format string must only include the following characters: b, i, s, z, Z")
   else:
       try:
           packed = bof_pack(fstring=sys.argv[1], args=sys.argv[2:])
           print(" ".join(sys.argv[2:]) + " (\"" + sys.argv[1] + "\")")
           print("-hex-> " + hexlify(packed).decode('utf-8'))
           print("-b64-> " + b64encode(packed).decode('utf-8'))
       except Exception as e:
           print("Exception occured packing your data:")
           print(e)



