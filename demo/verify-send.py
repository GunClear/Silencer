#!python
import os
#from ctypes import *
import ctypes

if __name__ == '__main__':
    GTSvkPath = ctypes.create_string_buffer(b'../build/src/GTS.vk.bin')
    GTSwitnessPath = ctypes.create_string_buffer(b'../build/src/GTS.witness.bin')
    GTSproofPath = ctypes.create_string_buffer(b'../build/src/GTS.proof.bin')
    libc = ctypes.cdll.LoadLibrary("../build/src/silencer")

    ret = libc.verify_send_wit(GTSwitnessPath, GTSvkPath, GTSproofPath)

    #Instead of calling verify_send_wit() directly, this will call main() with argument "9"
    # LP_c_char = ctypes.POINTER(ctypes.c_char)
    # LP_LP_c_char = ctypes.POINTER(LP_c_char)
    # libc.main.argtypes = (ctypes.c_int, # argc
    #                         LP_LP_c_char) # argv
    # argc = 2
    # argv = (LP_c_char * (argc + 1))()
    # arg = "/home/sean/Silencer/build/src/silencer"
    # enc_arg = arg.encode('utf-8')
    # argv[0] = ctypes.create_string_buffer(enc_arg)
    # arg = "9"
    # enc_arg = arg.encode('utf-8')
    # argv[1] = ctypes.create_string_buffer(enc_arg)
    # arg = ""
    # enc_arg = arg.encode('utf-8')
    # argv[2] = ctypes.create_string_buffer(enc_arg)
    # ret = libc.main(argc, argv)

    print("verify_send_wit() returned: ", ret)
