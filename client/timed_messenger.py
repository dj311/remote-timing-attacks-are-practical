import ctypes
import os


class TimedResponse(ctypes.Structure):
    """
    Structure of the response from the send_and_receive function. This
    is the ctypes equivelant to s_timed_response in timed_messenger.c
    """

    _fields_ = [
        ("start_time", ctypes.c_ulonglong),
        ("end_time", ctypes.c_ulonglong),
        ("response_length", ctypes.c_int),
        ("response", ctypes.c_byte * 4096),
    ]


C_SOURCE = "./timed_messenger.c"
C_LIBRARY = "./timed_messenger.so"


# To start, check if the C source code is newer than the compiled
# library.  If so, recompile the library before loading it.
try:
    library_exists = os.path.exists(C_LIBRARY)
    library_stale = os.path.getmtime(C_SOURCE) > os.path.getmtime(C_LIBRARY)
except OSError:
    pass
else:
    if not library_exists or library_stale:
        os.system(f"cc -shared -fPIC -o {C_LIBRARY} {C_SOURCE}")


messenger = ctypes.CDLL(C_LIBRARY)
messenger.timed_send_and_receive.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
messenger.timed_send_and_receive.restype = TimedResponse


send_and_receive = messenger.timed_send_and_receive
