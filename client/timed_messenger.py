import ctypes


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


messenger = ctypes.CDLL("./libtimedmessenger.so")
messenger.timed_send_and_receive.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
messenger.timed_send_and_receive.restype = TimedResponse


send_and_receive = messenger.timed_send_and_receive
