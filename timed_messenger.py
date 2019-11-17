from ctypes import *


class TimedResponse(Structure):
    _fields_ = [
        ("start_time", c_ulonglong),
        ("end_time", c_ulonglong),
        ("response_length", c_int),
        ("response", c_byte * 4096),
    ]


messenger = CDLL("./libtimedmessenger.so")
messenger.timed_send_and_receive.argtypes = [c_int, c_char_p, c_uint]
messenger.timed_send_and_receive.restype = TimedResponse


send_and_receive = messenger.timed_send_and_receive
