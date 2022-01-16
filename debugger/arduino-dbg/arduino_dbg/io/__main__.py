# (c) Copyright 2022 Aaron Kimball
#
# Short test program for arduino_dbg.io.

import arduino_dbg.io as io
import os

if __name__ == "__main__":
    (left, right) = io.make_bidi_pipe()

    pid = os.fork()
    if pid == 0:
        # Child
        left.open()
        s = "Major Tom to ground control\n"
        left.write(s.encode("utf-8"))
        ln = left.readline().decode("utf-8")
        print(f'Child received: {ln}')
        left.close()
    else:
        # Parent
        right.open()
        ln2 = right.readline().decode("utf-8")
        print(f'Parent received: {ln2}')
        s2 = "ground control to Major Tom\n"
        right.write(s2.encode("utf-8"))
        right.close()

