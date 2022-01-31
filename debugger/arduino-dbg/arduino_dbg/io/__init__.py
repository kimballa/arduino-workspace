# (c) Copyright 2022 Aaron Kimball

"""
Classes to interact with serial connections or virtual connections to a locally-mounted service.
We wrap enough of the serial.Serial interface for the Debugger's needs, and also support
a version that operates on two internal pipes for intra-process "serial" connection to the
HostedDumpDebugger service.
"""

import fcntl
import os
import serial
import time


class DebugConn(object):
    """
    Abstract interface for a bi-directional communication channel (e.g., a serial port).

    Implementations include a wrapper around PySerial, and a wrapper around a pair of OS pipes
    used for inter-thread communication or IPC.
    """
    def __init__(self):
        pass

    def max_retries(self):
        """ Return the max number of times we should attempt to retry this connection. """
        # No particular limit
        return None

    def open(self, *args, **kwargs):
        raise Exception("Unimplemented")

    def reopen(self, *args, **kwargs):
        raise Exception("Unimplemented")

    def close(self):
        raise Exception("Unimplemented")

    def readline(self, *args, **kwargs):
        raise Exception("Unimplemented")

    def write(self, *args, **kwargs):
        raise Exception("Unimplemented")

    def is_open(self):
        raise Exception("Unimplemented")

    def available(self):
        raise Exception("Unimplemented")

    def __repr__(self):
        return "DebugConn (base)"


class SerialConn(DebugConn):
    """
    Connection to debugged instance over a serial port
    """

    def __init__(self, port, baud, timeout):
        DebugConn.__init__(self)
        self._conn = None
        self.port = None
        self.baud = None
        self.timeout = None
        self.reopen(port, baud, timeout)

    def reopen(self, port=None, baud=None, timeout=None):
        """
          (Re)establish serial connection.
        """

        if port is not None:
            self.port = port
        if baud is not None:
            self.baud = baud
        if timeout is not None:
            self.timeout = timeout

        if self._conn is not None:
            self.close()

        if self.port is not None and self.port != '':
            self._conn = serial.Serial(self.port, self.baud, timeout=self.timeout)

    def open(self):
        self.reopen()

    def is_open(self):
        return self._conn is not None and self._conn.is_open

    def available(self):
        return self._conn.in_waiting

    def write(self, *args, **kwargs):
        return self._conn.write(*args, **kwargs)

    def readline(self, *args, **kwargs):
        return self._conn.readline(*args, **kwargs)

    def close(self):
        if self._conn:
            self._conn.close()
        self._conn = None

    def __repr__(self):
        return f'SerialDebugConn(port={self.port}, baud={self.baud}, timeout={self.timeout})'


class LocalBidiPipeConn(DebugConn):
    """
    Given handles to opposite ends of two open pipes, enable bidirectional conversation with
    another paired LocalBidiPipeConn.
    """

    def __init__(self, read_fd, write_fd, timeout):
        DebugConn.__init__(self)
        self._read_fd = read_fd
        self._write_fd = write_fd
        self.timeout = timeout

        fcntl.fcntl(self._read_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(self._write_fd, fcntl.F_SETFL, os.O_SYNC)

        self._is_open = True
        self._buf = bytearray()
        self._n_buffered = 0

    def max_retries(self):
        # This connection cannot be retried.
        return 0

    def open(self, *args, **kwargs):
        # The pipes start already-open.
        pass

    def reopen(self):
        raise OSError("Cannot re-open pipe once closed.")

    def close(self):
        if not self._is_open:
            return

        os.close(self._read_fd)
        os.close(self._write_fd)

        self._read_fd = None
        self._write_fd = None

        self._is_open = False

    def readline(self, *args, **kwargs):
        out = bytearray()

        # Start by draining our buffer.
        while self._n_buffered:
            c = self._buf[0]

            out.append(c)
            del self._buf[0]  # This can be O(n^2) but we don't actually buffer very far.
            self._n_buffered -= 1

            if c == ord('\n'):
                # We hit the end.
                return bytes(out)

        sleep_start = None
        while True:
            try:
                newbytes = os.read(self._read_fd, 1)
                if len(newbytes) == 0:
                    return bytes(out)  # EOF condition -- we're done.
            except BlockingIOError:
                # Got nothing from nonblocking read.
                if sleep_start is not None:
                    # Not our first attempt at this.
                    if time.time() - sleep_start > self.timeout:
                        # We hit the limit; return whatever we've got.
                        return bytes(out)
                else:
                    # This is the first such time point. Mark when we started.
                    sleep_start = time.time()
                time.sleep(0.025)  # Wait 25ms and try again.
                continue

            sleep_start = None  # We got a byte; reset timeout.
            c = newbytes[0]
            out.append(c)
            if c == ord('\n'):
                break  # Done!

        return bytes(out)


    def write(self, byteseq):
        return os.write(self._write_fd, byteseq)

    def is_open(self):
        return self._is_open

    def available(self):
        if not self._is_open:
            return False
        elif self._n_buffered > 0:
            # Got something in the buffer already, so yes data is available.
            return True
        else:
            # Determine if data is available by doing a non-blocking read.
            # Keep the data in our internal buffer.
            try:
                newbytes = os.read(self._read_fd, 1)
                if len(newbytes) == 0:
                    # Hit EOF
                    return False

                for b in newbytes:
                    self._buf.append(b)
                    self._n_buffered += 1
                return self._n_buffered > 0
            except BlockingIOError:
                # Didn't get anything back from read().
                return False


    def __repr__(self):
        return f"LocalBidiConn(r_fd={self._read_fd}, w_fd={self._write_fd})"


def make_bidi_pipe():
    """
    Make a bidirectional communication pipe and return a pair of LocalBidiPipeConn instances
    that can talk to one another.
    """
    (r1, w1) = os.pipe()
    (r2, w2) = os.pipe()
    timeout = 0.1

    left = LocalBidiPipeConn(r1, w2, timeout)
    right = LocalBidiPipeConn(r2, w1, timeout)

    return (left, right)

