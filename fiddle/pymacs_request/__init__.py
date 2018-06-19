# MIT License

# Copyright (c) 2017 Rebecca ".bx" Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import unicode_literals
import os, atexit, time, signal, subprocess

name = "emacs_python_pipe"

class Emacs():
    # Requests towards Emacs are written to file "_request", while
    # replies from Emacs are read from file "_reply".  We call Emacs
    # attention by erasing "_reply", and Emacs calls our attention by
    # erasing "_request".  These rules guarantee that no file is ever
    # read by one side before it has been fully written by the other.
    # Busy waiting, with built-in delays, is used on both sides.

    popen = None

    def __init__(self):
        self.comm_dir = os.getcwd()
        self.reply_file = os.path.join(self.comm_dir, "_reply")
        self.req_file = os.path.join(self.comm_dir, "_request")
        self.cleanup()
        atexit.register(self.cleanup)
        emacs = '/usr/bin/emacsclient'
        self.command = (emacs, "-s", "default")
        self.command = self.command + ('--eval', '(pymacs-run-one-request "%s")' % self.comm_dir)

    def cleanup(self):
        if self.popen is not None:
            self.popen.poll()
            if self.popen.returncode is None:
                os.kill(self.popen.pid, signal.SIGINT)
                os.waitpid(self.popen.pid, 0)
            self.popen = None
        if os.path.exists(self.req_file):
            os.remove(self.req_file)
        if os.path.exists(self.reply_file):
            os.remove(self.reply_file)

    def receive(self):
        while os.path.exists(self.req_file):
            self.popen.poll()
            assert (self.popen.returncode is None) or (self.popen.returncode == 0), self.popen.returncode
            time.sleep(0.005)

            self.popen.poll()
        assert (self.popen.returncode is None) or (self.popen.returncode == 0), self.popen.returncode
        handle = open(self.reply_file)
        buffer = handle.read()
        handle.close()
        return unicode(buffer)

    def send(self, text):
        handle = open(self.req_file, 'w')
        handle.write(text.encode('ascii', 'ignore'))
        handle.close()
        if os.path.exists(self.reply_file):
            os.remove(self.reply_file)
        if self.popen is None:
            self.popen = subprocess.Popen(self.command, stdout=open("/dev/null", "w"))
        self.popen.poll()
        assert self.popen.returncode is None, self.popen.returncode


def ask_emacs(text, printer="prin1", execbuffer=""):
    Emacs.services = Emacs()
    if printer is not None:
        text = '(%s %s)' % (printer, text)
    Emacs.services.send(text)
    repl = Emacs.services.receive()
    Emacs.services.cleanup()
    return repl


def get_emacs_var(name):
    res = ask_emacs(name)[1: -1]  # strip off quotation marks
    if res == "nil":
        return None
    else:
        return res


def ask_emacs_in_buffer(cmd, bufname):
    return ask_emacs('(with-current-buffer (get-buffer-create %s) %s)'
                     % (bufname, cmd))
