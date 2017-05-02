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

import subprocess
import os
import shlex


class Cmd():
    def __init__(self):
        self.returncode = 0

    def _check_output(self, cmd, chdir=None, catcherror=False, teefile=None):
        cwd = os.getcwd()
        out = ""
        if chdir is not None:
            os.chdir(chdir)
        if catcherror:
            try:
                if teefile:
                    output = []
                    c = ["unbuffer"]+shlex.split(cmd)
                    proc = subprocess.Popen(c, stdout=subprocess.PIPE)
                    if teefile:
                        teefile = open(teefile, "w")
                    for i in iter(proc.stdout.readline, ''):
                        output.append(i)
                        if teefile:
                            teefile.write(i)
                        else:
                            print i[0:-1]
                    self.returncode = proc.returncode
                    out = "".join(output)
                    if teefile:
                        teefile.close()
                else:
                    out = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as e:
                self.returncode = e.returncode
                out = e.output
        else:
            self.returncode = 0
            out = subprocess.check_output(cmd, shell=True)
        if cwd is not None:
            os.chdir(cwd)
        return out

    def run_cmd(self, cmd, pwd=None, catcherror=False):
        return self._check_output(cmd, pwd, catcherror).strip()

    def run_multiline_cmd(self, cmd, pwd=None, catcherror=True, teefile=None):
        return self._check_output(cmd, pwd, catcherror, teefile).split('\n')

    def get_last_cmd_return_value(self):
        return self.returncode
