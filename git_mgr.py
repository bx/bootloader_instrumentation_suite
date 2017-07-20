import pygit2

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


class GitManager():
    def __init__(self, root):
        self.root = root
        self.repo = pygit2.Repository(self.root)

    def get_info(self):
        return {'head': self.get_head(), 'commit': self.get_commit()}

    def commit_changes(self):
        self.repo.index.add_all()
        self.repo.index.write()
        tree = self.repo.index.write_tree()
        author = pygit2.Signature("bx", "bx@cs")
        old = self.repo.create_commit(self.get_head(),
                                      author,
                                      author,
                                      "auto commit for testing",
                                      tree,
                                      [self.repo.head.get_object().hex])

    def has_nothing_to_commit(self):
        status = self.repo.status()
        okstatus = [pygit2.GIT_STATUS_IGNORED, pygit2.GIT_STATUS_CURRENT]
        for (path,flags) in status.iteritems():
            if flags not in okstatus:
                print "need to commit %s, %s" %(path, flags)
                return False
        return True

    def get_section_info(self):
        info = {
            "git-root": self.root,
            "git-head": self.get_head(),
            "git-commit": self.get_commit()
        }
        return info

    def get_head(self):
        return self.repo.head.name

    def get_commit(self):
        return self.repo.head.target.hex
