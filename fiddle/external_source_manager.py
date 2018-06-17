#! /usr/bin/env python
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

from config import Main
from doit.tools import run_once
import sys
import time
import os
import pathlib
from doit.action import CmdAction
from doit.tools import LongRunning
import git_mgr


class task_ran(object):
    def __init__(self, n):
        self.n = n

    def __call__(self, task, values):
        if self.n in values:
            ctime = self.n
            return (time.time() - ctime) > 0
        else:
            return False


class CodeTask(object):
    def task_name(self, basename=None, name=None):
        if basename is None:
            basename = self.basename
        if name is None:
            name = self.name
        return "%s:%s" % (basename, name)

    @classmethod
    def get_task_name(cls, basename, name):
        return cls.task_name(cls(None, None, False), basename, name)

    def __init__(self, name, cfg, init=True):
        if init:
            for a in ['uptodate', 'targets', 'actions']:
                if not hasattr(self, a):
                    setattr(self, a, [])
            self.basename = cfg.name
            self.name = name
            self.file_dep = []
            self.task_dep = []
            self.other = []
            self.build_cfg = cfg
            self.root_dir = self.gf('root')
            if os.path.isdir(os.path.join(self.root_dir, ".git")):
                self.git = git_mgr.GitManager(self.root_dir)
            else:
                self.git = None

    def gf(self, field):
        return getattr(self.build_cfg, field)

    def path(self, rel):
        p = pathlib.Path(self.root_dir) / rel
        return p

    def save_timestamp(self):
        return {'%stime' % self.name: time.time()}

    def list_tasks(self):
        l = {
            'name': self.name,
            'basename': self.basename,
            #'verbosity': 2,
            'uptodate': self.uptodate,
            'targets': self.targets,
            'actions': self.actions,
            }
        return l

    def format_command(self, cmd):
        config_type = self.build_cfg.config_type if hasattr(self.build_cfg, "config_type") else ""
        config_name = self.build_cfg.config_name if hasattr(self.build_cfg, "config_name") else ""
        if config_type and config_name:
            cfg = Main.object_config_lookup(config_type, config_name)
            keywords = Main.__dict__
            keywords.update(cfg.__dict__)
            # filter out keys that begin with _Main_ which are a result of use of the @property decorator
            keywords = {k.replace("_Main__", ""): v for (k, v) in keywords.iteritems()}
            cmd = cmd.format(**keywords)
        return cmd


class CodeTaskClean(CodeTask):
    #defaults = {'clean': 'make clean'}

    def __init__(self, cfg):
        super(CodeTaskClean, self).__init__('do_clean', cfg)
        #(self.save_timestamp,),
        self.actions = [
                        CmdAction(self.format_command(self.gf("clean")),
                                    cwd=self.root_dir)]
        self.uptodate = [True]


class CodeTaskConfig(CodeTask):
    #defaults = {'build_prepare': './configure'}

    def __init__(self, cfg):
        super(CodeTaskConfig, self).__init__('config', cfg)
        #(self.save_timestamp,),
        self.actions = [
                        CmdAction(self.format_command(self.gf('build_prepare')),
                                  cwd=self.root_dir)]
        #self.uptodate = [not task_ran("clean")]


class CodeTaskBuild(CodeTask):
    #defaults = {'build_cmd': 'make'}
    #defaults.update(CodeTaskClean.defaults)
    #defaults.update(CodeTaskConfig.defaults)
    def __init__(self, cfg, printonly=False):
        super(CodeTaskBuild, self).__init__('build', cfg)
        if not printonly:
            c = ""
            for i in ['clean', 'build_prepare', 'build_cmd']:
                l = self.gf(i)
                if l:
                    c += "%s; " % l            
        else:
            c = self.gf("build_cmd")
        #self.uptodate = [task_ran('config')]
        self.targets = self.all_targets()
        self.actions = [CmdAction(self.format_command(c),
                                  cwd=self.root_dir)]

    def all_targets(self):
        files = self.gf("_files")
        paths = []
        for (k, v) in files.iteritems():
            if v.type == "target":
                path = v.relative_path
                root = getattr(v, "root_path", v.software.root)
                paths.append(os.path.join(root, path))

        return paths



class CodeTaskList():
    def __init__(self, cfg, always_uptodate=False, printonly=False):
        self.build_cfg = cfg
        self.basename = cfg.name
        self.always_uptodate = always_uptodate
        self.root_dir = self.build_cfg.root
        if os.path.isdir(os.path.join(self.root_dir, ".git")):
            self.git = git_mgr.GitManager(self.root_dir)
        else:
            self.git = None
        self.build = CodeTaskBuild(cfg, printonly=printonly)
        if printonly:
            self.clean = CodeTaskClean(cfg)
            self.config = CodeTaskConfig(cfg)
            self.tasks = [self.clean, self.config, self.build]
        else:
            self.config = CodeTaskBuild(cfg, printonly=printonly)
            self.tasks = [self.build]

        if always_uptodate:
            for t in self.tasks:
                t.uptodate = [True]

    def has_nothing_to_commit(self):
        return self.git.has_nothing_to_commit() if self.git else True

    def commit_changes(self):
        if self.git:
            self.git.commit_changes()

    def get_gitinfo(self):
        if self.git:
            head = self.git.get_head()
            head = head.translate(None, "/")
            sha = self.git.get_commit()
            gitinfo = "%s.%s" % (head, sha)
            return (gitinfo, sha)
        else:
            return (None, None)  #, None)

    def list_tasks(self):
        yield {
            'basename': self.basename,
            'name': None,
            }
        for task in self.tasks:
            yield task.list_tasks()


class SourceLoader():
    def __init__(self, build, print_only=False):
        self.init_only = True if not build else False
        self.builds = build
        ss = Main.config_class_lookup("Software")
        target_software = Main.target_software

        self.code_tasks = [CodeTaskList(s, s.name not in self.builds, print_only)
                           for s in ss
                           if (s.name in self.builds)]

        ## always need the target
        if target_software.name not in self.builds:
            self.code_tasks.append(CodeTaskList(Main.target_software, False))
        #if self.init_only:
        #    for c in self.code_tasks:
        #        for t in c.tasks:
        #            t.uptodate = [True]
#        else:
#            for c in self.code_tasks:
#                if c.basename in self.builds:
#                    for t in c.tasks:
#                        t.uptodate = [False]

    def list_tasks(self):
        #l = []
        for c in self.code_tasks:
            # only if in bulid list
            if c.basename in self.builds:
                name = "task_%s" % c.basename
                tl = c.list_tasks
                yield (name, tl)
                #l.append((name, tl))
        #return l
