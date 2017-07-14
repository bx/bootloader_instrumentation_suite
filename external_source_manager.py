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
            self.build_cfg = cfg
            self.root_dir = self.gf('root')
            if os.path.isdir(os.path.join(self.root_dir, ".git")):
                self.git = git_mgr.GitManager(self.root_dir)
            else:
                self.git = None

    def gf(self, field):
        if not hasattr(self.build_cfg, field):
            return self.defaults[field]
        else:
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
            'verbosity': 2,
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
            cmd = cmd.format(**keywords)
        return cmd


class CodeTaskClean(CodeTask):
    defaults = {'clean': 'make clean'}

    def __init__(self, cfg):
        super(CodeTaskClean, self).__init__('do_clean', cfg)
        self.actions = [(self.save_timestamp,),
                        LongRunning(self.format_command(self.gf("clean")),
                                    cwd=self.root_dir, save_out='cleaned')]
        self.uptodate = [run_once]


class CodeTaskConfig(CodeTask):
    defaults = {'build_prepare': './configure'}

    def __init__(self, cfg):
        super(CodeTaskConfig, self).__init__('config', cfg)
        self.actions = [(self.save_timestamp,),
                        CmdAction(self.format_command(self.gf('build_prepare')),
                                  cwd=self.root_dir, save_out='configured')]
        self.uptodate = [task_ran("clean")]


class CodeTaskBuild(CodeTask):
    defaults = {'build_cmd': 'make'}

    def __init__(self, cfg):
        super(CodeTaskBuild, self).__init__('build', cfg)
        self.uptodate = [task_ran('config')]
        self.targets = self.all_targets()
        self.actions = [CmdAction(self.format_command(self.gf("build_cmd")),
                                  cwd=self.root_dir)]

    def all_targets(self):
        bins = self.gf("binary")
        if isinstance(bins, list):
            return [str(self.path(b)) for b in bins]
        else:
            return [str(self.path(self.gf("binary")))]


class CodeTaskList():
    def __init__(self, cfg, always_uptodate):
        self.build_cfg = cfg
        self.basename = cfg.name
        self.always_uptodate = always_uptodate
        self.root_dir = self.build_cfg.root
        if os.path.isdir(os.path.join(self.root_dir, ".git")):
            self.git = git_mgr.GitManager(self.root_dir)
        else:
            self.git = None

        self.build = CodeTaskBuild(cfg)
        self.tasks = [CodeTaskClean(cfg), CodeTaskConfig(cfg), self.build]

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
            return (None, None)#, None)

    def list_tasks(self):
        yield {
            'basename': self.basename,
            'name': None,
            }
        for task in self.tasks:
            yield task.list_tasks()


class SourceLoader():
    def __init__(self, print_build, do_build):
        # bootloader_only = len(do_build) == 0
        self.print_build = print_build
        self.do_build = do_build
        self.builds = list(set(do_build + print_build))
        ss = Main.config_class_lookup("Software")
        bootloader = Main.get_bootloader_cfg()

        self.code_tasks = [CodeTaskList(s, s.name in self.do_build)
                           for s in ss
                           if hasattr(s, "build_required")
                           and s.build_required
                           and (s.name in self.builds)]
        # always need the bootloader
        if bootloader.software not in self.builds:
            self.code_tasks.extend(CodeTaskList(s,
                                                s.name in self.do_build)
                                   for s in ss if s.name == bootloader.software)
        for c in self.code_tasks:
            if c.basename in self.do_build:
                for t in c.tasks:
                    t.uptodate = [False]

    def list_tasks(self):
        l = []
        for c in self.code_tasks:
            # only if in bulid list
            if c.basename in self.builds:
                name = "task_%s" % c.basename
                tl = c.list_tasks
                l.append((name, tl))
        return l
