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
import config
from config import Main
from doit import loader
from doit.task import dict_to_task
from doit.task import DelayedLoader
from doit.task import Task
from doit.tools import run_once
from doit.cmd_base import TaskLoader
from doit.action import PythonAction
from datetime import datetime
import sys
import traceback
import time
try:
    import IPython
except ImportError:
    class NoIPython:
        def embed():
            print "IPython is not installed, embedded console is not supported"
    IPython = NoIPython()
import os
import re
import atexit
import glob
import importlib
import difflib
from doit.action import CmdAction
from doit import create_after
from doit.tools import LongRunning, Interactive, PythonInteractiveAction
import inspect
import string
import pure_utils
import external_source_manager
from doit.tools import create_folder
import tempfile
import parse_am37x_register_tables
import addr_space
import staticanalysis
import labeltool
import traceback
import substage
import yaml
import db_info
from doit import exceptions


class DelTargetAction(PythonInteractiveAction):

    def execute(self, out, err):
        ret = super(DelTargetAction, self).execute(sys.stdout, err)
        if isinstance(ret, exceptions.CatchedException) or isinstance(ret, Exception):
            if self.task:
                for f in self.task.targets:
                    cmd = "rm -rf %s" % f
                    os.system(cmd)
        return ret


_manager_singleton = None


def task_manager(instance_id=None, verbose=False):
    class TestTaskManager(object):
        def __init__(self, instance_id):
            self.ALL_GROUPS = 0
            self.instance_id = instance_id
            self.tasks = {}
            self.enabled = [self.ALL_GROUPS]
            self.taskmanagers = {}
            self.grouporder = []
            self.verbose = verbose

        def enable(self, subgroup):
            self.enabled.append(subgroup)

        def add_mgr(self, mgr):
            self.taskmanagers[mgr.subgroup] = mgr

        def add_tasks(self, task_list, subgroup):
            l = self.tasks.get(subgroup, [])
            l.extend(task_list)
            for t in task_list:
                if not self.verbose:
                    #print dir(t)
                    t.verbosity = 0
            self.tasks[subgroup] = l

        def list_tasks(self):
            class List():
                def __init__(self, obj, subgroup):
                    self.obj = obj
                    self.subgroup = subgroup

                def list_tasks(self):
                    return self.obj._list_tasks(self.subgroup)
            ts = []
            for k in self.grouporder:
                ts.append(("task_%s_subgroup" % self.build_name(k),
                           List(self, k).list_tasks))
            ts.append(("task_%s_subgroup_all_" % self.build_name(),
                       List(self, self.ALL_GROUPS).list_tasks))
            return ts

        def _list_tasks(self, subgroup):
            if subgroup == self.ALL_GROUPS:
                vallists = [self.tasks[t] for t in self.grouporder]
                alldeps = []
                allfiles = []
                for subgroup in self.grouporder:
                    tasks = self.tasks[subgroup]
                    subfiles = []
                    if subgroup in self.enabled:
                        for t in tasks:
                            #print "%s enable %s------%s--" % (subgroup, t.name, t.file_dep)
                            subfiles.extend(t.file_dep)
                            alldeps.append(self.build_name(subgroup))
                            allfiles.extend(t.file_dep)
                    yield {
                        'basename': subgroup,
                        'name': None,
                        'file_dep': subfiles,
                    }
                yield {
                    'basename': "ALL_GROUPS",
                    'name': None,
                    'task_dep': self.grouporder,
                }

            else:
                for inst in self.tasks[subgroup]:
                    # print "file dep %s <- %s" % (inst.targets, inst.file_dep)
                    r = {
                        'actions': inst.actions,
                        'targets': inst.targets,
                        'file_dep': inst.file_dep,
                        'task_dep': inst.task_dep
                    }
                    r['basename'] = inst.name
                    r['name'] = self.build_name(subgroup)
                    r.update(inst.other)
                    if subgroup not in self.enabled:
                        del r['targets']
                        del r['actions']
                        del r['file_dep']
                        del r['task_dep']
                    else:
                        #print "enable :--:%s %s -> %s" % (self.task_name(inst,
                        #                                                   subgroup),
                        #                                  r['file_dep'], r['targets'])
                        yield r

        def task_name(self, task, subgroup):
            return "%s:%s" % (task.name, self.build_name(subgroup))

        def build_name(self, subgroup=""):
            if not subgroup:
                return self.instance_id
            else:
                return "%s:%s" % (subgroup, self.instance_id)

    global _manager_singleton
    if not _manager_singleton:
        if instance_id is None:
            raise Exception("instance_id must be defined")
        _manager_singleton = TestTaskManager(instance_id)
    return _manager_singleton


class TestTask(object):
    names = set()

    @classmethod
    def exists(cls, d):
        return d in cls.names

    def __init__(self, name, unique=False):
        if unique:
            self.name = name
        else:
            self.name = "%s_%s" % (name, self.__class__.__name__)
        if not self.exists(self.name):
            self.names.add(self.name)
        else:
            raise Exception("Task of name %s exists" % self.name)

        for i in ["actions", "targets", "file_dep", "other", "task_dep"]:
            if not hasattr(self, i):
                default = {} if i == 'other' else []
                listname = "list_%s" % i
                if i is not "other":
                    val = getattr(self, listname)() if hasattr(self, listname) else default
                else:
                    val = getattr(self, listname)() if hasattr(self, listname) else default
                setattr(self, i, val)




class CopyFileTask(TestTask):
    dsts = set()

    @classmethod
    def exists(cls, d):
        return d in cls.dsts

    
    def __init__(self, src, dst):
        super(CopyFileTask, self).__init__("%s->%s" % (src, dst), True)
        self.src = src
        self.dst = dst
        self.actions = ["cp -f %s %s" % (self.src, self.dst)]
        if self.dst in MkdirTask.dirs or os.path.isdir(self.dst):
            target = os.path.join(self.dst, os.path.basename(self.src))
        else:
            target = self.dst
        self.targets = [target]
        self.file_dep =[self.src]
        if self.exists(target):
            raise Exception("Duplicate file copy target %s" % target)
        self.dsts.add(target)


class MkdirTask(TestTask):
    dirs = set()

    @classmethod
    def exists(cls, d):
        return d in cls.dirs

    def __init__(self, d):
        super(MkdirTask, self).__init__(d, True)
        self.dst = d
        self.actions = [(create_folder, [self.dst])]
        if self.dst in MkdirTask.dirs:
            raise Exception("Duplicate of mkdir directory %s" % self.dst)
        MkdirTask.dirs.add(self.dst)
        self.targets = [self.dst]

        
class CmdTask(TestTask):
    def __init__(self, cmds, file_deps, tgts, name):
        super(CmdTask, self).__init__(name)
        self.fdeps = file_deps
        self.targets = tgts
        self.actions = cmds
        self.file_dep = self.fdeps

class LazyCmdTask(TestTask):
    def __init__(self, cmds, file_deps, tgts, name):
        self.fdeps = file_deps
        self.targets = tgts
        self._actions = cmds
        self._file_dep = self.fdeps

        super(LazyCmdTask, self).__init__(name)        

    @property
    def actions(self):
        act = [Main.populate_from_config(c) for c in self._actions]
        return act

    @actions.setter
    def actions(self, a):
        pass

    @property
    def file_dep(self):
        return [Main.populate_from_config(c) for c in self._file_dep]        

    @file_dep.setter
    def file_dep(self, f):
        pass


class DelTargetActionTask(TestTask):
    def __init__(self, fn, file_dep, tgts, name):
        super(DelTargetActionTask, self).__init__(name)
        self.targets = tgts
        self.file_dep = file_dep

        self.del_fn = deltargets
        self.actions = [DelTargetAction(fn)]


class ActionListTask(TestTask):
    def __init__(self, actions, file_deps, tgts, name):
        super(ActionListTask, self).__init__(name)
        self.fdeps = file_deps
        self.targets = tgts
        self.actions = actions
        self.file_dep = self.fdeps

    def __repr__(self):
        return "Actions %s" % self.actions


class ResultsLoader(object):
    def __init__(self, instance_id, subgroup, run_task=True):
        self.instance_id = instance_id
        self.subgroup = subgroup
        self.task_adders = []
        self.task_manager = task_manager(instance_id)
        self.task_manager.grouporder.append(self.subgroup)
        self.run_task = run_task
        if self.run_task:
            self.enable()

    def noop(self, soft, i, dstdir, deps):
        return []

    def import_files(self, obj, rawobj, dstdir, mmap=False, host=False, stage=False):        
        tasks = [] if MkdirTask.exists(dstdir) else [self._mkdir(dstdir)]
        if not hasattr(rawobj, "Files"):
            return []
        raw_files = rawobj.Files
        if stage:
            Main.raw.runtime.current_stage = stage.stagename
        else:
            Main.raw.runtime.current_stage = ""
        if host:
            Main.raw.runtime.current_host = host.name
        else:
            Main.raw.runtime.current_host = ""
        for (f, v) in obj._files.iteritems():
            file_raw = getattr(raw_files, f)
            process_file = file_raw.type == "mmap" if mmap else file_raw.type in ["config", "target"]
            if process_file and not v.imported:
                v.imported = True
                if not file_raw.generate:
                    p = Main.populate_from_config(file_raw.path)
                    base = os.path.basename(p)
                    dst = os.path.join(dstdir, base)                    
                    if file_raw.cache:
                        tasks.append(self._copy_file(p,
                                                     dst))
                        v.path = dst
                        file_raw.path = dst
                    else:
                        v.path = p
                        file_raw.path = p

                else:
                    basename = os.path.basename(file_raw.relative_path)
                    target_location = os.path.join(dstdir, basename)
                    rawobj.path = target_location
                    v.path = target_location
                    if hasattr(file_raw, "file_deps"):
                        deps = file_raw.file_deps
                    else:
                        deps = []
                    target = [target_location]
                    v._update_raw("path", target_location)
                    
                    if hasattr(file_raw, "command"):
                        cmd = file_raw.command
                        n = "%s_%s" % (v.software.name, f)
                        c = LazyCmdTask([cmd], deps, target, n)
                        if all(map(os.path.exists, target)): # do not generate target multiple times
                            c.uptodate = [True]
                        else:
                            tasks.append(c)
                    elif hasattr(file_raw, "generator"):
                        gen = getattr(self, file_raw.generator, None)
                        if gen and callable(gen):
                            tasks.extend(gen(v.software, v, dstdir, deps))
                        else:
                            raise Exception("I do not know how to generate file '%s' (%s), no such generator named '%s'" % (file_raw.name, v.software.name, file_raw.generator))
                    else:
                        raise Exception("I do not know how to generate file %s, needs a command or generator" % file_raw.path)
        del Main.raw.runtime.current_stage        
        del Main.raw.runtime.current_host
        return tasks

    def get_build_name(self):
        return self.task_manager.build_name(self.subgroup)

    def enable(self):
        self.task_manager.enable(self.subgroup)

    def _add_tasks(self):
        for i in self.task_adders:
            t = i()
            self.task_manager.add_tasks(t, self.subgroup)
        self.task_manager.add_mgr(self)

    def _copy_file(self, path, dst):
        return CopyFileTask(path, dst)

    def _mkdir(self, path):
        return MkdirTask(path)

    def save_config(self, k, v):
        Main.set_config(k,  v)
        def save():
            return {k: v}
        return ActionListTask([(save,)], [], [], "save_%s" % k)

    def _backup_config_file_task(self, from_path, to_path):
        return self._copy_file(from_path, to_path)

    def _update_runtime_config(self, attr, value):
        if not attr.startswith("runtime."):
            r = "runtime."
        else:
            r = ""
        attr = r + attr
        self._update_config(attr, value)

    def _update_config(self, attr, value):
        Main._plain_update_raw(attr, value)


class PostTraceLoader(ResultsLoader):
    _processes_types = {'consolidate_writes': {'fn':
                                               "_histogram"},
                        'policy_check': {'fn':
                                         "_policy_check"},
                        'noop': {'fn': "_noop"},
                        'browse_db': {'fn':
                                      "_browse_db"},
                        'process_watchpoints': {"fn":
                                                "_watchpoints",
                                                "traces": ["watchpoint"]}}
    supported_types = _processes_types.iterkeys()

    def __init__(self, processes, run):
        instance_id = Main.test_instance_id
        super(PostTraceLoader, self).__init__(instance_id, "post_trace", run)
        self.trace_id = Main.raw.runtime.trace.id
        self.data_dir = Main.raw.runtime.trace.data_dir
        self.stages = Main.raw.runtime.enabled_stages
        self.hw = Main.raw.runtime.trace.host
        self.tracenames = [t.name for t in Main.raw.runtime.enabled_traces]
        self.processes = list(set(processes))
        self.task_adders = [self._setup_tasks,
                            self._process_tasks]
        self._add_tasks()

    def _test_path(self, rel=""):
        return os.path.join(self.data_dir, "postprocess", rel)

    def _process_path(self, p, rel=""):
        return os.path.join(self._test_path(p), rel)

    def _setup_tasks(self):
        tasks = []
        targets = []
        tasks.append(self._mkdir(self._test_path()))
        for (k, v) in self._processes_types.iteritems():
            if "traces" in v.iterkeys() and not all(map(lambda t: t in v["traces"],
                                                        self.tracenames)):
                continue

            tasks.append(self._mkdir(self._process_path(k)))
        return tasks

    def _process_tasks(self):
        tasks = []
        uptodate = {"uptodate": [True]}
        not_uptodate = {"uptodate": [False]}
        pps = Main.object_config_lookup("PostProcess")
        exabled = False
        for k in pps:
            if k.name not in self.processes:
                enabled = False
            else:
                enabled = True
            for stage in self.stages:
                ts = self._get_postprocess_tasks(enabled, k, stage)
                for t in ts:
                    if not enabled:
                        t.other.update(uptodate)
                        t.actions = []
                    else:
                        t.other.update(not_uptodate)                
                tasks.extend(ts)
        return tasks

    def _get_postprocess_tasks(self, enabled, task, stage):
        tasks = []
        file_deps = [Main.raw.runtime.trace.done]
        targets = []
        task_name = task.name
        dstdir = self._process_path(task_name)
        for (name, f) in task._files.iteritems():
            f.path = {}

        stagedir = os.path.join(dstdir, stage.stagename)
        tasks.append(self._mkdir(stagedir))
        for (name, f) in task._files.iteritems():
            rel_path = Main.populate_from_config(f.relative_path)
            path = os.path.join(stagedir, rel_path)
            self._update_config("postprocess.%s.files.%s.%s" %
                                (task_name, name, stage.stagename),
                                path)
            f.path[stage.stagename] = path
            if f.type in ["target", "log"]:
                targets.append(path)
        done_file = os.path.join(stagedir, "postprocess-done")
        self._update_config("postprocess.%s.files.done.%s" % (task_name, stage.stagename),
                            done_file)
        targets.append(done_file)
                                    

        if hasattr(task, "function"):
            proc = getattr(self, task.function)
            actions = proc(task.name, enabled, stage)
            tasks.append(ActionListTask(actions,
                                        file_deps,                                        
                                        targets,
                                        "postprocess_%s_%s" %
                                        (task.name, stage.stagename)))
        return tasks

    def _watchpoints(self, name, enabled):
        if "watchpoint" not in self.tracenames:
            return []
        watch_import_done = {}

        import qemu_raw_trace
        tasks = []
        raw_output = Main.get_config("trace_events_output")
        target = []

        class Do():
            def __init__(self, stage, events, raw):
                self.stage = stage
                self.raw = raw
                self.events = events

            def __call__(self):
                qemu_raw_trace.process_and_import(self.events,
                                                  self.raw,
                                                  self.stage)
        events = Main.get_config("all_qemu_evnts")
        for s in self.stages:
            n = s.stagename
            watch_import_done[n] = "watchpoint-import.done"
            tasks.append(ActionListTask([PythonInteractiveAction(Do(s, events, raw_output)),
                                         "touch %s" % watch_import_done[n]],
                                        [raw_output, events, Main.get_config("trace_db", n),
                                         Main.get_config("trace_db_done", n)],
                                        [watch_import_done[n]],
                                        "import_watchpoints_to_tracedb"))
        Main.set_config("watch_import_done", lambda s: watch_import_done[s.stagename])
        return tasks

    def _browse_db(self, name, enabled):
        tasks = []

        class Do():
            def __init__(self):
                pass

            def __call__(self):
                rwe = self
                IPython.embed()
        a = ActionListTask([PythonInteractiveAction(Do())],
                           [], [], name)
        tasks.append(a)
        return tasks

    def _histogram(self, name, enabled, stage):
        tasks = []
        deps = []
        class Do():
            def __init__(self, s, o, o2, done, tracename):
                self.s = s
                self.o = o
                self.o2 = o2
                self.done = done
                self.tracename = tracename

            def __call__(self):
                db_info.create(self.s, "policydb", trace=self.tracename)

                db_info.get(self.s).consolidate_trace_write_table()
                db_info.get(self.s).generate_write_range_file(self.o, self.o2)
                os.system("touch %s" % self.done)
        tasks = []
        for t in self.tracenames:
            if t not in Main.object_config_lookup("PostProcess", name).supported_traces:
                continue
            o = getattr(getattr(Main.raw.postprocess, name).files.range_txt, stage.stagename)
            o2 = getattr(getattr(Main.raw.postprocess, name).files.range_csv, stage.stagename)
            done = getattr(getattr(Main.raw.postprocess, name).files.done, stage.stagename)
            tasks.append(PythonInteractiveAction(Do(stage, o, o2, done, t)))
        return tasks


    def _noop(self, name, enabled):
        return []


    def _policy_check(self, name, enabled, stage):        
        tasks = []
        deps = []
        class Do():
            def __init__(self, s):
                self.s = s

            def __call__(self):
                db_info.create(self.s, "policydb", trace="breakpoint")
                db_info.get(self.s).check_trace()
        tp_db = {}
        tp_db_done = {}
        for n in Main.raw.policies.stages_with_policies:
            tp_db[n] = self._process_path(name, "policy-tracedb-%s.h5" % n)
            tp_db_done[n] = self._process_path(name, "policy-tracedb-%s.completed" % n)
            targets = [tp_db_done[n], tp_db[n]]
            a = PythonInteractiveAction(Do(Main.stage_from_name(n)))
            tasks.append(a)        
        return tasks

    



class TraceTaskLoader(ResultsLoader):
    def __init__(self,
                 create,
                 run,
                 print_cmds,
                 quick):
        self.print_cmds = print_cmds
        instance_id = Main.test_instance_id
        super(TraceTaskLoader, self).__init__(instance_id,
                                              "trace",
                                              run)
        self.test_root = Main.test_instance_root        
        self.create = create
        self.toprint = []
        self.quick = quick
        self.quit = True
        self.trace_id = Main.raw.runtime.trace.id
        self.tracenames = [t.name for t in Main.raw.runtime.enabled_traces]
        self.hw = Main.raw.runtime.trace.host
        self.hwname = self.hw.name
        paths = [os.path.dirname(os.path.realpath(__file__))] + sys.path
        paths = " ".join(paths)  # filter(lambda p: not (p.endswith(".egg") or p.endswith(".zip")), sys.path))
        self._update_runtime_config("python_path", paths)
        self.task_adders = [self._setup_collector]
        self._add_tasks()

    def _dest_dir_root_path(self, rel=""):
        return os.path.join(self.test_root, "trace_data", rel)

    def _test_path(self, rel=""):
        return os.path.join(self._dest_dir_root_path(self.trace_id), rel)




    def _setup_collector(self):
        tasks = []
        processed_software = []
        commands = {}
        gdb_cmds = []# ["file %s" % Main.raw.runtime.enabled_stages[0].elf]
        file_deps = []
        targets = []
        traceroot = self._test_path()


        def stage_dependent(s):
            if getattr(s, "stage_dependent", False):
                return True
            for (k, v) in s.iteritems():
                if isinstance(v, str) and "{runtime.stage}":
                    return True
            return False

        def sub_stage(c, stage=None):
            sub = "{runtime.stage}"
            if not stage:
                substages = Main.raw.runtime.enabled_stages
            else:
                substages = [stage]            
            if sub in c:
                cs = []
                for sn in substages:
                    cs.append(c.replace(sub,
                                     sn.stagename))
                return cs
            else:
                return [c]
        def sub_host(c):
            s = "{runtime.host}"
            if s in c:
                return c.replace(s,
                                 Main.raw.runtime.current_host)
            else:
                return c

        for tracename in self.tracenames:
            trace_dstdir = os.path.join(traceroot, tracename)
            tasks.append(self._mkdir(trace_dstdir))
            self._update_runtime_config("trace.%s.dir" % (tracename), trace_dstdir)
            for s in Main.raw.runtime.enabled_stages:
                tasks.append(self._mkdir(os.path.join(trace_dstdir, s.stagename)))
                                                                
            trace = Main.object_config_lookup("TraceMethod", tracename)
            rawtrace = getattr(Main.raw.TraceMethod, tracename)

            Main.raw.runtime.current_host = Main.raw.runtime.trace.host_name
            Main.raw.runtime.current_stage = ""
            if "Files" not in rawtrace.keys():
                continue
            for (name, rawf) in rawtrace.Files.iteritems():
                if rawf.type in ["target", "log"]:
                    p = rawf.relative_path
                    p = sub_host(p)
                    if stage_dependent(rawf):
                        for stage in Main.raw.runtime.enabled_stages:
                            p = sub_stage(p, stage)[0]
                            p = Main.populate_from_config(p)
                            p = os.path.join(trace_dstdir, stage.stagename, p)
                            targets.append(p)
                            self._update_runtime_config("trace.%s.files.%s.%s" % (trace.name,
                                                                            name,
                                                                            stage.stagename), p)
                            if hasattr(rawf, "global_name"):
                                n = sub_host(rawf.global_name)
                                n = sub_stage(n, stage)[0]
                                n = Main.populate_from_config(n)
                                self._update_config(n, p)


                    else:
                        p = Main.populate_from_config(p)
                        p = os.path.join(trace_dstdir, p)
                        targets.append(p)
                        self._update_runtime_config("trace.%s.files.%s" % (trace.name,
                                                                           name), p)
                        if hasattr(rawf, "global_name"):
                            n = sub_host(rawf.global_name)
                            n = Main.populate_from_config(n)
                            self._update_config(n, p)                                                    
                        
                elif rawf.type == "file_dep":
                    p = rawf.path
                    p = sub_host(p)
                    if stage_dependent(p):
                        for stage in Main.raw.runtime.enabled_stages:
                            p = sub_stage(p, stage)[0]
                            p = Main.populate_from_config(p)
                            file_deps.append(p) 
                            self._update_runtime_config("trace.%s.files.%s.%s" % (trace.name,
                                                                            name,
                                                                            stage.stagename), p)      
                    else:
                        p = Main.populate_from_config(p)
                        file_deps.append(p)
                        self._update_runtime_config("trace.%s.files.%s" % (trace.name,
                                                                           name), p)                                
            for s in trace.software:
                if isinstance(s, str):
                    #try:
                    s = Main.object_config_lookup("Software", s)
                    #except ConfigException:
                    #    continue
                if s.name in processed_software:
                    continue                
                processed_software.append(s.name)
                if s.build:
                    s.binary = Main.populate_from_config(s.binary)
                    file_deps.append(s.binary)
                for c in s._configs:
                    cmd = c.command
                    if cmd:
                        cmd = "%s %s" % (s.binary, cmd)
                        cmd = Main.populate_from_config(cmd)
                        self._update_config("Software.%s.ExecConfig.command" % s.name,
                                            cmd)
                        commands[s.name] = cmd                
                for v in s._GDB_configs:
                    for c in v.commands:
                        c = sub_host(c)
                        cs = sub_stage(c)
                        cs = [Main.populate_from_config(i) for i in cs]
                        gdb_cmds.extend(cs)
                
                        
            for v in trace._GDB_configs:
                for c in v.commands:
                    c = sub_host(c)
                    cs = sub_stage(c)
                    cs = [Main.populate_from_config(i) for i in cs]
                    gdb_cmds.extend(cs)
                    

        Main.raw.TraceMethod.gdb_commands = " ".join(map(lambda x: "-ex '%s'" % x,
                                                         gdb_cmds))
        done_file = os.path.join(trace_dstdir,"trace-done")
        self._update_runtime_config("trace.done", done_file) 
        run_trace = Main.populate_from_config(trace.run)
        self._update_config("runtime.trace.command", run_trace)
        self.toprint.append(run_trace)
        targets.append(done_file)
        done = "touch %s" % done_file
        #self._update_config("runtime.trace.done_file", done_file)       
        c = CmdTask([LongRunning(run_trace + "; " + done)],
                    file_deps, targets, "trace_%s" % trace.name)
        tasks.append(c)
        return tasks


    def do_print_cmds(self):
        if not self.toprint:
            return
        print "----------------------------------------"
        for a in self.toprint:
            print a
        print "----------------------------------------"



class TraceTaskPrepLoader(ResultsLoader):
    def __init__(self, trace_name, create, run_tasks,
                 print_cmds, stages=None, trace_list=[], host=None, hook=False):
        self.print_cmds = print_cmds
        instance_id = Main.test_instance_id
        super(TraceTaskPrepLoader, self).__init__(instance_id, "trace_prep", run_tasks)
        self.test_root = Main.test_instance_root
        #self.trace_id = Main.raw.runtime.trace.id
        self.create = create
        self.trace_id = trace_name
        self._update_config("runtime.trace.id", self.trace_id)
        self.config_path = self._test_path("config.yml")


        if self.create:
            self.stagenames = [s.stagename for s in stages]
            self.hwname = Main.hardwareclass
            self.tracenames = trace_list
            self.hostname = host
        else:
            # get these values from the config
            with open(self.config_path, 'r') as f:
                settings = yaml.load(f)
            self.stagenames = settings['stages']
            self.hwname = settings['hw']
            self.tracenames = settings['traces']
            self.hostname = settings['host']

        self.hw = Main.object_config_lookup("HardwareClass", self.hwname)
        self.host = Main.object_config_lookup("HostConfig", self.hostname)
        self.stages = [Main.stage_from_name(s) for s in self.stagenames] 
        self._update_runtime_config("trace.host", getattr(Main.raw.HostConfig, self.hostname))
        self._update_runtime_config("trace.host_name", self.host.name)        
        for k in self.host._GDB_configs:
            for (name, v) in k.__dict__.iteritems():
                if isinstance(v, str) and not v in ["name", "kind", "typ", "type"]:
                    self._update_runtime_config("trace.host_configs.%s" % name, v)
        self._update_runtime_config("trace.hw", self.hw)
        active_stages = [Main.stage_from_name(s) for s in self.stagenames]
        self._update_runtime_config("enabled_stages", active_stages)
        self._update_runtime_config("enabled_stagenames", " ".join(self.stagenames))
        active_traces = [t for t in Main.traces if t.name in self.tracenames]
        self._update_runtime_config("enabled_traces", active_traces)

        self.name = "%s.%s.%s" % (self.hostname,
                                  "-".join(self.tracenames), "-".join(self.stagenames))
        self.namefile = self._test_path(self.name)
        self.task_adders = [self._setup_tasks, self._host_backup_tasks]
        self._add_tasks()

    @classmethod
    def _existing_trace_ids(cls, instance_id, list_times=False):
        for f in glob.glob("%s/*" % os.path.join(cls.instance_root(instance_id),  "trace_data")):
            if os.path.isdir(f) and not os.path.basename(f) == "trace_data-by_name":
                if not list_times:
                    yield (os.path.basename(f))
                else:
                    t = os.stat(f).st_ctime
                    timestr = datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')
                    yield (timestr, os.path.basename(f), "unknown")

    @classmethod
    def get_trace_name(cls, instance_id, trace_id=None, create=False, hook=False):
        if create:
            trace_id = cls.create_new_id(instance_id)
        elif trace_id is None:  # get last id
            existing = sorted(cls._existing_trace_ids(instance_id))
            if len(existing) > 0:
                trace_id = existing[-1]
            else:
                return None
        else:
            if not hook:
                existing = sorted(cls._existing_trace_ids(instance_id))
                if trace_id not in existing:
                    try:
                        i = int(trace_id)
                    except:
                        i = None
                    if i is not None:
                        i = cls._format_id(i)
                        if i in existing:
                            trace_id = i
                    res = difflib.get_close_matches(trace_id, existing, 1, 0)
                    if not res:
                        if len(existing) == 0:
                            raise Exception("No exising trace result dirs")
                        trace_id = existing[-1]
                    else:
                        trace_id = res[0]
        return cls._format_id(trace_id)

    @classmethod
    def test_path(cls, instance_id, trace_id):
        return os.path.join(cls.instance_root(instance_id), "trace_data", trace_id)

    @classmethod
    def _format_id(cls, num):
        return str(num).zfill(8)

    def _host_backup_tasks(self):
        tasks = []
        d = getattr(Main.raw.hosts, self.hostname).cache
        #self._update_runtime_config("%s_root_testdir" % self.hostname, d)
        for (k, v) in self.host._files.itervalues():
            if v.type == "config" or v.type == "mmap" and not v.generate:
                self._backup_config_file_task(v.path, d)
        return tasks

    @classmethod
    def create_new_id(cls, instance_id):
        num = 0
        existing = sorted(cls._existing_trace_ids(instance_id))
        if len(existing) == 0:
            return cls._format_id(0)
        while True:
            if cls._format_id(num) in existing:
                num += 1
            else:
                break
        return cls._format_id(num)

    @classmethod
    def instance_root(cls, instance_id):
        return os.path.join(Main.test_data_path, instance_id)

    def _dest_dir_root_path(self, rel=""):
        return os.path.join(self.test_root, "trace_data", rel)

    def _test_path(self, rel=""):
        return os.path.join(self._dest_dir_root_path(self.trace_id), rel)

    def _setup_tasks(self):
        tasks = []
        deps = []
        tasks.append(self._mkdir(self._test_path()))
        symlink_dir = os.path.join(self._dest_dir_root_path(), "trace_data-by_name")
        tasks.append(self._mkdir(symlink_dir))
        target_dir = os.path.join(symlink_dir, os.path.basename(self.namefile))
        tasks.append(self._mkdir(target_dir))
        target_file = os.path.join(target_dir, self.trace_id)
        tasks.append(CmdTask(["ln -s -f %s %s" % (self._test_path(), target_file)],
                             [], [target_file], "symlink-%s" % target_file))
        self._update_config("runtime.trace.data_dir", self._test_path())

        def write(f, stagenames, hwname, tracenames, host):
            with open(f, "w") as fconfig:
                contents = """
stages: [{}]
hw: {}
traces: [{}]
host: {}
"""
                filecontents = contents.format(", ".join(stagenames), hwname,
                                               ", ".join(tracenames), host)
                fconfig.write(filecontents)
        Main.set_runtime_config("test_config_file", self.config_path)
        a = ActionListTask([(write, [self.config_path,
                                     self.stagenames, self.hwname, self.tracenames, self.hostname])],
                           [], [self.config_path], "test_config_file")
        try:
            os.makedirs(self._test_path())
        except OSError:
            pass

        # just force this to be create, I cannot figure out what this dependency isn't being
        # triggered otherwise
        for (l,args) in a.actions:
            l(*args)

        if not self.create:
            a.other = {'uptodate': [True]}
        else:
            a.other = {'uptodate': [False]}
        tasks.append(a)
        c = CmdTask(["touch %s" % self.namefile], [],
                    [self.namefile], "test_name_file")
        tasks.append(c)
        return tasks

class InstrumentationTaskLoader(ResultsLoader):
    def __init__(self, target_task,
                 instance_id,
                 manager,
                 create=False,
                 gitinfo={"local": "n/a", "sha1": "none"},
                 rm_tmp=True,
                 testonly=False):
        super(InstrumentationTaskLoader, self).__init__(instance_id, "instance", True)
        self.testonly = testonly
        self.create = create
        self.gitinfo = gitinfo
        self.manager = manager
        self.test_data_path = Main.test_data_path
        self.target_path = target_task.root_dir
        self.hardwareclass = Main.get_hardwareclass_config()
        self.instance_id = instance_id
        self.target_task = target_task
        self.rm_tmp = rm_tmp
        hw = Main.get_hardwareclass_config()
        hwname = hw.name
        targetname = Main.target_software.name
        hdir = os.path.join(hw.hw_info_path, hwname)
        Main.test_instance_id = self.instance_id
        self._update_runtime_config("instance_id", self.instance_id)

        self._update_runtime_config("hardware_data_target_dir",  os.path.join(hdir, targetname))

        self.task_adders = [
            self._mkdir_tasks,
            self._staticanalysis_dirs,            
            self._image_tasks,                            
            self._addr_map_tasks,
            self._staticanalysis_tasks]
        #self._trace_tasks]
        self.task_adders.extend(self._hw_tasks_from_config())
        self._add_tasks()

    def _hw_tasks_from_config(self):
        tasks = []
        return tasks

    def _mkdir_tasks(self):
        tasks = []
        tasks.append(self._mkdir(self.test_data_path))
        tasks.append(self._mkdir(self._full_path()))
        return tasks
    
    def _full_path(self, rel=""):
        return os.path.join(self.test_data_path, self.instance_id, rel)

    def _target_src_path(self, rel=""):
        return os.path.join(self.target_path, rel)

    def _suite_src_path(self, rel=""):
        return os.path.join(Main.config.test_suite_path, rel)

    def _addr_map_tasks(self):
        tasks = []

        dstdir = self._full_path("mmap")

        hwclass = Main.get_hardwareclass_config()
        config_data = getattr(Main.raw.HardwareClass, hwclass.name)
        cache = Main.raw.hw_cache
        raw = []
        actions = []
        tasks.append(self._mkdir(dstdir))
        self._update_config("static_analysis.mmap.dir", dstdir)
        tasks.extend(self.import_files(hwclass, config_data, Main.raw.hw_cache, True))        
        mmapdb_path = os.path.join(dstdir, "mmap.h5")
        self._update_config("static_analysis.mmap.db", mmapdb_path)
        self._update_config("static_analysis.mmap.db_done", mmapdb_path+"-completed")


        class addr_space_setup():
            def __call__(self):
                done_target = Main.raw.static_analysis.mmap.db_done
                target = Main.raw.static_analysis.mmap.db
                if os.path.exists(target) and not os.path.exists(done_target):
                    #creation must have failed, try again
                    os.remove(target)
                db_info.create("any", "mmapdb")
                return os.system("touch %s" % done_target) == 0
        a = DelTargetAction(addr_space_setup())

        actions.append(a)
        raw.extend([s.elf
                for s in Main.stages])
        targets = [mmapdb_path,
                   mmapdb_path+"done"]
        rtask = ActionListTask(actions, raw,
                               targets,
                               "generate_addr_info")
        rtask.task_dep.append(dstdir)
        tasks.append(rtask)
        return tasks

    def _staticanalysis_dirs(self):
        tasks = []
        dstdir = self._full_path("static_analysis")
        tasks.append(self._mkdir(dstdir))
        self._update_config("static_analysis.dir", dstdir)        
        for s in Main.stages:
            n = s.stagename
            d = os.path.join(dstdir, n)
            tasks.append(self._mkdir(d))
        return tasks
    
    def _staticanalysis_tasks(self):
        tasks = []

        dstdir = Main.raw.static_analysis.dir
        for s in Main.stages:
            n = s.stagename
            d = os.path.join(dstdir, n)
            self._update_config("static_analysis.db.%s" % n, os.path.join(d,
                                                                          "static-analysis.h5"))
            self._update_config("static_analysis.db_done.%s" % n, os.path.join(d,
                                                                               "static-analysis.h5-completed"))

            # calculate thumb ranges on demand
            class get_thumb_ranges():
                def __init__(self, stage):
                    self.stage = stage                

                def __call__(self):                
                    v = staticanalysis.ThumbRanges.find_thumb_ranges(self.stage)      
                    Main.set_runtime_config("thumb_ranges.%s" % self.stage.stagename, v)
                    return v
            self._update_config("runtime.thumb_ranges.%s" % n, get_thumb_ranges(s))

        # calculate labels on demand
        def get_labels():
            try:
                v = Main.get_runtime_config("labels_internal")
            except AttributeError:
                tmpdir = Main.raw.runtime.temp_target_src_dir
                olddir = os.getcwd()
                os.chdir(tmpdir)
                v = labeltool.get_all_labels(tmpdir)
                Main.raw.runtime.labels_internal = v
                os.chdir(olddir)
            return v
        Main.raw.runtime.labels = get_labels

        for s in Main.stages:
            class run_analysis():
                def __init__(self, stage):
                    self.stage = stage

                def __call__(self):
                    done_target = Main.get_static_analysis_config("db_done", self.stage)
                    target = Main.get_static_analysis_config("db", self.stage)                    
                    if not os.path.exists(done_target):
                        if os.path.exists(target):
                            # if done doesnt existb but target does, probably means
                            # target db was not sucessfully created
                            os.remove(target)
                        db_info.create(self.stage, "staticdb")
                    return os.system("touch %s" % done_target) == 0
            n = s.stagename
            target = Main.get_static_analysis_config("db", s)
            done_target = Main.get_static_analysis_config("db_done", s)                
            a = DelTargetAction(run_analysis(s))
            actions = [a]
            rtask = ActionListTask(actions,
                                   [s.elf],
                                   [target, done_target], "staticanalysis_%s" % n)
            tasks.append(rtask)
        return tasks

    def _image_tasks(self):
        tasks = []
        targetimages = []
        targetelfs = []
        imgsrcs = []
        elfdst = {}
        imagedst = {}
        deps = []
        targets = []
        Main.test_instance_root = self._full_path()
        Main.test_instance_id = self.instance_id

        dstdir = self._full_path("images")
        tasks.append(self._mkdir(dstdir))
        self._update_config("instance_image_cache", dstdir)
        self.config_path = self._full_path("config.yml")
        self._update_runtime_config("instance_config_file", self.config_path)

        
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                settings = yaml.load(f)
                self.local = settings['local']
                self.sha = settings['sha1']
        else:
            self.local = self.gitinfo['local']
            self.sha = self.gitinfo['sha1']

        def write(f, local, sha):
            with open(f, "w") as fconfig:
                contents = """
local: {}
sha1: {}
"""
                filecontents = contents.format(local, sha)
                fconfig.write(filecontents)
        a = ActionListTask([(write, [self.config_path, self.local, self.sha])],
                           [], [self.config_path], "instance_config_file")
        tasks.append(a)

        # make temporary copy of git tree to pull labels from
        if not hasattr(Main.raw.runtime, "temp_target_src_dir"):
            tmpdir = tempfile.mkdtemp()
            self._update_runtime_config("temp_target_src_dir", tmpdir)

        def rm_src_dir():
            print "removing temporary copy of target source code at %s" % tmpdir
            os.system("rm -rf %s" % tmpdir)
            
        if self.rm_tmp:
            atexit.register(rm_src_dir)
        olddir = os.getcwd()
        os.chdir(self.local)
        if Main.target_software.git:
            os.system("git archive %s | tar -C %s -x" % (self.sha, tmpdir))
            os.system("ls -l %s" % tmpdir)
        else:
            os.system("cp -avr ./* %s > /dev/null" % tmpdir)
        os.chdir(olddir)

        if os.path.exists(dstdir):
            has_all_images = True
            for stage in Main.stages:
                for t in ["elf", "image"]:
                    if not has_all_images:
                        break
                    path_raw = getattr(stage, t)
                    rel_path = Main.populate_from_config(path_raw)
                    rel_path = os.path.basename(rel_path)
                    cached_path = os.path.join(dstdir,
                                               rel_path)
                    if not os.path.exists(cached_path):
                        has_all_images = False
                        break
        else:
            has_all_images = False
                
        
        # update paths of generated binaries to where they live in
        # temp build directory or image cache dir
        for (f, v) in Main.target_software._files.iteritems():
            if hasattr(v, "path"):
                p = Main._populate_from_config(v.path)
            elif not has_all_images:
                p = os.path.join(tmpdir, v.relative_path)
            else:
                p = os.path.join(dstdir, os.path.basename(v.relative_path))
            if hasattr(v, "global_name"):
                n = Main._populate_from_config(v.global_name)
                self._update_config(n, p)

            
            
        for i in Main.stages:
            i.elf = Main._populate_from_config(i.elf)
            i.image = Main._populate_from_config(i.image)            
            elfdst[i.stagename] = os.path.join(dstdir, os.path.basename(i.elf))

            imagedst[i.stagename] = os.path.join(dstdir, os.path.basename(i.image))
            self._update_config("target.file.elf.%s" % i.stagename, elfdst[i.stagename])
            self._update_config("target.file.image.%s" % i.stagename, imagedst[i.stagename])

        targetelfs = elfdst.values()
        targetimage = imagedst.values()
        tocpy = targetelfs + targetimages
        targets.extend(tocpy)
        
        if not has_all_images:
            builder = self.manager.build([Main.target_software.basename], False)[0]
            build_cmds = []
            for t in builder.tasks:
               for action in t.list_tasks()['actions']:
                   if isinstance(action, CmdAction):
                       do = action.expand_action()
                       build_cmds = ["cd %s && %s" % (tmpdir, do)] + build_cmds
            build_cmds.append("mkdir -p %s && true" % dstdir)
            for i in Main.stages:
                for t in ["elf", "image"]:
                    build_cmds.append("cp %s %s" % (os.path.join(tmpdir,
                                                                 getattr(i, t)),
                                                    dstdir))
            for b in build_cmds:
                if not self.testonly:
                    os.system(b)

        # NEXT: set true paths of all target files generated here
        for stage in Main.stages:
            for t in ["elf", "image"]:
                finaldst = os.path.join(dstdir,
                                        os.path.basename(getattr(stage, t)))
                if has_all_images:
                    setattr(stage, t, finaldst)
                else:
                    img = getattr(stage, t)
                    new = os.path.join(tmpdir,
                                       img)
                    setattr(stage, t, new)

        # for s in Main.object_config_lookup("Software"):
        #     for (f, v) in s._files.iteritems():
        #         file_raw = getattr(getattr(Main.raw.Software, s.name).Files, v.name)
        #         if v.type == "image" and v.generate and not v.imported:
        #             v.imported = True
        #             if hasattr(v, "command"):
        #                 cmd = file_raw.command
        #                 n = "%s_%s" % (v.software.name, f)
        #                 c = LazyCmdTask([cmd], deps, target, n)
        #                 if all(map(os.path.exists, target)): # do not generate target multiple times
        #                     c.uptodate = [True]
        #                 else:
        #                     tasks.append(c)
        #             elif hasattr(file_raw, "generator"):
        #                 gen = getattr(self, file_raw.generator, None)
        #                 if gen and callable(gen):
        #                     tasks.extend(gen(v.software, v, dstdir, deps))
        #                 else:
        #                     raise Exception("I do not know how to generate file '%s' (%s), no such generator named '%s'" % (file_raw.name, v.software.name, file_raw.generator))                    

                    
        # remove build tasks from list so they don't get rerun in original source dir
        self.manager.src_manager.code_tasks = []

        hwclass = Main.get_hardwareclass_config()
        config_data = getattr(Main.raw.HardwareClass, hwclass.name)
        cache = self._full_path("hw")
        os.system("mkdir -p %s" % cache)        
        tasks.append(self._mkdir(cache))
        self._update_config("hw_cache", cache)        
        tasks.extend(self.import_files(hwclass, config_data, cache))
        dstdir = os.path.join(cache, "host")
        tasks.append(self._mkdir(dstdir))
        soft_cache = self._full_path("software_config")
        self._update_config("sw_cache", soft_cache)
        tasks.append(self._mkdir(soft_cache))
        
        for h in Main.object_config_lookup("HostConfig"):
            d = os.path.join(soft_cache, h.name)
            self._update_config("hosts.%s.cache" % h.name, d)
            tasks.append(self._mkdir(d))
            for s in Main.stages:
                for soft in Main.object_config_lookup("Software"):
                    cache = os.path.join(d, soft.name)
                    raw = getattr(Main.raw.Software, soft.name)
                    self._update_config("runtime.software.%s.cache" % soft.name, cache)                    
                    tasks.extend(self.import_files(soft, raw, cache, host=h, stage=s))
        for stage in Main.stages:                    
            stage.post_build_setup(os.path.dirname(stage.image))                    
        return tasks



    def build_target(self, soft, i, dstdir, deps):
        tasks = []
        return tasks

    def sd_image_builder(self, soft, i, dstdir, deps):
        tasks = []
        skel = None
        for (f, v) in soft._files.iteritems():
            if f == "sdskeleton":
                skel = v
                v.imported = True
                break
        sd_image = None
        for (f, v) in soft._files.iteritems():
            if f == "sd_image":
                sd_image = v
                v.imported = True
                if hasattr(v, "file_deps"):
                    file_deps = v.file_deps
                else:
                    file_deps = []
                break
        dstdir =  Main.raw.instance_image_cache
        sdtarget = os.path.join(dstdir, sd_image.relative_path)
        sdtmpdir = tempfile.mkdtemp()
        tmpmnt = os.path.join(sdtmpdir, "mnt")
        tmpsd = os.path.join(sdtmpdir, sd_image.relative_path)
        tmpsd = Main.populate_from_config(tmpsd)
        sp = Main.populate_from_config(skel.path)
        cp = "cp %s %s" % (sp, tmpsd)
        mkdir = "mkdir -p %s" % (tmpmnt)
        mnt = "sudo mount -o loop,offset=%d %s %s" % (512*63, tmpsd, tmpmnt)
        update_mnt = []
        bins = []
        t = Main.raw.runtime.temp_target_src_dir
        for s in Main.stages:
            e = s.elf
            i = s.image
            if e == i:
                bins.extend([e])
            else:
                bins.extend([e, i])

        for i in bins:
            update_mnt.append("sudo cp %s %s" % (i,
                                                 tmpmnt))
        if hasattr(soft, "import_root"):
            dst_root = Main.populate_from_config(soft.import_root)
        else:
            dst_root = ""

        umount = "sudo umount %s" % tmpmnt
        cp_final = "cp %s %s" % (tmpsd, sdtarget)
        rmtmp = "sudo rm -r %s" % sdtmpdir
        cmds = [cp, mkdir, mnt] + update_mnt + [umount, cp_final, rmtmp]

        self._update_runtime_config("target.sd_image", sdtarget)
        mksd = CmdTask(cmds,
                       bins,
                       [sdtarget],
                       "sd_card_image")
        if os.path.exists(sdtarget):
            mksd.uptodate = [True]
        else:
            mksd.uptodate = [False]
        tasks.append(mksd)
        return tasks


class PolicyTaskLoader(ResultsLoader):
    def __init__(self, import_policy, policies):
        instance_id = Main.test_instance_id
        super(PolicyTaskLoader, self).__init__(instance_id, "policy", import_policy)
        self.policy_files = {}
        self.import_policy = {}
        self.policies = {}
        if import_policy:
            self.import_policy = policies
            self.policies = {k:substage.SubstagesInfo.calculate_name_from_files(sub, reg) for (k, (sub, reg)) in policies.iteritems()}
        else:
            if not policies:
                self.policies = self.default_policies(instance_id, Main.stages)
            else:
                self.policies = policies
        for (stage, pname) in self.policies.iteritems():
            self.policy_files[stage] = (self._policy_stage_substage_file(stage),
                                        self._policy_stage_region_file(stage))


        self.stagenames = policies.keys
        self.task_adders = [self._import_tasks, self._policy_tasks]
        self._add_tasks()

    @classmethod
    def default_policies(cls, instance, stages):
        p = {}
        rt = os.path.join(TraceTaskPrepLoader.instance_root(instance),
                          "policies")
        for s in stages:
            sroot = os.path.join(rt, s.stagename)
            (n_time, n_name) = (0, None)
            for f in glob.glob("%s/*" % sroot):
                if os.path.isdir(f):
                    t = os.stat(f).st_ctime
                    if t > n_time: # it's newer
                        n_time = t
                        n_name = os.path.basename(f)
            if n_name:
                p[s.stagename] = n_name
        return p
    
    def _import_tasks(self):
        tasks = []
        tasks.append(self._mkdir(self._policy_root()))
        stages = self.policies.keys()
        self._update_config("policies.stages_with_policies", stages)
        for (s, files) in self.import_policy.iteritems():
            (sub, reg) = files
            tasks.append(self._mkdir(self._policy_root(s)))
            tasks.append(self._mkdir(self._policy_stage_root(s)))
            os.system("mkdir -p %s" % self._policy_stage_root(s)) # HACK 
            tasks.append(self._copy_file(sub,
                                         self._policy_stage_substage_file(s)))
            tasks.append(self._copy_file(reg,
                                         self._policy_stage_region_file(s)))
            
        for (s, name) in self.policies.iteritems():
            self._update_config("policies.name.%s" % s, name)
            self._update_config("policies.regions_file.%s" % s,
                                self._policy_stage_region_file(s))                                
            self._update_config("policies.substages_file.%s" % s,
                                self._policy_stage_substage_file(s))
            
        return tasks

    def _policy_root(self, stage=""):
        if type(stage) == str:
            s = stage
        else:
            s = stage.stagename
        return os.path.join(Main.test_instance_root, 'policies', s)

    
    def _policy_stage_region_file(self, stage):
        return self._policy_stage_root(stage, "regions.yml")

    def _policy_stage_substage_file(self, stage):
        return self._policy_stage_root(stage, "substages.yml")

    def _policy_stage_root(self, stage, rel=""):
        if type(stage) == str:
            s = stage
        else:
            s = stage.stagename
        policy_name = self.policies[s]
        return os.path.join(self._policy_root(), s, policy_name, rel)

    def _policy_tasks(self):
        tasks = []
            
        for (stage, name) in self.policies.iteritems():
            db = self._policy_stage_root(stage, "policy-db.h5")                
            self._update_config("policies.db.%s" % stage,
                                        db)
            db_done = self._policy_stage_root(stage,
                                              "policy-db.h5-completed")
            self._update_config("policies.db_done.%s" % stage,
                                        db_done)
            class setup_policy():
                def __init__(self, stage, done):
                    self.stage = stage
                    self.done = done

                def __call__(self):
                    db_info.create(self.stage, "policydb", trace=False)
                    os.system("touch %s" % self.done)

            at = DelTargetAction(setup_policy(stage, db_done))
            actions = [at]
            staticdb = getattr(Main.raw.static_analysis.db, stage)
            staticdb_done = getattr(Main.raw.static_analysis.db_done, stage)
            mmapdb = Main.raw.static_analysis.mmap.db
            mmapdb_done = Main.raw.static_analysis.mmap.db_done

            targets = []
            if stage in self.policies:
                targets = [db, db_done]

                a = ActionListTask(actions,
                                   [mmapdb_done, mmapdb, staticdb_done,
                                    staticdb, self._policy_stage_substage_file(stage),
                                    self._policy_stage_region_file(stage)],
                                   targets,
                                   "create_%s_policy_db" % stage)
            a.task_dep.append("instance")
            tasks.append(a)
        return tasks
