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
import config
from doit import loader
from doit.task import dict_to_task
from doit.task import DelayedLoader
from doit.task import Task
from doit.tools import run_once
from doit.dependency import UptodateCalculator
from doit.cmd_base import TaskLoader
from doit.action import PythonAction
import sys
import time
import os
import re
import glob
import importlib
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
import qemu_raw_trace
import db_info
from doit import exceptions
import qemu_raw_trace


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
_diabled_tasks = []


def task_manager(test_id=None):
    class TestTaskManager(object):
        def __init__(self, test_id):
            self.ALL_GROUPS = 0
            self.test_id = test_id
            self.tasks = {}

        def add_tasks(self, task_list, subgroup):
            l = self.tasks.get(subgroup, [])
            l.extend(task_list)
            self.tasks[subgroup] = l

        def list_tasks(self):
            class List():
                def __init__(self, obj, subgroup):
                    self.obj = obj
                    self.subgroup = subgroup

                def list_tasks(self):
                    return self.obj._list_tasks(self.subgroup)
            ts = []
            for k in self.tasks.iterkeys():
                ts.append(("task_%s_subgroup" % self.build_name(k),
                           List(self, k).list_tasks))
            ts.append(("task_%s_subgroup_all_" % self.build_name(),
                       List(self, self.ALL_GROUPS).list_tasks))
            return ts
#                     self._list_tasks(subgroup_only, all_groups))

        def _list_tasks(self, subgroup):
            if subgroup == self.ALL_GROUPS:
                vallists = [t for t in self.tasks.itervalues()]
                task_lists = [item for sublist in vallists for item in sublist]
                alldeps = []
                for (subgroup, tasks) in self.tasks.iteritems():
                    for t in tasks:
                        alldeps.append(self.task_name(t, subgroup))
                yield {
                    'basename': "all_subroups",
                    'name': None,
                    'task_dep': alldeps,
                }
            else:
                for inst in self.tasks[subgroup]:
                    r = {
                        'basename': self.task_name(inst, subgroup),
                        'name': self.test_id,
                        'actions': inst.actions,
                        'targets': inst.targets,
                        'file_dep': inst.file_dep
                    }
                    r.update(inst.other)
                    yield r

        def task_name(self, task, subgroup):
            return "%s:%s" % (subgroup, task.name)

        def build_name(self, subgroup=""):
            if not subgroup:
                return self.test_id
            else:
                return "%s:%s" % (self.test_id, subgroup)

    global _manager_singleton
    if not _manager_singleton:
        if test_id is None:
            raise Exception("test_id must be defined")
        _manager_singleton = TestTaskManager(test_id)
    return _manager_singleton


class TestTask(object):
    def __init__(self, name):
        self.name = "%s_%s" % (name, self.__class__.__name__)
        for i in ["actions", "targets", "file_dep", "other"]:
            if not hasattr(self, i):
                default = {} if i == 'other' else []
                listname = "list_%s" % i
                if i is not "other":
                    val = getattr(self, listname)() if hasattr(self, listname) else default
                else:
                    val = getattr(self, listname)() if hasattr(self, listname) else default
                setattr(self, i, val)
        self.verbosity = 2


class CopyFileTask(TestTask):
    def uptodate(self):
        return os.path.exists(self.dst)

    def __init__(self, src, dst, name):
        super(CopyFileTask, self).__init__(name)
        self.src = src
        self.dst = dst
        self.other = {'uptodate': [(self.uptodate, )]}
        self.file_dep = [self.src]
        self.actions = ["cp %s %s" % (self.src, self.dst)]
        self.targets = [self.dst]


class MkdirTask(TestTask):
    dirs = set()

    def uptodate(self):
        return os.path.exists(self.dst)

    @classmethod
    def exists(cls, d):
        return d in cls.dirs

    def __init__(self, d, name):
        self.dst = d
        self.other = {'uptodate': [(self.uptodate, )]}
        self.actions = [(create_folder, [self.dst])]
        MkdirTask.dirs.add(d)
        super(MkdirTask, self).__init__(name)


class CmdTask(TestTask):
    def __init__(self, cmds, file_deps, tgts, name):
        super(CmdTask, self).__init__(name)
        self.fdeps = file_deps
        self.targets = tgts
        self.actions = cmds
        self.file_dep = self.fdeps


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


class ResultsLoader(object):
    def __init__(self, test_id, subgroup, run_task=True):
        self.test_id = test_id
        self.subgroup = subgroup
        self.task_adders = []
        self.task_manager = task_manager(test_id)
        self.run_task = run_task

    def get_build_name(self):
        return self.task_manager.build_name(self.subgroup)

    def _add_tasks(self):
        for i in self.task_adders:
            t = i()
            if self.run_task:
                self.task_manager.add_tasks(t, self.subgroup)

    def _copy_file(self, path, dst, name=None):
        name = path if name is None else name
        return CopyFileTask(path, dst, name)

    def _mkdir(self, path, name=None):
        name = path if name is None else name
        return MkdirTask(path, name)

    def save_config(self, k, v):
        Main.set_config(k,  v)

        def save():
            return {k: v}
        return ActionListTask([(save,)], [], [], "save_%s" % k)


class PostTraceLoader(ResultsLoader):
    _processes_types = {'consolidate_writes': {'fn':
                                               "_histogram",},
                        'policy_check': {'fn':
                                         "_policy_check",},
                        'process_watchpoints': {"fn":
                                                "_watchpoints",
                                                "traces": ["watchpoint"]}}
    supported_types = _processes_types.iterkeys()

    def __init__(self, processes):
        test_id = Main.get_config("test_instance_id")
        super(PostTraceLoader, self).__init__(test_id, "post_trace")
        self.trace_id = Main.get_config("trace_id")
        self.data_dir = Main.get_config("trace_data_dir")
        self.name = Main.get_config("trace_name")
        self.stages = Main.get_config("trace_stages")
        self.hw = Main.get_config("trace_hw")
        self.tracenames = Main.get_config("trace_traces")
        self.processes = list(set(processes))
        self.task_adders = [self._setup_tasks,
                            self._process_tasks]
        self._add_tasks()

    def _test_path(self, rel=""):
        return os.path.join(self.data_dir, rel)

    def _process_path(self, p, rel=""):
        return os.path.join(self._test_path(p), rel)

    def _setup_tasks(self):
        tasks = []
        targets = []
        for (k, v) in self._processes_types.iteritems():
            if "traces" in v.iterkeys() and not all(map(lambda t: t in v["traces"],
                                                           self.tracenames)):
                continue
            tasks.append(self._mkdir(self._process_path(k)))
        return tasks

    def _process_tasks(self):
        tasks = []
        uptodate = {"uptodate": [True]}
        for (k, v) in self._processes_types.iteritems():
            if "traces" in v.iterkeys() and not all(map(lambda t: t in v["traces"],
                                                           self.tracenames)):
                continue
            if k not in self._processes_types.iterkeys():
                continue
            proc = getattr(self, v["fn"])
            ts = proc(k)
            if k not in self.processes:
                for t in ts:
                    t.other.update(uptodate)
            tasks.extend(ts)
        return tasks

    def _watchpoints(self, name):
        tasks = []
        raw_output = Main.get_config("trace_events_output")
        target = []
        test_db = {}
        test_db_done = {}

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
            test_db[n] = self._test_path("tracedb-%s.h5" % n)
            test_db_done[n] = self._test_path("tracedb-%s.completed" % n)
            tasks.append(ActionListTask([PythonInteractiveAction(Do(s, events, raw_output)),
                                         "touch %s" % test_db_done[n]],
                                        [raw_output, events, events],
                                        [test_db_done[n], test_db[n]],
                                        "import_watchpoints_to_tracedb"))
        Main.set_config("trace_db", lambda s: test_db[s.stagename])
        Main.set_config("trace_db_done", lambda s: test_db_done[s.stagename])
        return tasks

    def _histogram(self, name):
        tasks = []

        class Do():
            def __init__(self, s, o):
                self.s = s
                self.o = o

            def __call__(self):
                db_info.get(self.s).generate_write_range_file(self.o)

        for s in self.stages:
            deps = [Main.get_config('trace_db_done', s)]
            outfile = self._process_path(name,
                                         "%s-write_range_info.txt" % s.stagename)

            a = ActionListTask([PythonInteractiveAction(Do(s, outfile))],
                               deps, [outfile], name)
            tasks.append(a)
        return tasks

    def _policy_check(self, name):
        tasks = []
        tp_db = {}
        deps = []
        fns = {}
        el_file = {}
        tp_db_done = {}

        class Do():
            def __init__(self, s):
                self.s = s

            def __call__(self):
                db_info.create(self.s, "policytracedb")
                #db_info.get(self.s).generate_write_range_file(self.o)

        for s in Main.get_config("stages_with_policies"):
            if s not in self.stages:
                continue
            n = s.stagename
            tp_db[n] = self._process_path(name, "policy-tracedb-%s.h5" % n)
            tp_db_done[n] = self._process_path(name, "policy-tracedb-%s.completed" % n)
            el_file[n] = self._process_path(name, "substages-%s.el" % n)
            fns[n] = self._process_path(name, "%s_fn_lists" % n)
            tasks.append(self._mkdir(fns[n]))
            if "framac" not in self.tracenames:
                deps = [Main.get_config("calltrace_db", s)]
            else:
                deps = [Main.get_config('framac_callstacks', s)]
            tasks.append(ActionListTask([PythonInteractiveAction(Do(s)),
                                         "touch %s" % tp_db_done[n]],
                                        deps,
                                        [tp_db_done[n], tp_db[n], el_file[n]],
                                        "%s_postprocess_trace_policy" % (n)))

        Main.set_config("policy_trace_db", lambda s: tp_db[s.stagename])
        Main.set_config("policy_trace_el", lambda s: el_file[s.stagename])
        Main.set_config("policy_trace_done", lambda s: tp_db_done[s.stagename])
        Main.set_config("policy_trace_fnlist_dir", lambda s: fns[s.stagename])
        return tasks


class TraceTaskLoader(ResultsLoader):
    def __init__(self, instrumentation_task, trace_name, create, quick, run_tasks):
        test_id = Main.get_config("test_instance_id")
        print "trace task run %s" % run_tasks
        super(TraceTaskLoader, self).__init__(test_id, "trace", run_tasks)
        self.test_root = Main.get_config("test_instance_root")
        self.create = create
        self.quick = quick
        if self.create:
            self.trace_id = self.create_new_id()
        else:
            self.trace_id = trace_name
        self.config_path = self._test_path("config.yml")
        if create:
            self.stagenames = instrumentation_task['stages']
            self.hwname = instrumentation_task['hw']
            self.tracenames = instrumentation_task['traces']
        else:
            with open(self.config_path, 'r') as f:
                settings = yaml.load(f)
                self.stagenames = settings['stages']
                self.hwname = settings['hw']
                self.tracenames = settings['traces']
        self.hw = Main.get_hardwareclass_config().hardware_type_cfgs[self.hwname]
        self.stages = [Main.stage_from_name(s) for s in self.stagenames]
        self.name = "%s.%s.%s" % (self.hwname,
                                  "-".join(self.tracenames), "-".join(self.stagenames))
        self.namefile = self._test_path(self.name)

        Main.set_config("trace_name", self.name)
        Main.set_config("trace_stages", self.stages)
        Main.set_config("trace_hw", self.hw)
        Main.set_config("trace_traces", self.tracenames)
        Main.set_config("trace_id", self.trace_id)
        self.task_adders = [self._setup_tasks, self._collect_data]
        self._add_tasks()

    def _format_id(self, num):
        return str(num).zfill(8)

    def create_new_id(self):
        num = 0
        existing = sorted(self.existing_trace_ids())
        if len(existing) == 0:
            return self._format_id(0)
        while True:
            if self._format_id(num) in existing:
                num += 1
            else:
                break
        return self._format_id(num)

    def existing_trace_ids(self):
        for f in glob.glob("%s/*" % self._dest_dir_root_path()):
            if os.path.isdir(f):
                yield os.path.basename(f)

    def _dest_dir_root_path(self, rel=""):
        return os.path.join(self.test_root, "trace_data", rel)

    def _test_path(self, rel=""):
        return os.path.join(self._dest_dir_root_path(self.trace_id), rel)

    def _setup_tasks(self):
        tasks = []
        deps = []
        if not MkdirTask.exists(self._test_path()):
            tasks.append(self._mkdir(self._test_path()))
        tasks.append(self.save_config("trace_data_root", self._test_path()))
        symlink_dir = os.path.join(self.test_root,
                                   "test_data-by_name", self.name)
        if not MkdirTask.exists(symlink_dir):
            tasks.append(self._mkdir(symlink_dir))
        if not os.path.exists(symlink_dir):
            tasks.append(CmdTask(["ln -s %s %s" % (self._test_path(),
                                                   symlink_dir)],
                                 [], [], "make_name_symlink"))
        tasks.append(self.save_config("trace_data_dir", self._test_path()))
        contents = """
stages: [{}]
hw: {}
traces: [{}]
"""
        filecontents = contents.format(", ".join(self.stagenames), self.hwname,
                                       ", ".join(self.tracenames))

        def write(f, c):
            with open(f, "w") as fconfig:
                fconfig.write(c)
        Main.set_config("test_config_file", self.config_path)
        #Do(filecontents, self.config_path)],
        a = ActionListTask([(write, [self.config_path, filecontents])],
                           [], [self.config_path], "test_config_file")
        tasks.append(a)
        c = CmdTask(["touch %s" % self.namefile], [],
                    [self.namefile], "test_name_file")
        c.other = {'uptodate': [False]}
        tasks.append(c)
        return tasks

    def _writes(self):
        tasks = []
        Main.set_config('trace_stages', self.stages)
        tasks.extend(self._collect_writes_data())
        return tasks

    def _collect_data(self):
        gdb_commands = []
        done_commands = []
        done_targets = []
        gdb_file_dep = []
        gdb_targets = []
        gdb_tasks = []
        handler_path = os.path.join(Main.hw_info_path, Main.hardwareclass, Main.task_handlers)
        sys.path.append(os.path.dirname(handler_path))
        name = re.sub(".py", "", os.path.basename(handler_path))
        mod = importlib.import_module(name)
        if "watchpoint" in self.tracenames and len(self.tracenames) > 1:
            raise Exception("watchpoints cannot be combined with breakpoint-type traces")
        config = {}
        if hasattr(mod, self.hwname):
            handler = getattr(mod, self.hwname)
            stages_with_policies = Main.get_config("stages_with_policies")
            policies = {s: Main.get_config("policy_name", s) for s in stages_with_policies}
            test_id = Main.get_config("test_instance_id")
            handler_tasks = handler(Main, Main.get_bootloader_cfg(),
                                    self.stages,
                                    policies,
                                    self.hw,
                                    Main.object_config_lookup("Software",
                                                              self.hw.host_software),
                                    test_id,
                                    self.trace_id,
                                    self._test_path(),
                                    "watchpoint" in self.tracenames,
                                    self.quick)

            (newtask, c, g, gdep,
             gtargets, d, dtargets) = self._process_handler(handler_tasks,
                                                            "hardware_handler", True)
            newtask.file_dep.extend([Main.get_config("test_config_file")])
            config.update(c)
            # ignore any gdb/done commands/deps/targets
            hwtaskname = newtask.name
        for tracename in self.hw.tracing_methods:
            if not hasattr(mod, tracename):
                continue
            trace_task_handler = getattr(mod, tracename)
            trace_output = trace_task_handler(Main,
                                              config,
                                              self.stages,
                                              policies,
                                              test_id,
                                              self.trace_id,
                                              self._test_path(),
                                              self.quick)
            (ttask, c, g, gdep,
             gtargets, d,
             dtargets) = self._process_handler(trace_output,
                                               "tracing_hardware_handler-%s" % tracename,
                                               tracename in self.tracenames)
            config.update(c)
            if tracename in self.tracenames:
                if g:
                    if gdb_commands:
                        gdb_commands.extend(g[1:])
                    else:
                        gdb_commands = g
                    gdb_tasks.append(newtask)
                    done_commands.extend(d)
                    gdb_file_dep.extend(gdep)
                    gdb_targets.extend(gtargets)
                    done_targets.extend(dtargets)
                else:
                    newtask.actions.extend(d)
                    newtask.targets.extend(dtargets)
                    newtask = self.merge_tasks(newtask, ttask)
        if gdb_commands:
            gdb = " ".join(gdb_commands)
            gdb += " -ex 'c' -ex 'monitor quit' -ex 'q'"
            print "gdb cmd: %s" % gdb
            c = CmdTask([Interactive(gdb)] + done_commands,
                        gdb_file_dep,
                        gdb_targets + done_targets, "gdb_tracing")
            newtask = self.merge_tasks(newtask, c)
        sys.path.pop()

        return [newtask]

    def merge_tasks(self, t1, t2):
        for i in ["file_dep", "actions", "targets"]:
            getattr(t1, i).extend(getattr(t2, i))
        t1.other.update(t2.other)
        return t1

    def _process_handler(self, handler_tasks, name, save):
        deps = []
        targets = []
        actions = []
        configs = {}
        gdb_commands = []
        done_commands = []
        gdb_targets = []
        gdb_file_dep = []
        done_targets = []
        for (n, c) in handler_tasks:
            a = None
            if n == "long_running":
                a = LongRunning(c)
            elif n == "interactive":
                a = Interactive(c)
            elif n == "set_config":
                for (k, v) in c.iteritems():
                    Main.set_config(k, v)
            elif n == "command":
                a = c
            elif n == "configs":
                configs.update(c)
            elif n == "targets":
                targets.extend(c)
            elif n == "gdb_commands":
                gdb_commands.extend(c)
            elif n == "file_dep":
                deps.extend(c)
            elif n == "done_commands":
                done_commands.extend(c)
            elif n == "gdb_targets":
                gdb_targets.extend(c)
            elif n == "done_targets":
                done_targets.extend(c)
            elif n == "gdb_file_dep":
                gdb_file_dep.extend(c)
            else:
                raise Exception("unknown hardware trace handler tag '%s' (%s)" % (n, c))
            if a:
                actions.append(a)

        task = ActionListTask(actions, deps,
                              targets, name)
        return (task, configs, gdb_commands,
                gdb_file_dep,
                gdb_targets, done_commands, done_targets)


class InstrumentationTaskLoader(ResultsLoader):
    def __init__(self, boot_task, test_id,
                 enabled_stages, create):
        super(InstrumentationTaskLoader, self).__init__(test_id, "instance", create)
        self.create = create
        self.enabled_stages = enabled_stages
        self.bootloader = Main.get_bootloader_cfg()
        self.test_data_path = Main.test_data_path
        self.bootloader_path = boot_task.root_dir
        Main.set_config("bootloader_path",  self.bootloader_path)
        self.boot_stages = Main.config_class_lookup("Bootstages")
        self.hardwareclass = Main.get_hardwareclass_config()
        self.test_id = test_id
        hwname = Main.get_hardwareclass_config().name
        bootname = Main.get_bootloader_cfg().software
        hdir = os.path.join(Main.hw_info_path, hwname)
        bootdir = os.path.join(hdir, bootname)
        Main.set_config("test_instance_id", test_id)
        self.default_file_paths = {"hwinfo": hdir,
                                   "reglist": os.path.join(hdir, "regs.csv"),
                                   "bootloaderdata": bootdir}
        Main.set_config("bootloader_data_dir",  bootdir)
        self.task_adders = [self._image_tasks, self._reg_tasks, self._qemu_tasks,
                            self._staticanalysis_tasks, self._addr_map_tasks]
        self._add_tasks()

    def _full_path(self, rel=""):
        return os.path.join(self.test_data_path, self.test_id, rel)

    def _boot_src_path(self, rel=""):
        return os.path.join(self.bootloader_path, rel)

    def _suite_src_path(self, rel=""):
        return os.path.join(Main.config.test_suite_path, rel)

    def _qemu_tasks(self):
        tasks = []
        bootinfo = self.default_file_paths["bootloaderdata"]
        tracefile = {}
        d = self._full_path("qemu-events")
        tasks.append(self._mkdir(d))
        for s in self.boot_stages:
            tracefile_src = os.path.join(bootinfo, s.stagename,
                                         "%s-events" % s.stagename)
            tracefile[s.stagename] = os.path.join(d,
                                                  "%s-events" % s.stagename)
            tasks.append(self._copy_file(tracefile_src, tracefile[s.stagename]))
        Main.set_config("trace_events_file", lambda s: tracefile[s.stagename])
        all_events = os.path.join(Main.object_config_lookup("Software",
                                                            "qemu").root, "trace-events")
        cached_events = self._full_path("qemu-trace-events")
        tasks.append(self._copy_file(all_events, cached_events))
        tasks.append(self.save_config("all_qemu_evnts", cached_events))
        return tasks

    def _reg_tasks(self):
        tasks = []
        regkey = "reglist"
        reglist = self._full_path("regs.csv")
        default_reglist = self.default_file_paths[regkey]
        pdf = Main.get_hardwareclass_config().tech_reference
        deps = [pdf]

        def regaction():
            if os.path.exists(default_reglist):
                deps.append(default_reglist)
            else:
                # recreate default reglist
                parse_am37x_register_tables.parse(pdf, default_reglist)

            return os.system("cp %s %s" % (default_reglist, reglist)) == 0
        tasks.append(self.save_config(regkey, reglist))
        rtask = ActionListTask([(regaction, )], deps, [reglist], "create_reg_csv")
        tasks.append(rtask)
        return tasks

    def _addr_map_tasks(self):
        tasks = []
        if not MkdirTask.exists(self.test_data_path):
            tasks.append(self._mkdir(self.test_data_path))
        dstdir = self._full_path("mmap")
        actions = []
        tasks.append(self.save_config("mmap_dir", dstdir))
        if not MkdirTask.exists(dstdir):
            tasks.append(self._mkdir(dstdir))
        mmapdb_path = os.path.join(dstdir, "mmap.h5")
        mmapdb_done_path = os.path.join(dstdir, "mmap.completed")
        tasks.append(self.save_config("mmapdb", mmapdb_path))
        tasks.append(self.save_config("mmapdb_done", mmapdb_done_path))

        class addr_space_setup():
            def __call__(self):
                done_target = Main.get_config("mmapdb_done")
                target = Main.get_config("mmapdb")
                if os.path.exists(target):
                    os.remove(target)
                db_info.create("any", "mmapdb")
                return os.system("touch %s" % done_target) == 0
        a = DelTargetAction(addr_space_setup())

        actions.append(a)
        deps = [Main.get_config("stage_elf", s) for s in Main.get_config('enabled_stages')]

        rtask = ActionListTask(actions, deps,
                               [mmapdb_path, mmapdb_done_path], "generate_addr_info")
        tasks.append(rtask)
        return tasks

    def _staticanalysis_tasks(self):
        tasks = []
        # db name for each stage
        staticdb = {}
        staticdb_done = {}
        for s in Main.get_config('enabled_stages'):
            staticdb[s.stagename] = self._full_path("static-analysis-%s.h5" % s.stagename)
            staticdb_done[s.stagename] = self._full_path("static-analysis-%s.completed"
                                                         % s.stagename)

        def getstaticdb(s):
            return staticdb[s.stagename]

        def getstaticdb_done(s):
            return staticdb_done[s.stagename]
        Main.set_config("staticdb", getstaticdb)
        Main.set_config("staticdb_done", getstaticdb_done)

        # calculate thumb ranges on demand
        def get_thumb_ranges(stage):
            n = stage.stagename
            flatkey = "%s_%s" % ("thumb_ranges", n)
            v = Main.get_config(flatkey)
            if v is None:
                # calculate and add
                v = staticanalysis.ThumbRanges.find_thumb_ranges(stage)
                Main.set_config(flatkey, v)
            return v

        Main.set_config("thumb_ranges", get_thumb_ranges)

        # calculate labels on demand
        def get_labels():
            internal = "labels_internal"
            v = Main.get_config(internal)
            if v is None:
                v = labeltool.get_all_labels(Main.get_bootloader_root())
                Main.set_config(internal, v)
            return v

        Main.set_config("labels", get_labels)
        for s in Main.get_config('enabled_stages'):
            n = s.stagename
            target = staticdb[n]
            done_target = staticdb_done[n]

            class run_analysis():
                def __init__(self, stage):
                    self.stage = stage

                def __call__(self):
                    target = Main.get_config("staticdb", self.stage)
                    if os.path.exists(target):
                        os.remove(target)
                    done_target = Main.get_config('staticdb_done', self.stage)
                    db_info.create(self.stage, "staticdb")
                    return os.system("touch %s" % done_target) == 0
            a = DelTargetAction(run_analysis(s))
            actions = [a]
            rtask = ActionListTask(actions,
                                   [Main.get_config("stage_elf", s)],
                                   [target, done_target], "staticanalysis_%s" % n)
            tasks.append(rtask)
        return tasks

    def _image_tasks(self):
        tasks = []
        if not MkdirTask.exists(self.test_data_path):
            tasks.append(self._mkdir(self.test_data_path))
        if not MkdirTask.exists(self._full_path()):
            tasks.append(self._mkdir(self._full_path()))
        tasks.append(self.save_config("test_instance_root", self._full_path()))
        dstdir = self._full_path("images")
        if not MkdirTask.exists(dstdir):
            tasks.append(self._mkdir(dstdir))
        bootimages = []
        bootelfs = []
        imgsrcs = []
        elfdst = {}
        imgdst = {}
        for i in self.boot_stages:
            bootelfs.append(self._boot_src_path(i.elf))
            bootimages.append(self._boot_src_path(i.image))
            elfdst[i.stagename] = os.path.join(dstdir, os.path.basename(i.elf))
            imgdst[i.stagename] = os.path.join(dstdir, os.path.basename(i.image))

        Main.set_config("stage_elf", lambda s: elfdst[s.stagename])
        Main.set_config("stage_image", lambda s: imgdst[s.stagename])
        tocpy = bootelfs + bootimages
        tasks.extend([self._copy_file(i,
                                      os.path.join(dstdir, os.path.basename(i)))
                      for i in tocpy])
        sdtarget = os.path.join(dstdir, "sd.img")
        sdskeleton = self.hardwareclass.sdskeleton
        tmpdir = tempfile.mkdtemp()
        tmpmnt = os.path.join(tmpdir, "mnt")
        tmpsd = os.path.join(tmpdir, "sd.img")
        cp = "cp %s %s" % (sdskeleton, tmpsd)
        mkdir = "mkdir -p %s" % (tmpmnt)
        mnt = "sudo mount -o loop,offset=%d %s %s" % (512*63, tmpsd, tmpmnt)
        update_mnt = []
        for i in imgdst.itervalues():
            update_mnt.append("sudo cp %s %s" % (i,
                                            tmpmnt))
        umount = "sudo umount %s" % tmpmnt
        cp_final = "cp %s %s" % (tmpsd, sdtarget)
        rmtmp = "sudo rm -r %s" % tmpdir
        cmds = [cp, mkdir, mnt] + update_mnt + [umount, cp_final, rmtmp]
        tasks.append(self.save_config('sd_image', sdtarget))
        deps = []
        for f in imgdst.itervalues():
            deps.append(f)
        mksd = CmdTask(cmds,
                       deps,
                       [sdtarget],
                       "sd_card_image")
        if not self.create:
            mksd.uptodate = [True]
        tasks.append(mksd)
        if 'all' in self.enabled_stages or self.enabled_stages is None:
            Main.set_config('enabled_stages',
                            list(Main.get_bootloader_cfg().supported_stages.itervalues()))
        else:
            ss = [v for v in
                  Main.get_bootloader_cfg().supported_stages.itervalues()
                  if v.stagename in self.enabled_stages]
            Main.set_config('enabled_stages', ss)
        for stage in Main.get_bootloader_cfg().supported_stages.itervalues():
            for t in ["elf", "image"]:
                e = elfdst[stage.stagename]
                if os.path.exists(e):
                    setattr(stage, t, e)
        for stage in Main.get_config('enabled_stages'):
            stage.post_build_setup()

        return tasks


class PolicyTaskLoader(ResultsLoader):
    def __init__(self, policies, run_tasks):
        print "policy task loader run %s" % run_tasks
        test_id = Main.get_config("test_instance_id")
        test_ = Main.get_config("test_instance_id")
        super(PolicyTaskLoader, self).__init__(test_id, "policy", run_tasks)
        self.policies = policies
        self.instance_dir = Main.get_config("test_instance_root")
        self.task_adders = [self._policy_tasks]
        self._add_tasks()

    def _policy_root(self, rel=""):
        return os.path.join(self.instance_dir, 'policies', rel)

    def _full_path(self, stage, rel=""):
        return os.path.join(self._policy_root(), stage.stagename, rel)

    def _policy_tasks(self):
        tasks = []
        policies = {}
        regions = {}
        names = {}
        dbs = {}
        dbs_done = {}
        pname = "substages.yml"
        rname = "memory_map.yml"
        if not MkdirTask.exists(self._policy_root()):
            tasks.append(self._mkdir(self._policy_root()))
        stages_with_policies = []
        for s in Main.get_config('enabled_stages'):
            s_policy = None
            s_regions = None
            n = s.stagename
            policy_file_name = "substages-%s.yml" % n
            regions_file_name = "memory_map-%s.yml" % n
            policystagedir = self._full_path(s)
            if not MkdirTask.exists(self._full_path(s)):
                tasks.append(self._mkdir(policy_file_name))

            stages_with_policies.append(s)
            if n not in self.policies:
                policy_entry = None
            else:
                policy_entry = self.policies[n]
            if type(policy_entry) == str:
                substagedatadir = os.path.join(policystagedir, policy_entry)
                s_policy = os.path.join(substagedatadir, policy_file_name)
                s_regions = os.path.join(substagedatadir, regions_file_name)
            elif policy_entry is None:
                # choose a default
                policy_dir = self._full_path(s)
                # choose any file in dir
                choices = glob.glob(policy_dir + "/*")
                for c in choices:
                    d = os.path.basename(c)
                    if d.startswith("."):
                        continue
                    if os.path.isdir(c):
                        s_policy = os.path.join(c, pname)
                        s_regions = os.path.join(c, rname)
                        if os.path.isfile(s_policy) and \
                           os.path.isfile(s_regions):
                            break
            else:
                s_policy = policy_entry[0]  # self.policies[n][0]
                s_regions = policy_entry[1]  # self.policies[n][1]
            pdir = os.path.join(Main.get_config("bootloader_data_dir"), n)
            if s_policy is None or not os.path.exists(s_policy):  # use default
                s_policy = os.path.join(pdir, pname)
            if s_regions is None or not os.path.exists(s_regions):  # use default
                s_regions = os.path.join(pdir, rname)
            names[n] = substage.SubstagesInfo.calculate_name_from_files(s_policy, s_regions)
            datadir = os.path.join(policystagedir, names[n])
            policies[n] = os.path.join(datadir, policy_file_name)
            regions[n] = os.path.join(datadir, regions_file_name)
            dbs_done[n] = os.path.join(datadir, "policy-%s.completed" % n)
            dbs[n] = os.path.join(datadir, "policy-%s.h5" % n)
            if not MkdirTask.exists(datadir):
                tasks.append(self._mkdir(datadir, "%s_data" % n))
            tasks.append(self._copy_file(s_policy,
                                         policies[n], "%s_policy" % n))
            tasks.append(self._copy_file(s_regions,
                                         regions[n], "%s_regions" % n))

        Main.set_config("policy_file", lambda s: policies[s.stagename])
        Main.set_config("regions_file", lambda s: regions[s.stagename])
        Main.set_config("policy_name", lambda s: names[s.stagename])
        Main.set_config("policy_db", lambda s: dbs[s.stagename])
        Main.set_config("policy_db_done", lambda s: dbs_done[s.stagename])
        Main.set_config("stages_with_policies", stages_with_policies)
        for s in Main.get_config('enabled_stages'):

            n = s.stagename
            if n not in self.policies:
                continue

            class setup_policy():
                def __init__(self, stage):
                    self.stage = stage

                def __call__(self):
                    target = Main.get_config("policy_db", self.stage)
                    if os.path.exists(target):
                        os.remove(target)

                    d = Main.get_config("policy_db_done", self.stage)
                    db_info.create(self.stage, "policydb")
                    os.system("touch %s" % d)
            pdb_done = Main.get_config("policy_db_done", s)
            target = Main.get_config("policy_db", s)
            at = DelTargetAction(setup_policy(s))
            actions = [at]
            staticdb_done = Main.get_config("staticdb_done", s)
            staticdb = Main.get_config("staticdb", s)
            mmapdb_done = Main.get_config("mmapdb_done")
            mmapdb = Main.get_config("mmapdb")
            a = ActionListTask(actions,
                               [mmapdb_done, mmapdb, staticdb_done,
                                staticdb, policies[n], regions[n]],
                               [target, pdb_done],
                               "create_%s_policy_db" % n)
            tasks.append(a)
        return tasks
