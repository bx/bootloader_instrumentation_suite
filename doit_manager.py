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

import external_source_manager
import instrumentation_results_manager
from doit.cmd_base import ModuleTaskLoader, TaskLoader
from doit.doit_cmd import DoitMain
from doit.cmd_base import Command
from doit.action import CmdAction
from config import Main
import pure_utils
import sys
import os
import glob


class TaskManager():
    loaders = []
    tasks = {}

    def __init__(self, do_build, create_test, enabled_stages,
                 policies, quick, run_trace, select_trace, import_policies,
                 post_trace_processing=[], open_instance=None, run=True,
                 print_cmds=False):
        if not do_build:
            (print_build_cmd, build_source) = ([], [])
        else:
            (print_build_cmd, build_source) = do_build
        self.create_test = create_test
        # run = run_trace is not None
        bootloader_only = len(build_source) == 0
        self.print_cmds = print_cmds
        self.src_manager = external_source_manager.SourceLoader(print_build_cmd, build_source)
        self.loaders.append(self.src_manager)
        if len(print_build_cmd) + len(build_source) > 0:
            return
        bootloader = Main.get_bootloader_cfg()
        self.boot_task = [s for s in self.src_manager.code_tasks
                          if s.build_cfg.name == bootloader.software][0]
        if create_test:
            if not self.boot_task.has_nothing_to_commit():
                self.boot_task.commit_changes()
            # rebuild bootloader now to ensure we have its elf/images available
            #self.boot_task.build.uptodate = [False]
            self.src_manager.builds.append(bootloader.software)
            (self.test_id, gitinfo) = self._calculate_current_id()
            current_id = self.test_id
            self.build(self.boot_task.basename, True)
        else:
            if open_instance is None:
                self.test_id = self._get_newest_id()
            else:
                self.test_id = open_instance
            self.boot_task.build.uptodate = [True]
            (current_id, gitinfo) = self._calculate_current_id()

        update_existing = (create_test or (current_id == self.test_id)) \
                          and (len(post_trace_processing) == 0)
        self.ti = instrumentation_results_manager.InstrumentationTaskLoader(self.boot_task,
                                                                            self.test_id,
                                                                            enabled_stages,
                                                                            create_test,
                                                                            gitinfo)

        instrumentation_results_manager.PolicyTaskLoader(policies,
                                                         (create_test and not print_cmds) or import_policies or len(post_trace_processing) > 0)


        if create_test:
            self.loaders.append(instrumentation_results_manager.task_manager())
            return
        trace_create = False
        if run_trace:
            trace_create = True

        trace = True
        if (len(post_trace_processing) > 0) or create_test or import_policies:
            trace = False
        if create_test:
            trace_create = True
        self.rt = instrumentation_results_manager.TraceTaskLoader(run_trace,
                                                                  select_trace,
                                                                  trace_create,
                                                                  quick,
                                                                  trace and not self.print_cmds,
                                                                  self.print_cmds)
        if post_trace_processing:
            self.pt = instrumentation_results_manager.PostTraceLoader(post_trace_processing)
        self.loaders.append(instrumentation_results_manager.task_manager())

    def _get_newest_id(self):
        root = Main.test_data_path
        choices = glob.glob(root + "/*")
        newest = None
        newest_time = 0
        for i in choices:
            itime = os.stat(i).st_ctime
            if itime > newest_time:
                newest = i
                newest_time = itime
        n = os.path.basename(newest)
        return n

    def _calculate_current_id(self):
        (gitid,  sha) = self.boot_task.get_gitinfo()
        cc = Main.cc
        cc_name = self.boot_task.build_cfg.compiler_name
        ccpath = "%s%s" % (cc, cc_name)
        defconfig = Main.get_bootloader_cfg().makecfg
        hwclass = Main.get_hardwareclass_config().name
        bootsoftware = self.boot_task.build_cfg.name
        ccinfo = pure_utils.file_md5(ccpath)
        gitinfo = {'local': self.boot_task.build_cfg.root,
                   'sha1': sha}
        return ("%s.%s.%s.%s.%s" % (hwclass, bootsoftware, defconfig, gitid, ccinfo),
                gitinfo)

    def build(self, targets, do_build=True):
        if do_build:
            makes = [external_source_manager.CodeTask.get_task_name(b, "build") for b in targets]
            return self.run(makes)
        else:
            rets = []
            for t in self.src_manager.code_tasks:
                if t.basename in targets:
                    rets.append(t)
            return rets

    def run(self, cmds):
        tasks = {}
        for v in self.loaders:
            for name, l in v.list_tasks():
                f = l
                tasks[name] = f
        ml = ModuleTaskLoader(tasks)
        main = DoitMain(ml)
        main.config['default_tasks'] = cmds
        main.config['verbose'] = 2
        main.config['verbosity'] = 2
        return main.run([])

    def create_test_instance(self):
        nm = self.ti.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret

    def run_trace(self):

        if self.print_cmds:
            return 0
        nm = self.rt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret

    def postprocess_trace(self):
        nm = self.pt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret
