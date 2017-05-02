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


class TaskManager():
    loaders = []
    tasks = {}

    def __init__(self, do_build, create_test, enabled_stages,
                 policies, quick, run_trace, select_trace, import_policies,
                 post_trace_processing=[]):
        self.do_build_all = do_build
        self.create_test = create_test
        run = run_trace is not None
        bootloader_only = create_test or run or len(post_trace_processing) > 0
        self.src_manager = external_source_manager.SourceLoader(self.do_build_all, bootloader_only)
        bootloader = Main.get_bootloader_cfg()
        self.boot_task = [s for s in self.src_manager.code_tasks
                          if s.build_cfg.name == bootloader.software][0]
        if not do_build:
            self.boot_task.build.uptodate = [True]
        self.test_id = None
        self.loaders.append(self.src_manager)
        if 'all' in enabled_stages or enabled_stages is None:
            Main.set_config('enabled_stages',
                            list(Main.get_bootloader_cfg().supported_stages.itervalues()))
        else:
            ss = [v for v in
                  Main.get_bootloader_cfg().supported_stages.itervalues()
                  if v.stagename in enabled_stages]
            Main.set_config('enabled_stages', ss)

        Main.set_config('policies', {s: {} for s in Main.get_config('enabled_stages')})
        if create_test:
            if not self.boot_task.has_nothing_to_commit():
                self.boot_task.commit_changes()
                self.boot_task.build.uptodate = [False]
        self.test_id = self._calculate_current_id()
        self.ti = instrumentation_results_manager.InstrumentationTaskLoader(self.boot_task,
                                                                            self.test_id,
                                                                            enabled_stages,
                                                                            create_test)

        for stage in Main.get_config('enabled_stages'):
            stage.elf = Main.get_config('stage_elf', stage)
            stage.image = Main.get_config('stage_image', stage)
            stage.post_build_setup()

        trace_create = False
        if run_trace:
            trace_create = True
        self.py = instrumentation_results_manager.PolicyTaskLoader(policies,
                                                                   import_policies)
        self.rt = instrumentation_results_manager.TraceTaskLoader(run_trace,
                                                                  select_trace,
                                                                  trace_create,
                                                                  quick)
        if post_trace_processing:
            self.pt = instrumentation_results_manager.PostTraceLoader(post_trace_processing)
        self.loaders.append(instrumentation_results_manager.task_manager())

    def _calculate_current_id(self):
        gitid = self.boot_task.get_gitinfo()
        cc = Main.cc
        cc_name = self.boot_task.build_cfg.compiler_name
        ccpath = "%s%s" % (cc, cc_name)
        defconfig = Main.get_bootloader_cfg().makecfg
        hwclass = Main.get_hardwareclass_config().name
        bootsoftware = self.boot_task.build_cfg.name
        ccinfo = pure_utils.file_md5(ccpath)
        return "%s.%s.%s.%s.%s" % (hwclass, bootsoftware, defconfig, gitid, ccinfo)

    def build(self, targets, do_build=True):
        if do_build:
            makes = [external_source_manager.CodeTask.get_task_name(b, "build") for b in targets]

            return self.run(makes)
        else:
            for t in self.src_manager.code_tasks:
                if t.basename in targets:
                    for task in t.tasks:
                        print "to %s %s:" % (task.name, task.basename)
                        for action in task.list_tasks()['actions']:
                            if isinstance(action, CmdAction):
                                print "cd %s" % task.root_dir
                                print action.expand_action()
                        print "\n"
            return 0

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
        nm = self.rt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret

    def postprocess_trace(self):
        nm = self.pt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret
