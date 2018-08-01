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
import difflib
import yaml
from datetime import datetime
from enum import Enum
from run_cmds import cmds


class ManagerException(Exception):
    pass


class TaskManager():
    loaders = []
    tasks = {}

    def __init__(self, command, instance, trace, host=None,
                 trace_list=[], stages=[],
                 policies={}, post_trace_processes=[],
                 rm_dir=True, quick=False, args=None, verbose=False):
        self.verbose = verbose
        if command == cmds.list_instances:
            print "Test instances"
            for i in self._get_all_ids():
                path = os.path.join(Main.test_data_path, i)
                time = os.stat(i).st_ctime
                timestr = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
                print "%s\t%s" % (timestr, i)
            return

        stages = [Main.stage_from_name(s) for s in stages]
        printonly = True if command in [cmds.print_build_commands, cmds.build_software] else False
        build = args if printonly else []
        if command == cmds.create:
            build = [Main.target_software.name]

        self.src_manager = external_source_manager.SourceLoader(build, printonly)
        self.loaders.append(self.src_manager)
        if command in [cmds.print_build_commands, cmds.build_software]:
            return

        self.target_task = [s for s in self.src_manager.code_tasks
                            if s.build_cfg.name == Main.target_software.name][0]

        if command == cmds.create:
            if not self.target_task.has_nothing_to_commit():
                self.target_task.commit_changes()
            (instance_id, gitinfo) = self._calculate_current_id()
        else:
            self.target_task.build.uptodate = [True]
            gitinfo = None
            create_trace = False
            if instance is None:
                instance_id = self._get_newest_id()
            else:
                ids = self._get_all_ids()
                if instance not in ids:
                    instance = difflib.get_close_matches(instance,
                                                 ids, 1, 0)[0]
                    instance_id = os.path.basename(instance)
                else:
                    instance_id = instance
            if command == cmds.list_test_runs:
                print "-- Test traces for instance '%s' --" % instance_id
                for (time, name, ran) in instrumentation_results_manager.TraceTaskPrepLoader._existing_trace_ids(instance_id, True):
                    print "%s\t%s (data collected: %s)" % (time, name, ran)
                return
            if command in [cmds.run_new_trace, cmds.setup_trace]:
                # create a new trace
                create_trace = True
                trace = []
            elif command in [cmds.list_policies, cmds.import_policy, cmds.do_trace, cmds.print_trace_commands,
                             cmds.postprocess_trace, cmds.hook]:
                create_trace = False
            # lookup existing trace
            trace_id = instrumentation_results_manager.TraceTaskPrepLoader.get_trace_name(instance_id,
                                                                                          trace,
                                                                                          create=create_trace)
            run_trace = False
            if command in [cmds.run_new_trace, cmds.do_trace]:
                run_trace = True
            if not policies:
                policies = instrumentation_results_manager.PolicyTaskLoader.default_policies(instance_id, stages)

        self.ti = instrumentation_results_manager.InstrumentationTaskLoader(self.target_task,
                                                                            instance_id,
                                                                            self,
                                                                            command == cmds.create,
                                                                            gitinfo,
                                                                            rm_dir)

        if command == cmds.create:
            self.pt = instrumentation_results_manager.PolicyTaskLoader(False, policies)
            self.loaders.append(instrumentation_results_manager.task_manager(verbose))
            return


        if command in [cmds.list_policies, cmds.import_policy]:
            self.pt = instrumentation_results_manager.PolicyTaskLoader(command == cmds.import_policy,
                                                                       policies)
            if cmds.import_policy:
               self.loaders.append(instrumentation_results_manager.task_manager(verbose))
               return
            print "-- Avilable policies for instance '%s' --" % instance_id
            for s in Main.stages:
                print "Stage %s:" % s.stagename
                rt = self.pt._policy_root(s)
                for f in glob.glob("%s/*" % rt):
                    if os.path.isdir(f):
                        t = os.stat(f).st_ctime
                        timestr = datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')
                        print "%s\t%s" % (timestr, os.path.basename(f))
            return

        self.tp = instrumentation_results_manager.TraceTaskPrepLoader(trace_id,
                                                                      create_trace,
                                                                      run_trace,
                                                                      command == cmds.print_trace_commands,
                                                                      stages,
                                                                      trace_list,
                                                                      host,
                                                                      False)
        self.pt = instrumentation_results_manager.PolicyTaskLoader(command == cmds.import_policy,
                                                                   policies)

        self.rt = instrumentation_results_manager.TraceTaskLoader(create_trace,
                                                                  run_trace,
                                                                  command == cmds.print_trace_commands,
                                                                  quick)
        if command in [cmds.postprocess_trace, cmds.hook]:
            self.ppt = instrumentation_results_manager.PostTraceLoader(post_trace_processes,
                                                                       command==cmds.postprocess_trace)
        else:
            self.ppt = None
        self.loaders.append(instrumentation_results_manager.task_manager(verbose))

    def _get_all_ids(self):
        root = Main.test_data_path
        return glob.glob(root + "/*")

    def _get_newest_id(self):
        choices = self._get_all_ids()
        newest = None
        newest_time = 0
        for i in choices:
            if not os.path.isdir(i):
                continue
            itime = os.stat(i).st_ctime
            if itime > newest_time:
                newest = i
                newest_time = itime
        n = os.path.basename(newest)
        return n

    def _calculate_current_id(self):
        (gitid,  sha) = self.target_task.get_gitinfo()
        ccpath = self.target_task.build_cfg.compiler
        #ccpath = "%s%s" % (cc, cc_name)
        if hasattr(Main.target, "makecfg"):
            defconfig = Main.target.makecfg
        else:
            defconfig = ""
        hwclass = Main.get_hardwareclass_config().name
        targetsoftware = self.target_task.build_cfg.name
        ccinfo = pure_utils.file_md5(ccpath)
        gitinfo = {'local': self.target_task.build_cfg.root,
                   'sha1': sha}
        return ("%s.%s.%s.%s.%s" % (hwclass, targetsoftware, defconfig, gitid, ccinfo),
                gitinfo)

    def build(self, targets, do_build=True):
        if do_build:
            makes = [external_source_manager.CodeTask.get_task_name(b, "build") for b in targets]
            self.run(makes)
            return []
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
        return main.run([])

    def create_test_instance(self):
        nm = self.ti.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret

    def import_policy(self):
        #tp = self.tp.get_build_name()
        nm = self.pt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret

    def run_trace(self):
        ti = self.ti.get_build_name()
        tp = self.tp.get_build_name()
        nm = self.rt.get_build_name()
        ip = self.pt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([ti, tp, ip, nm])
        return ret


    def postprocess_trace(self):
        nm = self.ppt.get_build_name()
        print "about to run %s" % nm
        ret = self.run([nm])
        return ret
