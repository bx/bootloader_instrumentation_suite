#!/usr/bin/env python2
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
from doit.action import CmdAction
import argparse
import os
import run_cmd
import sys
import doit_manager
import instrumentation_results_manager


def go():
    parser = argparse.ArgumentParser("Target test suite")
    cmds = parser.add_mutually_exclusive_group()

    class SubstageFileAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            self.stages = Main.stages
            self.stagenames = [s.stagename for s in self.stages]
            if len(self.stages) == 1:
                self.nargs = 2
            else:
                self.nargs = 3

            name = Main.get_hardwareclass_config().name
            path = Main.get_hardwareclass_config().hw_info_path
            defaultdir = os.path.join(Main.get_hardwareclass_config().hw_info_path, name)
                                      
            self.sdefaults = {}
            kwargs['default'] = self.sdefaults
            super(SubstageFileAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            stagename = values[0]
            f = os.path.abspath(values[1])
            d = os.path.abspath(values[2])
            if stagename not in self.stagenames:
                raise argparse.ArgumentError(self,
                                             "%s not a valid stage, must be one of %s" %
                                             (stagename, str(self.stagenames)))
            if not os.path.exists(f):
                raise argparse.ArgumentError("Substage definition file I am trying to import from '%s' not found" % f)
            if not os.path.exists(d):
                raise argparse.ArgumentError("Region definition file I am trying to import from '%s' not found" % d)

            getattr(namespace, self.dest)[stagename] = (f, d)

    class SubstageNameAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            stages = Main.stages            
            self.stagenames = [s.stagename for s in stages]
            self.nargs = 2
            defaults = {}
            kwargs['default'] = defaults
            super(SubstageNameAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            stagename = values[0]
            policy_name = values[1]
            if stagename not in self.stagenames:
                raise argparse.ArgumentError(self,
                                             "%s not a valid stage, must be one of %s" %
                                             (stagename, str(self.stagenames)))
            getattr(namespace, self.dest)[stagename] = policy_name

    cmds.add_argument('-c', '--create',
                      help='Create new result directory for current instance of '\
                      'software specified in configuration',
                      action='store_true', default=False)

    cmds.add_argument('-I', '--import_policy',
                      help="Import policy (substage and region definitions) into instance. ' \
                      'Requires stage name, path to file containing proposed substages, "
                      "and path to file containing region info", nargs="*", default={},
                      action=SubstageFileAction)
    cmds.add_argument('-L', '--list_policies', default=False, action="store_true",
                      help="Lists instance's imported policies",)

    cmds.add_argument('-B', '--build_software',
                      help="Name of software to clean, update git tree, "
                      "and build (openocd, u-boot, qemu))",
                      action="append", default=[])
    cmds.add_argument('-b', '--print_build_commands',
                      help="Print build commands for software",
                      default=[], action="append")
    cmds.add_argument('-S', '--setup_trace', action="store_true",
                      default=False)
    cmds.add_argument('-R', '--run_new_trace', action="store_true",
                      default=False)
    cmds.add_argument('-D', '--do_trace', action="store_true",
                      help="Performs trace if not already performed",
                      default=False)
    cmds.add_argument('--list_instances', action="store_true",
                      default=False)
    cmds.add_argument('-l', '--list_test_runs', action="store_true",
                      default=False)
    cmds.add_argument('-p', '--postprocess_trace', default=[], action="append",
                      choices=instrumentation_results_manager.PostTraceLoader.supported_types,
                      help="Run trace postprocessing command")
    cmds.add_argument('-P', '--print_trace_commands', action='store_true',
                        help='Prints commands used to produce trace')

    parser.add_argument('-i', '--select_instance',
                        help='Name test instance use, " \
                        "by default we use newest',
                        action='store', default=None)
    c = Main.get_hardwareclass_config()
    if not isinstance(c.default_host, str):
        raise Exception("check your configuration, default host should be a string")
    host = Main.object_config_lookup("HostConfig", c.default_host)
    parser.add_argument('-t', '--select_trace', action="store",
                        help="Select existing instance's trace by name")
    parser.add_argument("-T", "--trace_methods", default=host.default_tracing,  action="append",
                        choices=[m.name for m in Main.object_config_lookup("TraceMethod")])
    parser.add_argument('-s', '--stages', action='append', default=[s.stagename for s in Main.default_stages])
    parser.add_argument('-n', '--select_policy', action=SubstageNameAction, nargs=2)
    parser.add_argument('-H', '--host', action="store", default=host.name,
                        choices=[m.name for m in Main.object_config_lookup("HostConfig")])

    parser.add_argument('-k', '--keep_temp_files', action="store_true")
    parser.add_argument('-q', '--quick',
                        help='Try to skip some steps to be faster',
                        action='store_true', default=False)

    args = parser.parse_args()
    args.hook = ""
    other = None
    shell = run_cmd.Cmd()
    cmd = None
    for c in list(doit_manager.cmds):
        n =  c._name_
        if getattr(args, n):
            cmd = c
            break
    if "all" in args.stages:
        args.stages = Main.stages
    if args.print_build_commands or args.build_software:
        other = args.print_build_commands + args.build_software
    if args.import_policy:
        policy = args.import_policy
    else:
        policy = args.import_policy
    task_mgr = doit_manager.TaskManager(cmd,
                                        args.select_instance,
                                        args.select_trace,
                                        args.host,
                                        args.trace_methods,
                                        args.stages,
                                        policy,
                                        args.postprocess_trace,
                                        not args.keep_temp_files,
                                        args.quick,
                                        other)


    # task_mgr = doit_manager.TaskManager(args.print_build_commands,
    #                                     args.build_software,
    #                                     args.create,
    #                                     args.stages,
    #                                     policies,
    #                                     args.quick,
    #                                     args.run_trace,
    #                                     args.select_trace,
    #                                     import_policies,
    #                                     args.postprocess_trace,
    #                                     args.testcfginstance, run,
    #                                     args.print_cmds,
    #                                     rm_dir=not args.keep_temp_files)

    # if args.create or import_policies or args.print_cmds:
    #
    if args.create:
        task_mgr.create_test_instance()
    elif args.import_policy:
        task_mgr.import_policy()
    elif args.run_new_trace:
        task_mgr.run_trace()
    elif args.postprocess_trace:
        task_mgr.postprocess_trace()
    # elif args.run_trace:
    #     task_mgr.run_trace()

    if args.print_trace_commands:
        task_mgr.rt.do_print_cmds()
    #if args.buildcommands or
    if args.print_build_commands or args.build_software  or args.print_build_commands:
        targets = args.build_software if args.build_software else args.print_build_commands
        ret = task_mgr.build(targets, True if args.build_software else False)
        if args.print_build_commands:
            for r in ret:
                for task in r.tasks:
                    print "to %s %s:" % (task.name, task.basename)
                    for action in task.list_tasks()['actions']:
                        if isinstance(action, CmdAction):
                            print "cd %s" % task.root_dir
                            print action.expand_action()
                    print "\n"



if __name__ == '__main__':
    go()
