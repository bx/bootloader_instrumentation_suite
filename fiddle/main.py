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
import process_args


def go():
    parser = process_args.FiddleArgParser("Fiddle test suite")
    args = parser.args
    shell = run_cmd.Cmd()
    task_mgr = parser.task_manager()

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
