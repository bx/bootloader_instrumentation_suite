#!/usr/bin/env python

from setuptools import setup
from setuptools.command.build_py import build_py

from setuptools.command.install_lib import install_lib



import pip
from distutils.util import execute
import os
import sys



# this too is a hack, but I am unable to get setuputils to instal a requirement from a subdirectory of the capstone git repository
class PkgBuild(build_py):
    def run(self):
        if not (os.system('pip show capstone') == 0):
            os.system('pip install git+https://github.com/aquynh/capstone@next#subdirectory=bindings/python')
        build_py.run(self)


# class PkgInstall(install_lib):
#     def run(self):
#         install_lib.run(self)
#         pth = os.path.dirname(os.path.realpath(__file__))
#         img = os.path.join(pth, 'fiddle/hw_info/bbxm/beagleboard-xm-orig.img')

#         os.system("cp %s %s" % (img, os.path.join(self.install_base,"fiddle/hw_info/bbxm/")))



# I'm guessing the following block of commented-out code is not a kosher
# way of installing capstone...
# execute(os.system, ('git clone https://github.com/aquynh/capstone',))
# execute(os.system, ('cd capstone; git checkout -b next',))
# os.environ['PREFIX'] = sys.prefix
# execute(os.system, ('cd capstone; ./make.sh',))
# execute(os.system, ('cd capstone; ./make.sh install',))

setup(
    name="fiddle",
    version='0.0.9',
    packages=['fiddle', 'fiddle_gdb', 'fiddle_extra'],
    license="MIT",
    long_description=open("README").read(),
    author="bx",
    author_email="bx@cs.dartmouth.edu",
    url="https://github.com/bx/bootloader_instrumentation_suite",
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'fiddle = fiddle.main:go'
        ],
    },
    install_requires=[
        'doit==0.29.0',
        'PyYAML>=3.11',
        'pathlib',
        'pygit2',
        'pdfminer',
        'ipython',
        'intervaltree',
        'tables',
        'unicorn',
        'numpy',
        'munch',
        'sortedcontainers',
        'ipython==5.7.0',
        'functools32',
        'toml.py',
        'enum34',
        'r2pipe',
    ],
    cmdclass={'build_py': PkgBuild,},
              # 'install_lib': PkgInstall},
    package_data={
        'fiddle_extras': [
            "frama_c/Makefile", "frama_c/machdep_arm.ml",
            "frama_c/call.ml", "frama_c/dest_analysis.ml",
            "frama_c/call_analysis.ml"],
        'fiddle': ['configs/defaults.cfg',
                   'hw_info/bbxm/ocdinit', "hw_info/bbxm/ocdinit2",
                   "hw_info/_hw/test/_single", 'hw_info/bbxm/ocdinit',
                   'hw_info/bbxm.regs.csv', 'hw_info/bbxm/trace-events',
                   'hw_info/bbxm/hw_info.py',
                   'hw_info/bbxm/u_boot/main/main-events',
                   'hw_info/bbxm/u_boot/spl/spl-events',
                   'hw_info/bbxm/am37x_base_memory_map.csv',
                   'hw_info/bbxm/am37x_technical_reference.pdf',
                   'hw_info/bbxm/beagleboard-xm-orig.img'],
    },

)
