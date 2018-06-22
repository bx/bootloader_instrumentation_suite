#!/usr/bin/env python
import setuptools
from distutils.core import setup
from setuptools.command.install import install
import pip
from distutils.util import execute
import os
import sys


# this too is a hack, but I am unable to get setuputils to instal a requirement from a subdirectory of the capstone git repository
class PkgInstall(install):
    def run(self):
        install.do_egg_install(self)
        os.system('pip install git+https://github.com/aquynh/capstone@next#subdirectory=bindings/python')


# I'm guessing the following block of commented-out code is not a kosher
# way of installing capstone...
# execute(os.system, ('git clone https://github.com/aquynh/capstone',))
# execute(os.system, ('cd capstone; git checkout -b next',))
# os.environ['PREFIX'] = sys.prefix
# execute(os.system, ('cd capstone; ./make.sh',))
# execute(os.system, ('cd capstone; ./make.sh install',))

setuptools.setup(
    name="fiddle",
    version='0.0.9',
    packages=setuptools.find_packages(),
    license="MIT",
    long_description=open("README").read(),
    author="bx",
    author_email="bx@cs.dartmouth.edu",
    url="https://github.com/bx/bootloader_instrumentation_suite",
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
    cmdclass={'install': PkgInstall},
    package_data={
         'fiddle_extras': [
                           
                           "frama_c/Makefile", "frama_c/machdep_arm.ml",
                           "frama_c/call.ml", "frama_c/dest_analysis.ml",
                           "frama_c/call_analysis.ml"],
         'hw_info': ['bbxm/ocdinit', "bbxm/ocdinit2", "_hw"]
        
    },
    zip_safe=False,
)
