#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pwn-templates",
    version="2.0.0",
    author="p0ach1l",
    author_email="player@ctf.com",
    description="A tool for generating PWN exploit templates for CTF competitions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.6",
    install_requires=[
        "pwntools>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pwnt=pwn_templates.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "pwn_templates": ["../templates/*.py"],
    },
)
