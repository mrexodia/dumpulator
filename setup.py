#!/usr/bin/env python

# Based on: https://stackoverflow.com/a/62983901/1806760

import setuptools
import os

if __name__ == "__main__":
    ref_name = os.getenv("GITHUB_REF_NAME")
    if ref_name:
        from pkg_resources import parse_version
        try:
            parse_version(ref_name)
            print(f"injecting version = {ref_name} into setup.cfg")
            with open("setup.cfg", "r") as f:
                lines = f.readlines()
            with open("setup.cfg", "w") as f:
                for line in lines:
                    if line.startswith("version = "):
                        line = f"version = {ref_name}\n"
                    f.write(line)
        except:
            pass

    setuptools.setup()
