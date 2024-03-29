#!/usr/bin/env python
import subprocess
import sys

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
        except Exception:
            pass
    # HACK: support [options].develop_requires install development dependencies
    if "develop" in sys.argv:
        import configparser
        config = configparser.ConfigParser()
        config.read("setup.cfg")
        if "options" in config:
            options = config["options"]
            if "develop_requires" in options:
                develop_requires = [line for line in options["develop_requires"].splitlines() if line]
                pip_args = [sys.executable, "-m", "pip", "install", *develop_requires]
                print(f"Installing development requirements: python " + " ".join(pip_args[1:]))
                try:
                    subprocess.check_call(pip_args)
                except subprocess.CalledProcessError:
                    sys.exit(1)
    setuptools.setup()
