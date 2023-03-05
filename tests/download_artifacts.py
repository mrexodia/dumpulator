import os
import pathlib
import sys
import shutil
import argparse
import json
import urllib.request
from urllib.error import URLError

from typing import Dict

def download_file(url: str, file: str):
    with urllib.request.urlopen(url) as response:
        with open(file, "wb") as f:
            shutil.copyfileobj(response, f)

def main(*argv):
    # Defaults
    default_url = "https://api.github.com/repos/mrexodia/dumpulator/releases/tags/artifacts"
    default_dir = str(pathlib.Path(__file__).parent)

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*", help="Names of the release artifacts to download")
    parser.add_argument("--url", default=default_url)
    parser.add_argument("--dir", default=default_dir, help="Download destination directory")
    args = parser.parse_args(argv)

    # Create destination directory
    os.makedirs(args.dir, exist_ok=True)

    print(f"Fetching release JSON: {args.url}")
    assets: Dict[str, str] = {}
    try:
        with urllib.request.urlopen(args.url) as response:
            release = json.load(response)
            for asset in release["assets"]:
                assets[asset["name"]] = asset["browser_download_url"]
    except URLError as error:
        print(error)
        return False

    if not args.artifacts:
        args.artifacts = list(assets.keys())

    destination_dir = pathlib.Path(args.dir)
    print(f"Destination: {destination_dir}")
    for artifact in args.artifacts:
        if artifact not in assets:
            print(f"Could not find artifact '{artifact}' in release")
            return False
        try:
            url = assets[artifact]
            print(f"Downloading: {url}")
            download_file(url, str(destination_dir.joinpath(artifact)))
        except URLError as error:
            print(error)
            return False

    return True

if __name__ == "__main__":
    sys.exit(1 if main(*sys.argv[1:]) is False else 0)
