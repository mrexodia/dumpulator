# dumpulator

**Note: This is a work-in-progress prototype, please treat it as such.**

An easy-to-use library for emulating code in minidump files.

## Example

The example below opens `test.dmp` (download a copy [here](https://github.com/mrexodia/dumpulator/releases/download/v0.0.1/test.dmp)), allocates some memory and calls the decryption function at `0x140001000` to decrypt the string at `0x140003000`:

```python
from dumpulator import Dumpulator

dp = Dumpulator("test.dmp", trace=True)
temp_addr = dp.allocate(256)
dp.call(0x140001000, [temp_addr, 0x140003000])
decrypted = dp.read_str(temp_addr)
print(f"decrypted: '{decrypted}'")
```

The `test.dmp` is collected at the entry point of the `tests/StringEncryptionFun` example.

## Collecting the dump

There is a simple plugin for [x64dbg](https://github.com/x64dbg/x64dbg) available in the `MiniDumpPlugin` folder (you can also download a precompiled binary in the [releases](https://github.com/mrexodia/dumpulator/releases)). To use it you pause execution and execute the command `MiniDump my.dmp`.

## Installation

From pip (latest [release](https://github.com/mrexodia/dumpulator/releases)):

```
python -m pip install dumpulator
```

To install from source:

```
python setup.py install
```

Install for a development environment:

```
python setup.py develop
```

## Credits

- [herrcore](https://twitter.com/herrcore) for inspiring me to make this
- [secret club](https://secret.club)
