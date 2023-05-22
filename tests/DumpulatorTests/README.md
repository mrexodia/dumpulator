# DumpulatorTests

## Creating a dump

The harness dumps were created as follows:

- Start a clean Windows Sandbox install
- Put x64dbg in there
- Install the [DisableParallelLoader](https://github.com/mrexodia/DisableParallelLoader) plugin and enable it
- Load the harness executable
- Execute the `dbh` command to hide the debugger from the PEB
- Run until the entry point
- Use the `minidump` command to create the dump

## Adding a new test

Add a new `mytest.cpp` file to the `Tests` project. The tests are exported as `bool <Prefix>_<description>Test();` and the result indicates whether the test was successful or not. If you need a custom environment add the following in `tests/run-tests.py`:

```python
class <Prefix>Environment(TestEnvironment):
    def setup(self, dp: Dumpulator):
        # TODO: use the dp class to initialize your environment
        pass
```