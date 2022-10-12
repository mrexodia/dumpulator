#include <Windows.h>
#include <cstdio>

int main(int argc, char** argv)
{
#ifdef _WIN64
    auto dll = "Tests_x64.dll";
#else
    auto dll = "Tests_x86.dll";
#endif // _WIN64
    auto hLib = LoadLibraryA(dll);
    if (argc < 2)
    {
        // TODO: implement enumerating all exports and running them
        puts("Usage: Loader TestFunction");
        return EXIT_FAILURE;
    }
    auto TestFunction = (int(*)())GetProcAddress(hLib, argv[1]);
    return TestFunction() ? EXIT_SUCCESS : EXIT_FAILURE;
}