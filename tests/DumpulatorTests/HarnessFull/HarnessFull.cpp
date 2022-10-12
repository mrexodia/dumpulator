
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <CommCtrl.h>

int EntryPoint(void* peb)
{
	WSADATA wsa;
	WSAStartup(0, &wsa);
	CoInitialize(0);
	ShellExecuteW(0, L"open", L".", nullptr, nullptr, SW_SHOWNORMAL);
	MessageBeep(MB_ICONERROR);
	InitCommonControls();
	HKEY key;
	RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", &key);
	BCRYPT_ALG_HANDLE alg;
	BCryptOpenAlgorithmProvider(&alg, BCRYPT_RC4_ALGORITHM, nullptr, 0);
	HCRYPTPROV prov;
	CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	__debugbreak(); // Dump here
	return 0;
}