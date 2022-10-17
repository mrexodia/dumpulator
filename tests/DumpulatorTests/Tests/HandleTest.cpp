#include "debug.h"

extern "C" __declspec(dllexport) bool Handle_WriteAndCreateFileTest()
{
	DebugPrint(WIDEN(__FUNCTION__));

	char data_buffer[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
	DWORD data_buffer_len = sizeof(data_buffer);
	DWORD bytes_written = 0;
	BOOL ret_value = FALSE;

	HANDLE file_handle = CreateFile(
		L"nonexistent_file.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file_handle == INVALID_HANDLE_VALUE)
	{
		DebugPrint(L"Failed to create file");
		return ret_value;
	}

	ret_value = WriteFile(
		file_handle,
		data_buffer,
		data_buffer_len,
		&bytes_written,
		NULL
	);

	CloseHandle(file_handle);

	return ret_value;
}

extern "C" __declspec(dllexport) bool Handle_ReadFileTest()
{
	DebugPrint(WIDEN(__FUNCTION__));

	DWORD bytes_written = 0;
	BOOL ret_value = FALSE;
	char read_buffer[1000];

	HANDLE file_handle = CreateFile(
		L"test_file.txt",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file_handle == INVALID_HANDLE_VALUE)
	{
		DebugPrint(L"Failed to open file");
		return ret_value;
	}

	ret_value = ReadFile(
		file_handle,
		read_buffer,
		sizeof(read_buffer),
		&bytes_written,
		FALSE
	);

	CloseHandle(file_handle);

	return ret_value;
}
