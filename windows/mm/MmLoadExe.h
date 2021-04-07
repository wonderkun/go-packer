#include <Windows.h>

void ShowError(const char *lpszText);
BOOL IsExistReTable(LPVOID lpBaseAddress);
LPVOID runMyFile(LPVOID lpData, DWORD dwSize);
DWORD GetMyFileSize(LPVOID lpData);

BOOL mapping(LPVOID lpData, LPVOID lpBaseAddress);

DWORD Align(DWORD dwSize, DWORD dwAlignment);
BOOL DoReTable(LPVOID lpBaseAddress);

BOOL doImTable(LPVOID lpBaseAddress);

BOOL SetBase(LPVOID lpBaseAddress);

BOOL goFileStart(LPVOID lpBaseAddress);
int runmain(BYTE *pData,unsigned long dwFileSize);

