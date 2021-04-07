
#include "MmLoadExe.h"
#include <stdio.h>
#include "Syscalls.h"

#ifdef _WIN64
typedef  ULONG64 UNPTR;
#else
typedef  ULONG32 UNPTR;
#endif


// VirtualAlloc
// RtlZeroMemory
// RtlCopyMemory

void* internal_cleancall_wow64_gate = 0;

void ShowError(const char *lpszText)
{
	char szErr[MAX_PATH] = { 0 };
	wsprintfA(szErr, "%s Error!\nError Code Is:%d\n", lpszText, GetLastError());
#ifdef _DEBUG
	MessageBoxA(NULL, szErr, "ERROR", MB_OK | MB_ICONERROR);
#endif
}


// 判断是否有重定位表存在
BOOL IsExistReTable(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = NULL;

	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		pLoc = (PIMAGE_BASE_RELOCATION)((UNPTR)pDosHeader + pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	}
	else if(pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位 
		pLoc = (PIMAGE_BASE_RELOCATION)((UNPTR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	}

	// 判断是否有 重定位表
	if ((PVOID)pLoc == (PVOID)pDosHeader)
	{
		// 重定位表 为空
		return FALSE;
	}

	return TRUE;
}


// 模拟PE加载器加载内存EXE文件到进程中
// lpData: 内存EXE文件数据的基址
// dwSize: 内存EXE文件的内存大小
// 返回值: 内存EXE加载到进程的加载基址
LPVOID runMyFile(LPVOID lpData, DWORD dwSize)
{
	LPVOID lpBaseAddress = NULL;

	// 获取镜像大小
	DWORD dwSizeOfImage = GetMyFileSize(lpData);

	// 在进程中开辟一个可读、可写、可执行的内存块
	
	// EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	// 	IN HANDLE ProcessHandle,
	// 	IN OUT PVOID* BaseAddress,
	// 	IN ULONG ZeroBits,
	// 	IN OUT PSIZE_T RegionSize,
	// 	IN ULONG AllocationType,
	// 	IN ULONG Protect);

	NTSTATUS status = NtAllocateVirtualMemory(
		GetCurrentProcess(),
		&lpBaseAddress,0
	,&dwSizeOfImage,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// lpBaseAddress = VirtualAlloc(NULL,dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == lpBaseAddress)
	{
		ShowError("VirtualAlloc");
		return NULL;
	}
	memset(lpBaseAddress,'\x00', dwSizeOfImage);

	// 将内存PE数据按SectionAlignment大小对齐映射到进程内存中
	if (FALSE == mapping(lpData, lpBaseAddress))
	{
		ShowError("mapping");
		return NULL;
	}

	// 修改PE文件重定位表信息
	if (FALSE == DoReTable(lpBaseAddress))
	{
		ShowError("DoReTable");
		return NULL;
	}

	// 填写PE文件导入表信息
	if (FALSE == doImTable(lpBaseAddress))
	{
		ShowError("doImTable");
		return NULL;
	}

	//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
	//统一设置成一个属性PAGE_EXECUTE_READWRITE
	DWORD dwOldProtect = 0;
	// if (FALSE == VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	// {
	// 	ShowError("VirtualProtect");
	// 	return NULL;
	// }

	// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
	if (FALSE == SetBase(lpBaseAddress))
	{
		ShowError("SetBase");
		return NULL;
	}

	// 跳转到PE的入口点处执行, 函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	if (FALSE == goFileStart(lpBaseAddress))
	{
		ShowError("goFileStart");
		return NULL;
	}

	return lpBaseAddress;
}


// 根据PE结构,获取PE文件加载到内存后的镜像大小
// lpData: 内存DLL文件数据的基址
// 返回值: 返回PE文件结构中IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage值的大小
DWORD GetMyFileSize(LPVOID lpData)
{
	DWORD dwSizeOfImage = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);

	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		dwSizeOfImage = pNtHeaders64->OptionalHeader.SizeOfImage;
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位
		dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	}

	return dwSizeOfImage;
}


// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
// lpData: 内存DLL文件数据的基址
// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// 返回值: 成功返回TRUE，否则返回FALSE
BOOL mapping(LPVOID lpData, LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);
	// 获取SizeOfHeaders的值: 所有头+节表头的大小
	DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
	// 获取节表的数量
	WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	// 获取第一个节表头的地址
	
	/*
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	这样计算是错误的,因为 64 位程序和 32 位程序 IMAGE_NT_HEADERS 的大小不一样
	*/
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
	   // 32 位镜像 
		pSectionHeader = (PIMAGE_SECTION_HEADER)((UNPTR)pNtHeaders + sizeof(IMAGE_NT_HEADERS32));
	}else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

		pSectionHeader = (PIMAGE_SECTION_HEADER)((UNPTR)pNtHeaders + sizeof(IMAGE_NT_HEADERS64));
	}
	else {
	    // 无法识别的 EXE 镜像 
		ShowError("cann't identify file format.");
		return FALSE;
	}
	
	// 加载 所有头+节表头的大小
	memcpy(lpBaseAddress, lpData, dwSizeOfHeaders);
	// 对齐SectionAlignment循环加载节表
	WORD i = 0;
	LPVOID lpSrcMem = NULL;
	LPVOID lpDestMem = NULL;
	DWORD dwSizeOfRawData = 0;
	for (i = 0; i < wNumberOfSections; i++)
	{
		if ((0 == pSectionHeader->VirtualAddress) ||
			(0 == pSectionHeader->SizeOfRawData))
		{
			pSectionHeader++;
			continue;
		}

		lpSrcMem = (LPVOID)((UNPTR)lpData + pSectionHeader->PointerToRawData);
		lpDestMem = (LPVOID)((UNPTR)lpBaseAddress + pSectionHeader->VirtualAddress);
		dwSizeOfRawData = pSectionHeader->SizeOfRawData;
		memcpy(lpDestMem, lpSrcMem, dwSizeOfRawData);

		pSectionHeader++;
	}

	return TRUE;
}

// 对齐SectionAlignment
// dwSize: 表示未对齐前内存的大小
// dwAlignment: 对齐大小值
// 返回值: 返回内存对齐之后的值
DWORD Align(DWORD dwSize, DWORD dwAlignment)
{
	DWORD dwRet = 0;
	DWORD i = 0, j = 0;
	i = dwSize / dwAlignment;
	j = dwSize % dwAlignment;
	if (0 != j)
	{
		i++;
	}

	dwRet = i * dwAlignment;

	return dwRet;
}


// 修改PE文件重定位表信息
// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// 返回值: 成功返回TRUE，否则返回FALSE
BOOL DoReTable(LPVOID lpBaseAddress)
{
	/* 重定位表的结构：
	// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
	// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
	// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
	// -----------   -----------      ----
	// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
	// 重定位表是若干个相连，如果address 和 size都是0 表示结束
	// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
	*/
	//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
	//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION pLoc = NULL;
	ULONGLONG   ImageBase = 0;

	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		pLoc = (PIMAGE_BASE_RELOCATION)((UNPTR)pDosHeader + pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		ImageBase = pNtHeaders64->OptionalHeader.ImageBase;
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位 
		pLoc = (PIMAGE_BASE_RELOCATION)((UNPTR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		ImageBase = pNtHeaders->OptionalHeader.ImageBase;
	}


	// 判断是否有 重定位表
	if ((PVOID)pLoc == (PVOID)pDosHeader)
	{
		// 重定位表 为空
		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
	{
		WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
		//计算本节需要修正的重定位项（地址）的数目
		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。

			#ifdef _WIN64
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
			{
			// 64位dll重定位，IMAGE_REL_BASED_DIR64
			// 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。

				UNPTR* pAddress = (UNPTR *)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				UNPTR ullDelta = (UNPTR)pDosHeader - ImageBase;
			    *pAddress += ullDelta;

			}
            #else
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
			{
				// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
				// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
				UNPTR* pAddress = (UNPTR*)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				UNPTR dwDelta = (UNPTR)pDosHeader - ImageBase;
				*pAddress += dwDelta;

		    }
            #endif

		}

		//转移到下一个节进行处理
		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}


// 填写PE文件导入表信息
// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// 返回值: 成功返回TRUE，否则返回FALSE
BOOL doImTable(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	
	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((UNPTR)pDosHeader +
			pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位 
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((UNPTR)pDosHeader +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	}

	
	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	char *lpDllName = NULL;
	HMODULE hDll = NULL;
	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DWORD i = 0;

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// 获取导入表中DLL的名称并加载DLL
		lpDllName = (char *)((UNPTR)pDosHeader + pImportTable->Name);
		hDll = GetModuleHandleA(lpDllName);
		if (NULL == hDll)
		{
			hDll = LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		i = 0;
		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
		lpImportNameArray = (PIMAGE_THUNK_DATA)((UNPTR)pDosHeader + pImportTable->OriginalFirstThunk);
		// 获取FirstThunk以及对应的导入函数地址表首地址
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((UNPTR)pDosHeader + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// 获取IMAGE_IMPORT_BY_NAME结构
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((UNPTR)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			// 判断导出函数是序号导出还是函数名称导出
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// 序号导出
				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// 名称导出
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！
			lpImportFuncAddrArray[i].u1.Function = (UNPTR)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}

	return TRUE;
}


// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
// lpBaseAddress: 内存EXE数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// 返回值: 成功返回TRUE，否则返回FALSE
BOOL SetBase(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);
	
	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		pNtHeaders64->OptionalHeader.ImageBase = (UNPTR)lpBaseAddress;
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位 
		pNtHeaders->OptionalHeader.ImageBase = (UNPTR)lpBaseAddress;
	}

	return TRUE;
}


// 跳转到PE的入口点处执行, 函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
// lpBaseAddress: 内存PE数据按SectionAlignment大小对齐映射到进程内存中的内存基址
// 返回值: 成功返回TRUE，否则返回FALSE
BOOL goFileStart(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UNPTR)pDosHeader + pDosHeader->e_lfanew);
	LPVOID lpExeEntry = NULL; 
	
	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 如果是64位 
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pNtHeaders);
		lpExeEntry = (LPVOID)((UNPTR)pDosHeader + pNtHeaders64->OptionalHeader.AddressOfEntryPoint);

	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 如果是32位 
		lpExeEntry = (LPVOID)((UNPTR)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	}

	// 跳转到入口点处执行
	//__asm
	//{
	//	mov eax, lpExeEntry
	//	jmp eax
	//}
	((void(*)())(lpExeEntry))();
	return TRUE;
}


int runmain(BYTE *pData,unsigned long dwFileSize)
{   
	internal_cleancall_wow64_gate = (void*)__readfsdword(0xC0);
	// 判断有无重定位表
	if (TRUE == IsExistReTable(pData))
	{
		printf("[FALSE] IsExistReTable\n");
		//system("pause");
		//return 0;
	}
	// 将内存DLL加载到程序中
	LPVOID lpBaseAddress = runMyFile(pData, dwFileSize);
	if (NULL == lpBaseAddress)
	{
		ShowError("runMyFile");
		return 3;
	}

	return 0;
}