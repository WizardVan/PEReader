#include <stdio.h>
#include <windows.h>
#include <Winbase.h>
#include <string.h>

typedef char (WINAPI *PGNSI)();

int main()
{
	IMAGE_NT_HEADERS* peHead;
	IMAGE_DOS_HEADER* dosMZ;
	IMAGE_SECTION_HEADER* secHead;
	IMAGE_SECTION_HEADER* pLog=NULL;
	DWORD OldProtect=0;

	HMODULE hModuleL = LoadLibrary("mono.dll");
	if (hModuleL)printf("Loaded\n");
	HMODULE hModuleG = GetModuleHandle("mono.dll");
	if (hModuleG)printf("Got\n");
	/*
	PGNSI pGNSI = (PGNSI)GetProcAddress(hModuleL, "getKey");
	if (pGNSI)
	{
		printf("Got function \n");
		char result = (pGNSI)();
		printf("%d", result);
	}
	*/
	dosMZ = (IMAGE_DOS_HEADER*)hModuleG;
	peHead = (IMAGE_NT_HEADERS*)((DWORD)hModuleG + dosMZ->e_lfanew);
	secHead = (IMAGE_SECTION_HEADER*)((DWORD)peHead + sizeof(IMAGE_NT_HEADERS));
	printf("%d\n", peHead->FileHeader.NumberOfSections);
	for (int i=0; i < peHead->FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSecTmp = (DWORD)secHead + sizeof(IMAGE_SECTION_HEADER)*i;
		//printf("%s\n", pSecTmp->Name);
		if (strstr(pSecTmp->Name, ".log"))
		{
			pLog = pSecTmp;
			break;
		}
		//printf("%d", i);
	}
	printf("%s\n", pLog->Name);
	printf("%x\n", pLog->VirtualAddress + (DWORD)hModuleG);
	int * pData = (int *)(pLog->VirtualAddress + (DWORD)hModuleG);
	printf("0x%x\n", pData);
	printf("0x%x\n", *pData);
	if(VirtualProtect((LPVOID)pData, 1024, PAGE_READWRITE, &OldProtect))printf("Success\n");
	//char tmpData[100];
	//char* pOldData = tmpData;
	//memcpy((char*)pData, (char*)pNewData, 2);
	//char* pNewData = malloc(100);
	//strcpy_s(pNewData,4, "\ue8c3\u1120\u1234\u4141");
	//memcpy((char*)pData, (char*)pNewData, 4);
	//*pData = 0x11111111;
	unsigned char *tmpData;
	tmpData = pData;
	for (int i = 0; i < pLog->SizeOfRawData; i++)
	{
		printf("0x%x ", *tmpData);
		tmpData++;
	}
	printf("\n");
	tmpData = pData;
	/*
	tmpData++;
	for (int i=1; i < pLog->SizeOfRawData; i++)
	{
		*tmpData = (unsigned char)((*tmpData) ^ (*(tmpData - 1)));
		tmpData++;
	}
	printf("0x%x\n", *pData);
	printf("\n");
	
	tmpData = pData;
	for (int i = 0; i < pLog->SizeOfRawData; i++)
	{
		printf("0x%x ", *tmpData);
		tmpData++;
	}
	*/
	printf("\n");
	getchar();
	return 0;
}