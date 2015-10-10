#include <stdio.h>
#include <windows.h>
#include <Winbase.h>
#include <string.h>

typedef char (WINAPI *PGNSI)();

int main()
{
	IMAGE_NT_HEADERS peHead;
	IMAGE_DOS_HEADER dosMZ;
	IMAGE_SECTION_HEADER* secHead;
	IMAGE_SECTION_HEADER* pLog = NULL;
	DWORD OldProtect = 0;
	int pPoint;
	unsigned long d;
	char file[] = "mono.dll";
	HANDLE hFIle;
	
	if ((hFIle = CreateFileA(file, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("\nFile OPEN Error");
		return 0;
	}
	if (!ReadFile(hFIle, (void*)&dosMZ, sizeof(dosMZ), &d, NULL))
	{
		printf("\nRead Fail");
		return 0;
	}
	
	SetFilePointer(hFIle, dosMZ.e_lfanew, NULL, FILE_BEGIN);
	
	if (!ReadFile(hFIle, (void*)&peHead, sizeof(peHead), &d, NULL))
	{
		printf("\nRead Fail");
		return 0;
	}
	if (!(dosMZ.e_magic == IMAGE_DOS_SIGNATURE))
	{
		printf("\nNot a Valid PE");
		return 0;
	}
	if (!(peHead.Signature == IMAGE_NT_SIGNATURE))
	{
		printf("\nNot Valid PE");
		return 0;
	}

	//dosMZ = (IMAGE_DOS_HEADER*)hModuleG;
	//peHead = (IMAGE_NT_HEADERS*)((DWORD)hModuleG + dosMZ->e_lfanew);
	secHead = (IMAGE_SECTION_HEADER*)((DWORD)&peHead + sizeof(IMAGE_NT_HEADERS));
	secHead = (IMAGE_SECTION_HEADER*)GlobalAlloc(GMEM_FIXED, sizeof(IMAGE_SECTION_HEADER)*peHead.FileHeader.NumberOfSections);
	ReadFile(hFIle, (void*)secHead, sizeof(IMAGE_SECTION_HEADER)*peHead.FileHeader.NumberOfSections, &d, NULL);

	printf("%d\n", peHead.FileHeader.NumberOfSections);
	for (int i = 0; i < peHead.FileHeader.NumberOfSections; i++)
	{
		//IMAGE_SECTION_HEADER* pSecTmp = (DWORD)secHead + sizeof(IMAGE_SECTION_HEADER)*i;
		printf("%s\n", secHead[i].Name);
		if (strstr(secHead[i].Name, ".log"))
		{
			//pLog = pSecTmp;
			printf("%d\n", i);
			pPoint = i;
			SetFilePointer(hFIle, (int)secHead[pPoint].PointerToRawData, NULL, FILE_BEGIN);
			break;
		}
		//printf("%d", i);
	}

	unsigned char op1;
	//unsigned char op2;
	unsigned char result;
	for (int i = 0; i < 54; i++)
	{
		ReadFile(hFIle, &op1, 1, &d, NULL);
		//printf("0x%x ", op1);
		SetFilePointer(hFIle, -1, NULL, FILE_CURRENT);
		/*
		if (i == 0)
		{
			result = op1;
			op2 = op1;
		}
		else
		{
			result = op1^op2;
			op2 = op1;
		}
		*/
		
		result = 0;
		WriteFile(hFIle, &result, 1, &d, NULL);
	}
	printf("\n ");
	SetFilePointer(hFIle, (int)secHead[pPoint].PointerToRawData, NULL, FILE_BEGIN);
	unsigned char ab;
	for (int i = 0; i <54; i++)
	{
		ReadFile(hFIle, &ab, 1, &d, NULL);
		printf("0x%x ", ab);
		
	}

	//printf("%d\n,%d", i);
	CloseHandle(hFIle);
	//return 0;
	
	/*
	printf("%s\n", pLog->Name);
	printf("%x\n", pLog->VirtualAddress + (DWORD)hModuleG);
	int * pData = (int *)(pLog->VirtualAddress + (DWORD)hModuleG);
	printf("0x%x\n", pData);
	printf("0x%x\n", *pData);
	*/
	//if (VirtualProtect((LPVOID)pData, 1024, PAGE_READWRITE, &OldProtect))printf("Success\n");
	//char tmpData[100];
	//char* pOldData = tmpData;
	//memcpy((char*)pData, (char*)pNewData, 2);
	//char* pNewData = malloc(100);
	//strcpy_s(pNewData,4, "\ue8c3\u1120\u1234\u4141");
	//memcpy((char*)pData, (char*)pNewData, 4);
	//*pData = 0x11111111;
	/*
	char *tmpData;
	tmpData = pData;
	tmpData++;
	for (int i = 1; i < 100; i++)
	{
		*tmpData = *tmpData ^ (*(tmpData - 1));
		tmpData++;
	}
	printf("0x%x\n", *pData);
	*/
	getchar();
	return 0;
}