// RVAConversion.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>

DWORD RVA2FOA(DWORD RVA, DWORD sectionRVA, DWORD sectionFOA)
{
	return RVA - sectionRVA + sectionFOA;
}

DWORD RVA2FOA(IMAGE_SECTION_HEADER *sectionHeaders, DWORD numOfSections, DWORD RVA)
{
	for (DWORD i = 0; i < numOfSections; i++)
	{
		DWORD sectionRVA = sectionHeaders[i].VirtualAddress;
		DWORD sectionFOA = sectionHeaders[i].PointerToRawData;
		DWORD sectionVirtualSize = sectionHeaders[i].Misc.VirtualSize;
		DWORD FOA;
		if (RVA >= sectionRVA && RVA <= sectionRVA + sectionVirtualSize)
		{
			FOA = RVA2FOA(RVA, sectionRVA, sectionFOA);
			if (FOA >= sectionHeaders[i].PointerToRawData && FOA <= sectionHeaders[i].PointerToRawData + sectionHeaders[i].SizeOfRawData)
			{
				printf("Section Found\n");
				printf("Name = ");
				for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
				{
					printf("%c", sectionHeaders[i].Name[j]);
				}
				printf("\n");
				return FOA;
			}
		}
	}
	return -1;
}

IMAGE_DOS_HEADER* GetDosHeader(BYTE *buffer, DWORD size)
{
	for (DWORD i = 0; i < size - 1; i++)
	{
		if (buffer[i] == 'M' && buffer[i + 1] == 'Z')
		{
			return (IMAGE_DOS_HEADER*)(buffer + i);
		}
	}
	printf("Fail to get dos header\n");
	return NULL;
}

IMAGE_NT_HEADERS* GetPEHeader(BYTE *buffer, DWORD size)
{
	IMAGE_DOS_HEADER *dosHeader = GetDosHeader(buffer, size);
	if (dosHeader)
	{
		IMAGE_NT_HEADERS *PEHeader = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
		if (PEHeader->Signature == 0x4550) //"PE\0\0"
		{
			return PEHeader;
		}
	}
	printf("Fail to get PE header\n");
	return NULL;
}

bool GetSectionHeaders(BYTE *buffer, DWORD size,IMAGE_SECTION_HEADER **pSectionHeaders, DWORD *pNumberOfHeaders)
{
	IMAGE_NT_HEADERS *PEHeader = GetPEHeader(buffer, size);
	if (PEHeader)
	{
		IMAGE_SECTION_HEADER *sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)(&(PEHeader->OptionalHeader)) + PEHeader->FileHeader.SizeOfOptionalHeader);
		DWORD numberOfHeaders = PEHeader->FileHeader.NumberOfSections;
		*pSectionHeaders = sectionHeaders;
		*pNumberOfHeaders = numberOfHeaders;
		return true;
	}
	*pSectionHeaders = NULL;
	*pNumberOfHeaders = 0;
	printf("Fail to get section headers\n");
	return false;
}

DWORD RVA2FOA(BYTE *buffer, DWORD size, DWORD RVA)
{
	IMAGE_SECTION_HEADER *sectionHeaders = NULL;
	DWORD numberOfSections = 0;
	if (GetSectionHeaders(buffer, size, &sectionHeaders, &numberOfSections)){
		return RVA2FOA(sectionHeaders, numberOfSections, RVA);
	}
	return 0;
}

bool LoadFileIntoBuffer(char *filename, BYTE **pBuffer, DWORD *pSize)
{
	FILE *file = fopen(filename, "rb");
	if (file)
	{
		fseek(file, 0, SEEK_END);
		*pSize = ftell(file);
		fseek(file, 0, SEEK_SET);
		*pBuffer = new BYTE[*pSize];
		fread(*pBuffer, 1, *pSize, file);
		return true;
	}
	return false;
}

DWORD Str2Num(char *str)
{
	DWORD len = strlen(str);
	DWORD num = 0;
	if (len >= 2)
	{
		if (str[0] == '0' && str[1] == 'x') //Hex
		{
			for (DWORD i = 2 ; i < len; i++)
			{
				char *p = str + i;
				if (*p >= '0' && *p <= '9')
				{
					num = num * 0x10 + *p - '0';
				}
				else if (*p >= 'a' && *p <= 'f')
				{
					num = num * 0x10 + *p - 'a' + 0xa;
				}
				else if (*p >= 'A' && *p <= 'F')
				{
					num = num * 0x10 + *p - 'A' + 0xa;
				}
				else
				{
					return 0;
				}
			}
			return num;
		}
	}
	return atoi(str);
}


int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s [filename] [RVA]",argv[0]);
		return 1;
	}
	BYTE *buffer;
	DWORD size;
	DWORD RVA = Str2Num(argv[2]), FOA;
	if (LoadFileIntoBuffer(argv[1], &buffer, &size))
	{
		printf("The file was loaded successfully\n");
		FOA = RVA2FOA(buffer, size, RVA);
		if (FOA == -1)
		{
			printf("Invalid RVA\n");
		}
		else
		{
			printf("RVA = 0x%08x, FOA = 0x%08x\n", RVA, FOA);
		}
	}
	else
	{
		printf("Error while loading file\n");
		return 1;
	}
	//system("pause");
	return 0;
}

