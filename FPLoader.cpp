/**
*  Copyright (C) 2016 Rafal Janicki
*
*  This software is provided 'as-is', without any express or implied
*  warranty.  In no event will the authors be held liable for any damages
*  arising from the use of this software.
*
*  Permission is granted to anyone to use this software for any purpose,
*  including commercial applications, and to alter it and redistribute it
*  freely, subject to the following restrictions:
*
*  1. The origin of this software must not be misrepresented; you must not
*     claim that you wrote the original software. If you use this software
*     in a product, an acknowledgment in the product documentation would be
*     appreciated but is not required.
*  2. Altered source versions must be plainly marked as such, and must not be
*     misrepresented as being the original software.
*  3. This notice may not be removed or altered from any source distribution.
*
*  Rafal Janicki
*  ravarcade@gmail.com
*/

/**
* Special Future Pinball.exe loader used to inject BAM.dll.  
*/

#include <windows.h>
#include <stdio.h>


#ifdef MAX_PATH
#undef MAX_PATH
#define MAX_PATH 2048
#endif

//  /Open "c:\Games\Future Pinball\Tables\Sci-Fi Classic.fpt"  /Play /Exit

// global variable: params from command line
bool isStayInRAM = false;
char *game_exe = "Future Pinball.exe";
char cmdLine_exe[MAX_PATH];

// some constants with default names and paths
const char *bam_dll = "BAM.dll";
const char *default_game_exe = "Future Pinball.exe";
const char *default_game_dir = "C:\\Games\\Future Pinball\\";
const char *default_bam_dir = "C:\\Games\\Future Pinball\\BAM\\";

/// <summary>
/// Finds the parameter in command line
/// </summary>
/// <param name="lpCmdLine">The command line (txt).</param>
/// <param name="param">The parameter (txt).</param>
/// <returns>Pointer to next element after param or NULL if param is not found.</returns>
const char *FindParam(const char *lpCmdLine, const char *param)
{
	static char tmpCmdLine[1024] = { 0 };
	static char *endCmdLine = tmpCmdLine;
	if (!tmpCmdLine[0]) {
		strcpy_s(tmpCmdLine, lpCmdLine);
		_strupr_s(tmpCmdLine);
		tmpCmdLine[sizeof(tmpCmdLine) - 1] = 0;
		endCmdLine = tmpCmdLine + strlen(tmpCmdLine);
	}

	char *txt = tmpCmdLine;
	size_t len = strlen(param);
	while (char *p = strstr(txt, param)) 
	{
		if (p > tmpCmdLine && p[-1] == '/' && (p[len] == 0 || p[len] == ' ' || p[len] == ':')) 
		{
			return lpCmdLine + (p - tmpCmdLine + len + (p[len] ? 1 : 0));
		}
		txt = p + 1;
		if (txt >= endCmdLine)
			break;
	}

	return NULL;
}

/// <summary>
/// Parses the command line.
/// </summary>
/// <param name="lpCmdLine">The command line.</param>
void ParseCommandLine(LPSTR lpCmdLine)
{
	isStayInRAM = FindParam(lpCmdLine, "STAYINRAM") != NULL;
	cmdLine_exe[0] = 0;
	const char * exeFileName = FindParam(lpCmdLine, "FPEXE");
	if (exeFileName) 
	{
		const char *begin = exeFileName[0] == '"' ? exeFileName + 1 : exeFileName;
		const char *end;
		if (exeFileName[0] == '"') 
		{
			end = strchr(begin, '"');
		}
		else 
		{
			end = strchr(begin, ' ');
			if (end == NULL)
				end = begin + strlen(begin);
		}

		size_t len = end - begin > sizeof(cmdLine_exe) - 1 ? sizeof(cmdLine_exe) - 1: end - begin;
		memcpy_s(cmdLine_exe, len, begin, len);
		cmdLine_exe[len] = 0;
	}
}

/// <summary>
/// Combines the path (dir) and file name into single one. Path ends after last '\' (slash). 
/// If somthing is after that last slash it is replaced with file name.
/// </summary>
/// <param name="FullFilePath">The full file path.</param>
/// <param name="path">The path (dir).</param>
/// <param name="filename">The filename.</param>
/// <returns>Return full file path.</returns>
char *CombinePathWithFileName(char FullFilePath[MAX_PATH], const char *path, const char *filename)
{
	strcpy_s(FullFilePath, MAX_PATH - 1, path);
	if (strrchr(FullFilePath, '\\') != NULL)
	{
		*(strrchr(FullFilePath, '\\') + 1) = 0;
	}
	else
	{
		strncat_s(FullFilePath, MAX_PATH - 1, "\\", MAX_PATH - 1);
	}
	strncat_s(FullFilePath, MAX_PATH - 1, filename, MAX_PATH - 1);
	FullFilePath[MAX_PATH - 1] = 0;

	return FullFilePath;
}

/// <summary>
/// main()
/// </summary>
/// <param name="hInstance">The handle to instance.</param>
/// <param name="hPrevInstance">The handle to previous instance.</param>
/// <param name="lpCmdLine">The command line params.</param>
/// <param name="nCmdShow">The window show state.</param>
/// <returns>Zero if work without error.</returns>
int WINAPI WinMain(
	HINSTANCE	hInstance,			// Instance
	HINSTANCE	hPrevInstance,		// Previous Instance
	LPSTR		lpCmdLine,			// Command Line Parameters
	int			nCmdShow)			// Window Show State
{
	ParseCommandLine(lpCmdLine);

	BOOL success;

	char current_dir[MAX_PATH];
	GetModuleFileNameA(NULL, current_dir, sizeof(current_dir));
	*(strrchr(current_dir, '\\') + 1) = 0;

	char current_dir_one_level_up[MAX_PATH];
	strcpy_s(current_dir_one_level_up, current_dir);
	*(strrchr(current_dir_one_level_up, '\\')) = 0;
	if (strrchr(current_dir_one_level_up, '\\') != NULL)
		*(strrchr(current_dir_one_level_up, '\\') + 1) = 0;

	// Find BAM.dll
	char bam_path[MAX_PATH];

	// search for BAM.dll in current dir (it should be here)
	CombinePathWithFileName(bam_path, current_dir, bam_dll);
	success = GetFileAttributesA(bam_path) != INVALID_FILE_ATTRIBUTES;
	if (!success)
	{	// search for BAM.dll in default bam dir
		CombinePathWithFileName(bam_path, default_bam_dir, bam_dll);
		success = GetFileAttributesA(bam_path) != INVALID_FILE_ATTRIBUTES;
	}

	if (!success)
	{	// error
		MessageBoxA(NULL, "Couldn't locate BAM.dll.", "Missing files.", MB_ICONERROR | MB_OK);
		return -1;
	}

	// Find Future Pinball.exe
	char game_exe[MAX_PATH];

	success = FALSE;
	if (cmdLine_exe[0])
	{
		// check if in cmdline was full path to game_exe
		strcpy_s(game_exe, cmdLine_exe); 
		success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;

		if (!success)
		{	// search for cmdLine_exe in current_dir_one_level_up
			CombinePathWithFileName(game_exe, current_dir_one_level_up, cmdLine_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}

		if (!success)
		{	// search for cmdLine_exe in current_dir
			CombinePathWithFileName(game_exe, current_dir, cmdLine_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}

		if (!success)
		{  // try cmdLine_exe use as path to default_game_exe
			CombinePathWithFileName(game_exe, cmdLine_exe, default_game_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}

		if (!success)
		{   // search for cmdLine_exe in default_game_dir
			CombinePathWithFileName(game_exe, default_game_dir, cmdLine_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}
	}
	else {
		// search for default_game_exe in current_dir_one_level_up
		CombinePathWithFileName(game_exe, current_dir_one_level_up, default_game_exe);
		success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;

		if (!success)
		{	// search for default_game_exe in current_dir
			CombinePathWithFileName(game_exe, current_dir, default_game_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}
	
		if (!success)
		{	// search for default_game_exe in defaul_game_dir
			CombinePathWithFileName(game_exe, default_game_dir, default_game_exe);
			success = GetFileAttributesA(game_exe) != INVALID_FILE_ATTRIBUTES;
		}
	}

	if (!success)
	{	// error
		MessageBoxA(NULL, "Couldn't locate Future Pinball.exe.", "Missing files.", MB_ICONERROR | MB_OK);
		return -1;
	}

	// Greate! Both BAM.dll and Future Pinball.exe found. Run.
	char game_dir[MAX_PATH];
	strcpy_s(game_dir, game_exe);
	*(strrchr(game_dir, '\\')) = 0;

	PROCESS_INFORMATION process_info;
	STARTUPINFOA startup_info;
	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);

	BOOL ret = CreateProcessA(
		game_exe,
		lpCmdLine, NULL, NULL, NULL,
		CREATE_SUSPENDED,
		NULL,
		game_dir,
		&startup_info,
		&process_info);

	LPVOID path_memory = VirtualAllocEx(
		process_info.hProcess,
		(LPVOID)0,
		(SIZE_T)0x1000,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);

	WriteProcessMemory(process_info.hProcess, path_memory, bam_path, strlen(bam_path)+1, NULL);

	// Create a new thread in the process that loads our DLL
	HANDLE hook_init_thread = CreateRemoteThread(
		process_info.hProcess,
		NULL, // lpThreadAttributes
		0, // dwStackSize
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "LoadLibraryA"),
		path_memory,
		0, // dwCreationFlags
		NULL // lpThreadId
		);

	// Wait for our hook to load
	WaitForSingleObject(hook_init_thread, INFINITE);
	CloseHandle(hook_init_thread);

	ResumeThread(process_info.hThread);


	if (isStayInRAM) {
		DWORD ws = WaitForSingleObject(process_info.hThread, INFINITE);
	}

	ExitProcess(0);

	return 0;
}