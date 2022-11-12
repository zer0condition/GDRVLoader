#include "global.h"
#include <iostream>
#include "driverloader.h"

const wchar_t* DroppedMapperPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

NTSTATUS NTAPI myDeleteFile(PWSTR FileName)
{
	NTSTATUS status;
	wchar_t FullPath[1024];

	UNICODE_STRING NtPath;
	OBJECT_ATTRIBUTES ObjectAttributes;

	if (!SearchPath(NULL, FileName, NULL, 1024, FullPath, NULL))
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!RtlDosPathNameToNtPathName_U(FullPath, &NtPath, NULL, NULL))
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	InitializeObjectAttributes(&ObjectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtDeleteFile(&ObjectAttributes);

	RtlFreeUnicodeString(&NtPath);
	return status;
}

int wmain(int argc, wchar_t** argv)
{
	NTSTATUS Status;
	if (argc == 2)
	{
		if (DropMapperFromBytes(DroppedMapperPath))
		{
			// Load driver
			Status = WindLoadDriver((PWCHAR)DroppedMapperPath, argv[1], FALSE);
			if (!NT_SUCCESS(Status))
				Printf(L"Driver load error: %08x\n", Status);

			myDeleteFile((PWSTR)DroppedMapperPath);
		}
	}
	else if (argc == 3)
	{
		// Unload driver
		Status = WindUnloadDriver((PWCHAR)argv[1], 0);
		if (NT_SUCCESS(Status))
			Printf(L"Driver unloaded successfully.\n");
		else
			Printf(L"Error unloading driver: %08X\n", Status);
	}

	return Status;
}

DECLSPEC_NOINLINE
static
VOID
ParseCommandLine(
	_In_ PWCHAR CommandLine,
	_Out_opt_ PWCHAR* Argv,
	_Out_opt_ PWCHAR Arguments,
	_Out_ PULONG Argc,
	_Out_ PULONG NumChars
	)
{
	*NumChars = 0;
	*Argc = 1;

	// Copy the executable name and and count bytes
	PWCHAR p = CommandLine;
	if (Argv != nullptr)
		*Argv++ = Arguments;

	// Handle quoted executable names
	BOOLEAN InQuotes = FALSE;
	WCHAR c;
	do
	{
		if (*p == '"')
		{
			InQuotes = !InQuotes;
			c = *p++;
			continue;
		}

		++*NumChars;
		if (Arguments != nullptr)
			*Arguments++ = *p;
		c = *p++;
	} while (c != '\0' && (InQuotes || (c != ' ' && c != '\t')));

	if (c == '\0')
		--p;
	else if (Arguments != nullptr)
		*(Arguments - 1) = L'\0';

	// Iterate over the arguments
	InQuotes = FALSE;
	for (; ; ++*NumChars)
	{
		if (*p != '\0')
		{
			while (*p == ' ' || *p == '\t')
				++p;
		}
		if (*p == '\0')
			break; // End of arguments

		if (Argv != nullptr)
			*Argv++ = Arguments;
		++*Argc;

		// Scan one argument
		for (; ; ++p)
		{
			BOOLEAN CopyChar = TRUE;
			ULONG NumSlashes = 0;

			while (*p == '\\')
			{
				// Count the number of slashes
				++p;
				++NumSlashes;
			}

			if (*p == '"')
			{
				// If 2N backslashes before: start/end a quote. Otherwise copy literally
				if ((NumSlashes & 1) == 0)
				{
					if (InQuotes && p[1] == '"')
						++p; // Double quote inside a quoted string
					else
					{
						// Skip first quote and copy second
						CopyChar = FALSE; // Don't copy quote
						InQuotes = !InQuotes;
					}
				}
				NumSlashes >>= 1;
			}

			// Copy slashes
			while (NumSlashes--)
			{
				if (Arguments != nullptr)
					*Arguments++ = '\\';
				++*NumChars;
			}

			// If we're at the end of the argument, go to the next
			if (*p == '\0' || (!InQuotes && (*p == ' ' || *p == '\t')))
				break;

			// Copy character into argument
			if (CopyChar)
			{
				if (Arguments != nullptr)
					*Arguments++ = *p;
				++*NumChars;
			}
		}

		if (Arguments != nullptr)
			*Arguments++ = L'\0';
	}
}

NTSTATUS
NTAPI
NtProcessStartupW(
	_In_ PPEB Peb
	)
{
	// On Windows XP (heh...) rcx does not contain a PEB pointer, but garbage
	Peb = Peb != nullptr ? NtCurrentPeb() : NtCurrentTeb()->ProcessEnvironmentBlock; // And this turd is to get Resharper to shut up about assigning to Peb before reading from it. Note LHS == RHS

	// Get the command line from the startup parameters. If there isn't one, use the executable name
	PRTL_USER_PROCESS_PARAMETERS Params = RtlNormalizeProcessParams(Peb->ProcessParameters);
	const PWCHAR CommandLineBuffer = Params->CommandLine.Buffer == nullptr || Params->CommandLine.Buffer[0] == L'\0'
		? Params->ImagePathName.Buffer
		: Params->CommandLine.Buffer;

	// Count the number of arguments and characters excluding quotes
	ULONG Argc, NumChars;
	ParseCommandLine(CommandLineBuffer,
					nullptr,
					nullptr,
					&Argc,
					&NumChars);

	// Allocate a buffer for the arguments and a pointer array
	const ULONG ArgumentArraySize = (Argc + 1) * sizeof(PVOID);
	PWCHAR *Argv = static_cast<PWCHAR*>(
		RtlAllocateHeap(RtlProcessHeap(),
						HEAP_ZERO_MEMORY,
						ArgumentArraySize + NumChars * sizeof(WCHAR)));
	if (Argv == nullptr)
		return NtTerminateProcess(NtCurrentProcess, STATUS_NO_MEMORY);

	// Copy the command line arguments
	ParseCommandLine(CommandLineBuffer,
					Argv,
					reinterpret_cast<PWCHAR>(&Argv[Argc + 1]),
					&Argc,
					&NumChars);

	// Call the main function and terminate with the exit status
	const NTSTATUS Status = wmain(Argc, Argv);
	return NtTerminateProcess(NtCurrentProcess, Status);
}
