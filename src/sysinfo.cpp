#include "global.h"

static
VOID
PrintGuid(
	_In_ GUID Guid
	)
{
	Printf(L"{%08lx-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
		Guid.Data1, Guid.Data2, Guid.Data3,
		Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
		Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]);
}

// TODO: warn when values aren't clean
NTSTATUS
PrintSystemInformation(
	)
{
	SYSTEM_BOOT_ENVIRONMENT_INFORMATION BootInfo = { 0 };
	NTSTATUS Status = NtQuerySystemInformation(SystemBootEnvironmentInformation,
												&BootInfo,
												sizeof(BootInfo),
												nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemBootEnvironmentInformation: error %08X\n\n", Status);
	else
	{
		Printf(L"SystemBootEnvironmentInformation:\n\t- BootIdentifier: ");
		PrintGuid(BootInfo.BootIdentifier);
		Printf(L"\n\t- FirmwareType: %s\n\t- BootFlags: 0x%p\n\n",
			(BootInfo.FirmwareType == FirmwareTypeUefi ? L"UEFI" : L"BIOS"), BootInfo.BootFlags);
	}

	ULONG Size = 0;
	Status = NtQuerySystemInformation(SystemModuleInformation,
										nullptr,
										0,
										&Size);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		Printf(L"SystemModuleInformation: %08X\n\n", Status);
	else
	{
		PRTL_PROCESS_MODULES ModuleInfo = static_cast<PRTL_PROCESS_MODULES>(
			RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * Size));
		Status = NtQuerySystemInformation(SystemModuleInformation,
										ModuleInfo,
										2 * Size,
										nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemModuleInformation: %08X\n\n", Status);
		else
		{
			RTL_PROCESS_MODULE_INFORMATION Ntoskrnl = ModuleInfo->Modules[0];
			Printf(L"SystemModuleInformation:\n\t- Kernel: %S (%S)\n\n",
				reinterpret_cast<PCHAR>(Ntoskrnl.FullPathName + Ntoskrnl.OffsetToFileName),
				Ntoskrnl.FullPathName);
		}
		RtlFreeHeap(RtlProcessHeap(), 0, ModuleInfo);
	}

	SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
										&CodeIntegrityInfo,
										sizeof(CodeIntegrityInfo),
										nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemCodeIntegrityInformation: error %08X\n\n", Status);
	else
		Printf(L"SystemCodeIntegrityInformation:\n\t- IntegrityOptions: 0x%04X\n\n",
			CodeIntegrityInfo.CodeIntegrityOptions);

	SYSTEM_KERNEL_DEBUGGER_INFORMATION KernelDebuggerInfo = { 0 };
	Status = NtQuerySystemInformation(SystemKernelDebuggerInformation,
										&KernelDebuggerInfo,
										sizeof(KernelDebuggerInfo),
										nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemKernelDebuggerInformation: error %08X\n\n", Status);
	else
		Printf(L"SystemKernelDebuggerInformation:\n\t- KernelDebuggerEnabled: %u\n\t- KernelDebuggerNotPresent: %u\n\n",
			KernelDebuggerInfo.KernelDebuggerEnabled, KernelDebuggerInfo.KernelDebuggerNotPresent);

	if ((RtlNtMajorVersion() >= 6 && RtlNtMinorVersion() >= 3) || RtlNtMajorVersion() > 6)
	{
		SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX KernelDebuggerInfoEx = { 0 };
		Status = NtQuerySystemInformation(SystemKernelDebuggerInformationEx,
											&KernelDebuggerInfoEx,
											sizeof(KernelDebuggerInfoEx),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemKernelDebuggerInformationEx: error %08X\n\n", Status);
		else
			Printf(L"SystemKernelDebuggerInformationEx:\n\t- DebuggerAllowed: %u\n\t- DebuggerEnabled: %u\n\t- DebuggerPresent: %u\n\n",
				KernelDebuggerInfoEx.DebuggerAllowed, KernelDebuggerInfoEx.DebuggerEnabled, KernelDebuggerInfoEx.DebuggerPresent);
	}

	UCHAR KdDebuggerEnabled = SharedUserData->KdDebuggerEnabled;
	Printf(L"SharedUserData->KdDebuggerEnabled: 0x%02X\n\n", KdDebuggerEnabled);

	if (RtlNtMajorVersion() > 6)
	{
		UCHAR KernelDebuggerFlags = 0;
		Status = NtQuerySystemInformation(SystemKernelDebuggerFlags,
											&KernelDebuggerFlags,
											sizeof(KernelDebuggerFlags),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemKernelDebuggerFlags: error %08X\n\n", Status);
		else
			Printf(L"SystemKernelDebuggerFlags: 0x%02X\n\n", KernelDebuggerFlags);

		SYSTEM_CODEINTEGRITYPOLICY_INFORMATION CodeIntegrityPolicyInfo = { 0 };
		Status = NtQuerySystemInformation(SystemCodeIntegrityPolicyInformation,
											&CodeIntegrityPolicyInfo,
											sizeof(CodeIntegrityPolicyInfo),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemCodeIntegrityPolicyInformation: error %08X\n\n", Status);
		else
			Printf(L"SystemCodeIntegrityPolicyInformation:\n\t- Options: 0x%04X\n\t- HVCIOptions: 0x%04X\n\n",
				CodeIntegrityPolicyInfo.Options, CodeIntegrityPolicyInfo.HVCIOptions);

#if 0 // Requires a file handle. Also not sure what if anything this is supposed to return
		SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION CodeIntegrityCertInfo;
		Status = NtQuerySystemInformation(SystemCodeIntegrityCertificateInformation,
											&CodeIntegrityCertInfo,
											sizeof(CodeIntegrityCertInfo),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemCodeIntegrityCertificateInformation: error %08X\n\n", Status);
#endif

		BOOLEAN KernelDebuggingAllowed = FALSE; // No idea if BOOLEAN is correct since size must be 0
		Status = NtQuerySystemInformation(SystemKernelDebuggingAllowed,
										&KernelDebuggingAllowed,
										0,
										nullptr);
		if (Status == STATUS_SECUREBOOT_NOT_ENABLED)
			Printf(L"SystemKernelDebuggingAllowed: STATUS_SECUREBOOT_NOT_ENABLED\n\n");
		else if (!NT_SUCCESS(Status))
			Printf(L"SystemKernelDebuggingAllowed: error %08X\n\n", Status);
		else
			Printf(L"SystemKernelDebuggingAllowed: %u\n\n", KernelDebuggingAllowed);

		// NB: in RS3, this changed to require size 36 (from 4). Output is still all zeroes
		SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION CodeIntegrityUnlockInfos[9] = { 0 };
		UCHAR Zeroes[sizeof(CodeIntegrityUnlockInfos)] = { 0 };
		Status = NtQuerySystemInformation(SystemCodeIntegrityUnlockInformation,
											&CodeIntegrityUnlockInfos[0],
											sizeof(CodeIntegrityUnlockInfos),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemCodeIntegrityUnlockInformation: error %08X\n\n", Status);
		else if (memcmp(CodeIntegrityUnlockInfos, Zeroes, sizeof(CodeIntegrityUnlockInfos)) == 0)
		{
			Printf(L"SystemCodeIntegrityUnlockInformation: 0\n\n");
		}
		else
		{
			// This has to be incorrect, but leave it in just in case the output changes to something non-zero later
			for (ULONG i = 0; i < ARRAYSIZE(CodeIntegrityUnlockInfos); ++i)
			{
				const SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION CodeIntegrityUnlockInfo = CodeIntegrityUnlockInfos[i];
				Printf(L"SystemCodeIntegrityUnlockInformation:\n\t- Locked: %u"
					L"\n\t- Unlockable: %u\n\t- UnlockApplied: %u\n\t- Flags: %04X\n\n",
					CodeIntegrityUnlockInfo.u1.s1.Locked, CodeIntegrityUnlockInfo.u1.s1.Unlockable,
					CodeIntegrityUnlockInfo.u1.s1.UnlockApplied, CodeIntegrityUnlockInfo.u1.Flags);
			}
		}
	}

	// Make it so the console doesn't go away immediately when opening the exe from explorer
	Printf(L"Press any key to exit.\n");
	WaitForKey();

	return Status;
}
