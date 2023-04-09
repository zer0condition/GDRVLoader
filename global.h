#pragma once


#include "utils/ntdll.h"
#include <ntstatus.h>
#include <iostream>

const BYTE Pattern_CipInit_1709[17] = "\x4c\x8b\xcb\x4c\x8b\xc7\x48\x8b\xd6\x8b\xcd\xe8\x00\x00\x00\x00";
const BYTE Pattern_CipInit[13] = "\x41\x8b\xca\x48\x83\xc4\x28\xe9\x00\x00\x00\x00";
const BYTE Pattern_gCiOptions[10] = "\x49\x8b\xe9\x89\x0d\x00\x00\x00\x00";
const BYTE Pattern_gCiEnabled[5] = "\xeb\x06\x88\x1d";


#ifdef __cplusplus
extern "C" {
#endif

#define PAGE_SIZE 0x1000

#if defined(__cplusplus) && \
	((defined(_MSC_VER) && (_MSC_VER >= 1900)) || defined(__clang__))
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

#if defined(__clang__)
#undef FIELD_OFFSET
#undef UFIELD_OFFSET
#define FIELD_OFFSET(type, field)	((LONG)__builtin_offsetof(type, field))
#define UFIELD_OFFSET(type, field)	((ULONG)__builtin_offsetof(type, field))notion
#endif

// swind2.cpp
NTSTATUS
WindLoadDriver(
	_In_ PWCHAR LoaderName,
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	);

NTSTATUS
WindUnloadDriver(
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	);

// sysinfo.cpp
NTSTATUS
PrintSystemInformation(
	);

// pe.cpp
NTSTATUS
MapFileSectionView(
	_In_ PCWCHAR Filename,
	_In_ BOOLEAN ForceDisableAslr,
	_Out_ PVOID *ImageBase,
	_Out_ PSIZE_T ViewSize
	);

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCSTR RoutineName
	);

FORCEINLINE
ULONG
RtlNtMajorVersion(
	)
{
	return *reinterpret_cast<PULONG>(0x7FFE0000 + 0x026C);
}

FORCEINLINE
ULONG
RtlNtMinorVersion(
	)
{
	return *reinterpret_cast<PULONG>(0x7FFE0000 + 0x0270);
}

CONSTEXPR
FORCEINLINE
LONGLONG
RtlMsToTicks(
	_In_ ULONG Milliseconds
	)
{
	return 10000LL * static_cast<LONGLONG>(Milliseconds);
}

FORCEINLINE
VOID
RtlSleep(
	_In_ ULONG Milliseconds
	)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -1 * RtlMsToTicks(Milliseconds);
	NtDelayExecution(FALSE, &Timeout);
}

CONSTEXPR
FORCEINLINE
BOOLEAN
IsWin64(
	)
{
#if defined(_WIN64) || defined(_M_AMD64)
	return TRUE;
#else
	return FALSE;
#endif
}

inline
VOID
WaitForKey(
	)
{
	HANDLE StdIn = NtCurrentPeb()->ProcessParameters->StandardInput;
	INPUT_RECORD InputRecord = { 0 };
	ULONG NumRead;
	while (InputRecord.EventType != KEY_EVENT || !InputRecord.Event.KeyEvent.bKeyDown || InputRecord.Event.KeyEvent.dwControlKeyState !=
		(InputRecord.Event.KeyEvent.dwControlKeyState & ~(RIGHT_CTRL_PRESSED | LEFT_CTRL_PRESSED)))
	{
		ReadConsoleInputW(StdIn, &InputRecord, 1, &NumRead);
	}
}

#ifdef NT_ANALYSIS_ASSUME
// wdm.h's asserts are incompatible with both clang and MS's own analyzer
#undef NT_ANALYSIS_ASSUME
#undef NT_ASSERT_ACTION
#undef NT_ASSERTMSG_ACTION
#undef NT_ASSERTMSGW_ACTION
#undef NT_ASSERT_ASSUME
#undef NT_ASSERTMSG_ASSUME
#undef NT_ASSERTMSGW_ASSUME
#undef NT_ASSERT
#undef NT_ASSERTMSG
#undef NT_ASSERTMSGW
#endif

#ifdef _PREFAST_
#define NT_ANALYSIS_ASSUME(...) _Analysis_assume_(__VA_ARGS__)
#elif defined(_DEBUG) || defined(DBG)
#define NT_ANALYSIS_ASSUME(...) ((void) 0)
#else
#define NT_ANALYSIS_ASSUME(...) __noop(__VA_ARGS__)
#endif

#if !defined(__clang__)
#if !defined(DbgRaiseAssertionFailure)
#define DbgRaiseAssertionFailure() __int2c()
#endif

#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L#_exp), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L##_msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", _msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)
#else
#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? (__debugbreak(), FALSE) : TRUE)
#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#endif

#if defined(_DEBUG) || defined(DBG)
#define NT_ASSERT_ASSUME(_exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERT_ACTION(_exp))

#define NT_ASSERTMSG_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSG_ACTION(_msg, _exp))

#define NT_ASSERTMSGW_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSGW_ACTION(_msg, _exp))

#define NT_ASSERT					NT_ASSERT_ASSUME
#define NT_ASSERTMSG				NT_ASSERTMSG_ASSUME
#define NT_ASSERTMSGW				NT_ASSERTMSGW_ASSUME
#else
#define NT_ASSERT(_exp)				((void) 0)
#define NT_ASSERTMSG(_msg, _exp)	((void) 0)
#define NT_ASSERTMSGW(_msg, _exp)	((void) 0)
#endif

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#pragma warning(push)
#pragma warning(disable:4309)
template<ULONG N>
struct static_print // Usage: static_print<FIELD_OFFSET(S, v)>()() prints the value as a compiler warning
{
	CHAR operator()() CONST { return N + 256; }
};
#pragma warning(pop)

template<typename T>
void print_size() { static_print<sizeof(T)>()(); }
#endif
