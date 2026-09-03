// Package apis holds the API classification tables shared by the pe, triage
// and cdb frontends. These drive both import categorization (static PE view)
// and per-function sink scoring (disassembly / cdb view).
//
// All tables are plain ASCII. Membership is case sensitive on purpose: PE
// import names and cdb symbol names preserve their original casing, and the
// A/W suffixes matter for exploitation.
package apis

// Category names used in reports and JSON output.
const (
	CatExploitation = "exploitation"
	CatDangerousCRT = "dangerous_crt"
	CatNetworking   = "networking"
	CatRegistry     = "registry"
	CatProcess      = "process"
	CatCrypto       = "crypto"
	CatFileIO       = "file_io"
)

// Exploitation APIs: primitives commonly chained in a working exploit
// (memory protection changes, allocation, library loading, command exec).
var Exploitation = set(
	"VirtualProtect", "VirtualProtectEx",
	"VirtualAlloc", "VirtualAllocEx",
	"NtProtectVirtualMemory",
	"WriteProcessMemory", "NtWriteVirtualMemory",
	"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
	"GetProcAddress",
	"WinExec", "ShellExecuteA", "ShellExecuteW",
	"ShellExecuteExA", "ShellExecuteExW",
	"CreateProcessA", "CreateProcessW",
	"HeapCreate", "HeapAlloc", "HeapFree",
	"SetProcessDEPPolicy",
	"NtSetInformationProcess",
	"MapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
)

// DangerousCRT: unbounded or easily-misused copy/format routines. These are
// the primary sinks that make a function worth reversing first.
var DangerousCRT = set(
	"strcpy", "strncpy", "lstrcpyA", "lstrcpyW", "wcscpy", "wcsncpy",
	"strcat", "strncat", "lstrcatA", "lstrcatW", "wcscat", "wcsncat",
	"sprintf", "_snprintf", "vsprintf", "swprintf", "wsprintfA", "wsprintfW",
	"gets", "_gets",
	"memcpy", "memmove", "wmemcpy", "CopyMemory", "RtlCopyMemory",
	"scanf", "sscanf", "fscanf",
	"printf", "fprintf", "vprintf", "vfprintf",
)

// Networking: input sources. A dangerous sink fed from one of these is the
// classic remote overflow shape.
var Networking = set(
	"recv", "recvfrom", "send", "sendto",
	"accept", "bind", "listen", "connect",
	"socket", "WSAStartup", "WSASocketA", "WSASocketW",
	"WSARecv", "WSASend", "WSAAccept", "WSAConnect",
	"InternetOpenA", "InternetOpenW",
	"InternetReadFile",
	"InternetOpenUrlA", "InternetOpenUrlW",
	"HttpOpenRequestA", "HttpOpenRequestW",
	"HttpSendRequestA", "HttpSendRequestW",
	"URLDownloadToFileA", "URLDownloadToFileW",
)

var Registry = set(
	"RegOpenKeyExA", "RegOpenKeyExW",
	"RegSetValueExA", "RegSetValueExW",
	"RegCreateKeyExA", "RegCreateKeyExW",
	"RegQueryValueExA", "RegQueryValueExW",
	"RegDeleteKeyA", "RegDeleteKeyW",
	"RegDeleteValueA", "RegDeleteValueW",
)

var Process = set(
	"CreateThread", "CreateRemoteThread",
	"OpenProcess", "TerminateProcess",
	"CreateToolhelp32Snapshot",
	"NtQueryInformationProcess",
	"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
	"OutputDebugStringA", "OutputDebugStringW",
)

var Crypto = set(
	"CryptAcquireContextA", "CryptAcquireContextW",
	"CryptEncrypt", "CryptDecrypt",
	"CryptCreateHash", "CryptHashData",
	"CryptDeriveKey", "CryptGenKey",
	"CryptImportKey", "CryptExportKey",
)

var FileIO = set(
	"CreateFileA", "CreateFileW",
	"ReadFile", "WriteFile",
	"SetFilePointer", "SetFilePointerEx",
	"DeleteFileA", "DeleteFileW",
	"CopyFileA", "CopyFileW",
	"MoveFileA", "MoveFileW",
)

// FormatFamily: functions whose format string is worth checking for a
// format-string vulnerability (non-literal first/format argument).
var FormatFamily = set(
	"printf", "fprintf", "sprintf", "_snprintf", "vsprintf",
	"swprintf", "wsprintfA", "wsprintfW", "vprintf", "vfprintf",
	"syslog",
)

// Category returns the category name for an API, or "" if uncategorized.
// The A/W and decoration variants are matched exactly; callers that want to
// normalize should strip a leading underscore before lookup if desired.
func Category(name string) string {
	switch {
	case Exploitation[name]:
		return CatExploitation
	case DangerousCRT[name]:
		return CatDangerousCRT
	case Networking[name]:
		return CatNetworking
	case Registry[name]:
		return CatRegistry
	case Process[name]:
		return CatProcess
	case Crypto[name]:
		return CatCrypto
	case FileIO[name]:
		return CatFileIO
	}
	return ""
}

// The sets below drive per-function ranking (analysis package). They are
// finer-grained than the report categories above: real triage cares whether a
// copy is bounded, and whether a "networking" call actually reads attacker
// bytes or is just connection setup.

// UnboundedCopy: copy/format routines with no destination length - the primary
// stack-overflow sinks. A function calling one of these is the prime suspect.
var UnboundedCopy = set(
	"strcpy", "strcat", "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
	"wcscpy", "wcscat", "gets", "_gets",
	"sprintf", "vsprintf", "swprintf", "wsprintfA", "wsprintfW", "wvsprintfA", "wvsprintfW",
	"scanf", "sscanf", "fscanf",
)

// BoundedCopy: length-taking copies. Still dangerous (wrong length, off-by-one)
// but a weaker signal than an unbounded copy.
var BoundedCopy = set(
	"strncpy", "strncat", "wcsncpy", "wcsncat",
	"memcpy", "memmove", "wmemcpy", "CopyMemory", "RtlCopyMemory", "_snprintf",
)

// InputRead: functions that actually read attacker-controlled bytes. Only these
// count as an input "source"; socket/bind/listen/accept are connection setup,
// not input, and must not make a boilerplate function look like a handler.
var InputRead = set(
	"recv", "recvfrom", "WSARecv", "WSARecvFrom",
	"ReadFile", "ReadFileEx", "InternetReadFile",
	"fread", "read", "_read", "ReadConsoleA", "ReadConsoleW",
)

// ExecPrimitive: the memory/exec primitives that matter for a working exploit.
// A deliberately small subset of Exploitation (Heap* etc. are too common to
// carry ranking signal).
var ExecPrimitive = set(
	"VirtualProtect", "VirtualProtectEx", "VirtualAlloc", "VirtualAllocEx",
	"WriteProcessMemory", "WinExec", "system",
	"CreateProcessA", "CreateProcessW",
	"LoadLibraryA", "LoadLibraryW", "ShellExecuteA", "ShellExecuteW",
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}
