#include <Windows.h>

#if !defined(_MSC_VER) || !defined(_M_IX86)
#error osedgadgets.c requires the 32-bit MSVC compiler
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
__declspec(dllexport) volatile DWORD helper_writable_slot[4] = {0};

/* Keeps a VirtualProtect import and import thunk in the helper DLL. */
__declspec(dllexport) BOOL __stdcall helper_memory_protect(
    LPVOID address,
    SIZE_T size,
    DWORD new_protection,
    PDWORD old_protection) {
    return VirtualProtect(address, size, new_protection, old_protection);
}
#endif

#if defined(OSED_PROFILE_EASY) || defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
__declspec(dllexport) __declspec(naked) void helper_sequence_01(void) {
    __asm {
        jmp esp
    }
}
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
__declspec(dllexport) __declspec(naked) void helper_sequence_02(void) {
    __asm {
        pop eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_03(void) {
    __asm {
        pop ecx
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_04(void) {
    __asm {
        pop edx
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_05(void) {
    __asm {
        pop ebx
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_06(void) {
    __asm {
        pop ebp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_07(void) {
    __asm {
        pop esi
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_08(void) {
    __asm {
        pop edi
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_09(void) {
    __asm {
        neg eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_10(void) {
    __asm {
        xchg eax, ebx
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_11(void) {
    __asm {
        pushad
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_12(void) {
    __asm {
        ret
    }
}
#endif

#if defined(OSED_PROFILE_SEH)
__declspec(dllexport) __declspec(naked) void helper_sequence_13(void) {
    __asm {
        pop eax
        pop ebx
        ret
    }
}
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
__declspec(dllexport) __declspec(naked) void helper_sequence_14(void) {
    __asm {
        xchg eax, esp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_15(void) {
    __asm {
        mov eax, dword ptr [eax]
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_16(void) {
    __asm {
        xchg eax, esi
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_17(void) {
    __asm {
        mov dword ptr [esi], eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_18(void) {
    __asm {
        add esp, 0x10
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_19(void) {
    __asm {
        call eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_20(void) {
    __asm {
        jmp eax
    }
}
#endif

#if defined(OSED_PROFILE_EASY)
__declspec(dllexport) __declspec(naked) void helper_sequence_21(void) {
    __asm {
        call esp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_22(void) {
    __asm {
        push esp
        ret
    }
}
#endif
