#include <Windows.h>

#if !defined(_MSC_VER) || !defined(_M_IX86)
#error osedgadgets.c requires the 32-bit MSVC compiler
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP) || defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
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

#if defined(OSED_PROFILE_EASY) || defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP) || defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
__declspec(dllexport) __declspec(naked) void helper_sequence_01(void) {
    __asm {
        jmp esp
    }
}
#endif

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP) || defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
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
        /* Emit the near-return opcode directly. A bare `ret` as the sole */
        /* instruction in a naked function makes the MSVC inline assembler */
        /* encode a frame-cleanup `ret 0` (C2 00 00); this gadget must be a */
        /* single-byte near return (C3) ROP NOP/trampoline. */
        _emit 0xC3
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

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP) || defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)
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

#if defined(OSED_PROFILE_DEP) || defined(OSED_PROFILE_ASLR_DEP)
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

#if defined(OSED_PROFILE_DEP3)
/*
 * DEP-3 is the exam-prep gadget vocabulary.  Every shortcut from DEP/DEP-2 is
 * gone: no direct pop edx, multi-register clobber on every bulk pop, an offset
 * dereference that forces pointer arithmetic, a wider ESP adjustment, and NEG
 * encoding for constants that would otherwise contain bad characters.  The
 * staged chain is 28 DWORDs and requires careful register ordering.
 */
__declspec(dllexport) __declspec(naked) void helper_sequence_30(void) {
    __asm {
        pop eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_31(void) {
    __asm {
        xchg eax, esp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_32(void) {
    __asm {
        pop ecx
        pop ebp
        pop edi
        pop eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_33(void) {
    __asm {
        xchg eax, edx
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_34(void) {
    __asm {
        pop ebx
        pop ebp
        pop eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_35(void) {
    __asm {
        pop ebp
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_36(void) {
    __asm {
        mov eax, dword ptr [eax + 0x10]
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_37(void) {
    __asm {
        xchg eax, esi
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_38(void) {
    __asm {
        add esp, 0x1C
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_39(void) {
    __asm {
        pushad
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_40(void) {
    __asm {
        _emit 0xC3
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_41(void) {
    __asm {
        neg eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_42(void) {
    __asm {
        mov dword ptr [esi], eax
        ret
    }
}

__declspec(dllexport) __declspec(naked) void helper_sequence_43(void) {
    __asm {
        xchg eax, ebx
        ret
    }
}
#endif
