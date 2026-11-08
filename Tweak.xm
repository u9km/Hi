// anogs killer — name-based, no offsets
// survives anogs version bumps. resolves every function by symbol.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import <unistd.h>

// إصلاح مشكلة الـ Linker (Name Mangling)
extern "C" {
    #import "litehook.h"
}

// ============================================================
// CONFIG
// ============================================================
#define FULL_DISABLE_ANOGS 1

// ============================================================
// DYLD / IMAGE HELPERS
// ============================================================
static const struct mach_header_64 *g_anogs_hdr = NULL;
static intptr_t g_anogs_slide = 0;

static void find_anogs_image(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, "anogs.framework")) {
            g_anogs_hdr   = (const struct mach_header_64 *)_dyld_get_image_header(i);
            g_anogs_slide = _dyld_get_image_vmaddr_slide(i);
            return;
        }
    }
}

static void *anogs_handle(void) {
    static void *h = NULL;
    if (h) return h;
    h = dlopen("@rpath/anogs.framework/anogs", RTLD_NOLOAD | RTLD_NOW);
    if (!h) h = dlopen("anogs.framework/anogs", RTLD_NOLOAD | RTLD_NOW);
    return h;
}

// ============================================================
// EXPORT-TRIE SCANNER (Flattened for Clang)
// ============================================================
typedef struct {
    const uint8_t *base;
    const uint8_t *end;
    const char *needle;
    uintptr_t found;
} export_ctx_t;

static void scan_walk(export_ctx_t *ctx, const uint8_t *node, const char *prefix, size_t plen) {
    if (ctx->found || node >= ctx->end) return;
    const uint8_t *cursor = node;
    uint64_t term_size = 0;
    int s = 0; uint8_t b;
    
    do { b = *cursor++; term_size |= (uint64_t)(b & 0x7f) << s; s += 7; } while (b & 0x80);
    
    if (term_size) {
        uint64_t flags = 0, off = 0;
        s = 0; do { b = *cursor++; flags |= (uint64_t)(b & 0x7f) << s; s += 7; } while (b & 0x80);
        s = 0; do { b = *cursor++; off |= (uint64_t)(b & 0x7f) << s; s += 7; } while (b & 0x80);
        
        if (strstr(prefix, ctx->needle)) {
            ctx->found = (uintptr_t)ctx->base + off;
            return;
        }
    }
    uint8_t nchild = *cursor++;
    for (uint8_t i = 0; i < nchild && !ctx->found; i++) {
        const uint8_t *label_start = cursor;
        while (*cursor) cursor++;
        cursor++;
        uint64_t child_off = 0;
        s = 0; do { b = *cursor++; child_off |= (uint64_t)(b & 0x7f) << s; s += 7; } while (b & 0x80);
        
        char newpfx[512];
        size_t ll = (cursor - label_start) - 1;
        if (plen + ll < sizeof(newpfx)) {
            memcpy(newpfx, prefix, plen);
            memcpy(newpfx + plen, label_start, ll);
            size_t nl = plen + ll;
            newpfx[nl] = 0;
            scan_walk(ctx, node + child_off, newpfx, nl);
        }
    }
}

static uintptr_t scan_exports_for(const char *needle) {
    if (!g_anogs_hdr) return 0;
    const uint8_t *base = (const uint8_t *)g_anogs_hdr;
    uint32_t export_off = 0, export_sz = 0;

    const uint8_t *lc = base + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < g_anogs_hdr->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmd == LC_DYLD_EXPORTS_TRIE) {
            const struct linkedit_data_command *d = (const struct linkedit_data_command *)cmd;
            export_off = d->dataoff; export_sz = d->datasize;
        } else if (cmd->cmd == LC_DYLD_INFO || cmd->cmd == LC_DYLD_INFO_ONLY) {
            const struct dyld_info_command *d = (const struct dyld_info_command *)cmd;
            if (d->export_size) { export_off = d->export_off; export_sz = d->export_size; }
        }
        lc += cmd->cmdsize;
    }
    if (!export_off || !export_sz) return 0;

    export_ctx_t ctx;
    ctx.base = base;
    ctx.end = base + export_off + export_sz;
    ctx.needle = needle;
    ctx.found = 0;

    scan_walk(&ctx, base + export_off, "", 0);
    return ctx.found;
}

// ============================================================
// SYMBOL RESOLVER
// ============================================================
static uintptr_t resolve_sym(const char *mangled, const char *bare) {
    void *h = anogs_handle();
    if (h && mangled) { void *p = dlsym(h, mangled); if (p) return (uintptr_t)p; }
    if (h && bare)    { void *p = dlsym(h, bare);    if (p) return (uintptr_t)p; }
    if (mangled) { uintptr_t p = scan_exports_for(mangled); if (p) return p; }
    if (bare)    { uintptr_t p = scan_exports_for(bare);    if (p) return p; }
    return 0;
}

// ============================================================
// OBJC HOOKS
// ============================================================
static NSUUID *hk_identifierForVendor(id self, SEL _cmd) {
    static NSUUID *uuid = nil;
    if (!uuid) uuid = [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
    return uuid;
}
static BOOL hk_GSDK_isJailbroken(id self, SEL _cmd) { return NO; }
static void hk_GSDK_reportEvent(id self, SEL _cmd, id ev, id prm) {}
static BOOL hk_GSDK_checkSignature(id self, SEL _cmd) { return YES; }
static BOOL hk_GSDKInitManager_checkEnvironmentIntegrity(id self, SEL _cmd) { return YES; }
static BOOL hk_GSDKHttpDnsResolver_verifyResponse(id self, SEL _cmd, id r) { return YES; }
static void hk_TSSAntiCheatManager_reportCheatData(id self, SEL _cmd, id d) {}

static void hook_method(const char *cls, const char *sel, void *fn) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (!m) return;
    method_setImplementation(m, (IMP)fn);
}

static void wait_for_class(const char *name, int ms) {
    for (int t = 0; t < ms; t += 50) {
        if (objc_getClass(name)) return;
        usleep(50000);
    }
}

// ============================================================
// C REPLACEMENTS (FULL mode)
// ============================================================
#if FULL_DISABLE_ANOGS
static int hk_SFileVerifyPiece(void *f, uint32_t p)              { return 1; }
static int hk_IFSVerifyFile(void *f)                              { return 1; }
static int hk_IFSReadPieceVerified(void *f, uint32_t p, void *b)  { return 1; }
static int hk_SFileReadPieceVerified(void *f, uint32_t p, void *b, uint32_t *o) { return 1; }
static int hk_verify_file_md5(const char *a, const char *b)       { return 0; }
static int hk_IFSGetFileSize(void *f, uint64_t *out) { if (out) *out = 0; return 1; }

static int hk_CheckFileMd5(const char *path, char *out) {
    if (!path || !out) return -1;
    if (strstr(path, "patch") || strstr(path, "game_patch") || strstr(path, ".pak")) {
        strncpy(out, "d41d8cd98f00b204e9800998ecf8427e", 32);
        out[32] = 0;
        return 0;
    }
    return -1;
}
static int hk_GetFileBufferMd5(const void *buf, size_t len, char *out) {
    if (!out) return -1;
    strncpy(out, "e10adc3949ba59abbe56e057f20f883e", 32);
    out[32] = 0;
    return 0;
}

static int hk_RSA_verify(int t, const uint8_t *s, uint32_t sl, const uint8_t *m, uint32_t ml, void *r) { return 1; }
static int hk_RSA_sign(int t, const uint8_t *m, uint32_t ml, uint8_t *s, uint32_t *sl, void *r) { return 1; }
static int hk_EVP_PKEY_verify(void *p, const uint8_t *s, size_t sl, const uint8_t *m, size_t ml) { return 1; }
static int hk_EVP_PKEY_verify_init(void *ctx)                     { return 1; }
static int hk_X509_verify_cert(void *x)                           { return 1; }
static int hk_X509_check_private_key(void *x, void *p)            { return 1; }
static int hk_PEM_read_bio_PrivateKey(void *a, void **b, void *c, void *d) { return 1; }
static int hk_SSL_CTX_use_PrivateKey_file(void *c, const char *f, int t) { return 1; }
static int hk_SSL_CTX_check_private_key(void *c)                  { return 1; }
static int hk_SSL_CTX_load_verify_locations(void *c, const char *ca, const char *cap) { return 1; }

static int hk_SFileOpenArchive(const char *n, uint32_t p, uint32_t f, void **h) { return 1; }
static int hk_SFileOpenFile(void *arc, const char *n, void **h)  { return 1; }
static int hk_IFSOpenArchive(const char *n, void **h)            { return 1; }
static int hk_IFSOpenFile(void *ifs, const char *n, void **h)    { return 1; }
static int hk_SFileCloseFile(void *h)                            { return 1; }
static int hk_SFileCloseArchive(void *h)                         { return 1; }

static int hk_is_jb(void)              { return 0; }
static int hk_ROOTED(void)             { return 0; }
static int hk_DEBUGGER_ATTACHED(void)  { return 0; }
static int hk_isDebuggerAttached(void) { return 0; }
static int hk_checkJailbreak(void)     { return 0; }
static int hk_hasCydia(void)           { return 0; }
static int hk_isJailbroken(void)       { return 0; }
static int hk_amIBeingDebugged(void)   { return 0; }
static int hk_ptrace(int r, int p, void *a, int d) { return (r == 31) ? 0 : -1; }
static int hk_task_for_pid(mach_port_name_t t, int p, mach_port_name_t *o) { return 5; }
static int hk_vm_read_overwrite(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, mach_vm_address_t d, mach_vm_size_t *o) { return 5; }
static int hk_vm_write(mach_port_name_t t, mach_vm_address_t a, uint32_t d, mach_vm_size_t s) { return 5; }
static int hk_vm_protect(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, int mx, int pr) { return 5; }
static int hk_mach_vm_protect(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, int mx, int pr) { return 5; }

static int hk_sysctl(int *n, uint32_t l, void *o, size_t *ol, void *nw, size_t nl) { return -1; }
static int hk_sysctlbyname(const char *n, void *o, size_t *ol, void *nw, size_t nl) {
    if (n && (strstr(n, "debug") || strstr(n, "kern.proc"))) {
        if (o && ol) bzero(o, *ol);
        return 0;
    }
    return -1;
}
static void *hk_dlopen(const char *n, int f)  { return NULL; }
static void *hk_dlsym(void *h, const char *n) { return NULL; }
#endif

// ============================================================
// SYMBOL TABLE
// ============================================================
#if FULL_DISABLE_ANOGS
typedef struct { const char *mangled; const char *bare; void *replacement; } hook_entry;

static hook_entry g_hooks[] = {
    { "__ZL19my_SFileVerifyPieceP3$_0j",                  "SFileVerifyPiece",           (void*)hk_SFileVerifyPiece           },
    { "__ZL16my_IFSVerifyFileP3$_0",                      "IFSVerifyFile",              (void*)hk_IFSVerifyFile              },
    { "__ZL23my_IFSReadPieceVerifiedP3$_0jPv",            "IFSReadPieceVerified",       (void*)hk_IFSReadPieceVerified       },
    { "__ZL25my_SFileReadPieceVerifiedP3$_0jPvPj",        "SFileReadPieceVerified",     (void*)hk_SFileReadPieceVerified     },
    { "__ZL18my_verify_file_md5PKcS0_",                   "verify_file_md5",            (void*)hk_verify_file_md5            },
    { "__ZL17my_IFSGetFileSizeP3$_0Py",                   "IFSGetFileSize",             (void*)hk_IFSGetFileSize             },
    { "__ZL15my_CheckFileMd5PKcPc",                       "CheckFileMd5",               (void*)hk_CheckFileMd5               },
    { "__ZL19my_GetFileBufferMd5PKvmPc",                  "GetFileBufferMd5",           (void*)hk_GetFileBufferMd5           },
    { "__ZL13my_RSA_verifyiPKhjS0_jPv",                   "RSA_verify",                 (void*)hk_RSA_verify                 },
    { "__ZL11my_RSA_signiPKhjPhPjPv",                     "RSA_sign",                   (void*)hk_RSA_sign                   },
    { "__ZL18my_EVP_PKEY_verifyPvPKhmS1_m",               "EVP_PKEY_verify",            (void*)hk_EVP_PKEY_verify            },
    { "__ZL23my_EVP_PKEY_verify_initPv",                  "EVP_PKEY_verify_init",       (void*)hk_EVP_PKEY_verify_init       },
    { "__ZL19my_X509_verify_certPv",                      "X509_verify_cert",           (void*)hk_X509_verify_cert           },
    { "__ZL25my_X509_check_private_keyPvS_",              "X509_check_private_key",     (void*)hk_X509_check_private_key     },
    { "__ZL26my_PEM_read_bio_PrivateKeyPvPS_S_S_",        "PEM_read_bio_PrivateKey",    (void*)hk_PEM_read_bio_PrivateKey    },
    { "__ZL30my_SSL_CTX_use_PrivateKey_filePvPKci",       "SSL_CTX_use_PrivateKey_file",(void*)hk_SSL_CTX_use_PrivateKey_file},
    { "__ZL28my_SSL_CTX_check_private_keyPv",             "SSL_CTX_check_private_key",  (void*)hk_SSL_CTX_check_private_key  },
    { "__ZL32my_SSL_CTX_load_verify_locationsPvPKcS1_",   "SSL_CTX_load_verify_locations",(void*)hk_SSL_CTX_load_verify_locations},
    { "__ZL19my_SFileOpenArchivePKcjjPP3$_0",             "SFileOpenArchive",           (void*)hk_SFileOpenArchive           },
    { "__ZL16my_SFileOpenFileP3$_0PKcPS0_",               "SFileOpenFile",              (void*)hk_SFileOpenFile              },
    { "__ZL17my_IFSOpenArchivePKcPP3$_0",                 "IFSOpenArchive",             (void*)hk_IFSOpenArchive             },
    { "__ZL14my_IFSOpenFileP3$_0PKcPS0_",                 "IFSOpenFile",                (void*)hk_IFSOpenFile                },
    { "__ZL17my_SFileCloseFileP3$_0",                     "SFileCloseFile",             (void*)hk_SFileCloseFile             },
    { "__ZL20my_SFileCloseArchiveP3$_0",                  "SFileCloseArchive",          (void*)hk_SFileCloseArchive          },
    { "__ZL8my_is_jbv",                                   "is_jb",                      (void*)hk_is_jb                      },
    { "__ZL9my_ROOTEDv",                                  "ROOTED",                     (void*)hk_ROOTED                     },
    { "__ZL20my_DEBUGGER_ATTACHEDv",                      "DEBUGGER_ATTACHED",          (void*)hk_DEBUGGER_ATTACHED          },
    { "__ZL21my_isDebuggerAttachedv",                     "isDebuggerAttached",         (void*)hk_isDebuggerAttached         },
    { "__ZL17my_checkJailbreakv",                         "checkJailbreak",             (void*)hk_checkJailbreak             },
    { "__ZL11my_hasCydiav",                               "hasCydia",                   (void*)hk_hasCydia                   },
    { "__ZL17my_isJailbroken_cv",                         "isJailbroken",               (void*)hk_isJailbroken               },
    { "__ZL19my_amIBeingDebuggedv",                       "amIBeingDebugged",           (void*)hk_amIBeingDebugged           },
    { "__ZL9my_ptraceiiPci",                              "ptrace",                     (void*)hk_ptrace                     },
    { "__ZL15my_task_for_pidjiPj",                        "task_for_pid",               (void*)hk_task_for_pid               },
    { "__ZL20my_vm_read_overwritejmmmPm",                 "vm_read_overwrite",          (void*)hk_vm_read_overwrite          },
    { "__ZL11my_vm_writejmmj",                            "vm_write",                   (void*)hk_vm_write                   },
    { "__ZL13my_vm_protectjmmii",                         "vm_protect",                 (void*)hk_vm_protect                 },
    { "__ZL18my_mach_vm_protectjyyii",                    "mach_vm_protect",            (void*)hk_mach_vm_protect            },
    { "__ZL9my_sysctlPijPvPmS0_m",                        "sysctl",                     (void*)hk_sysctl                     },
    { "__ZL15my_sysctlbynamePKcPvPmS1_m",                 "sysctlbyname",               (void*)hk_sysctlbyname               },
    { "__ZL9my_dlopenPKci",                               "dlopen",                     (void*)hk_dlopen                     },
    { "__ZL8my_dlsymPvPKc",                               "dlsym",                      (void*)hk_dlsym                      },
};
#endif

// ============================================================
// INSTALLERS
// ============================================================
static void install_objc_hooks(void) {
    wait_for_class("GSDK", 5000);
    wait_for_class("GSDKInitManager", 2000);
    wait_for_class("GSDKHttpDnsResolver", 2000);
    wait_for_class("TSSAntiCheatManager", 5000);

    hook_method("UIDevice", "identifierForVendor", (void *)hk_identifierForVendor);
    hook_method("GSDK", "isJailbroken", (void *)hk_GSDK_isJailbroken);
    hook_method("GSDK", "reportEvent:params:", (void *)hk_GSDK_reportEvent);
    hook_method("GSDK", "checkSignature", (void *)hk_GSDK_checkSignature);
    hook_method("GSDKInitManager", "checkEnvironmentIntegrity", (void *)hk_GSDKInitManager_checkEnvironmentIntegrity);
    hook_method("GSDKHttpDnsResolver", "verifyResponse:", (void *)hk_GSDKHttpDnsResolver_verifyResponse);
    hook_method("TSSAntiCheatManager", "reportCheatData:", (void *)hk_TSSAntiCheatManager_reportCheatData);
}

#if FULL_DISABLE_ANOGS
static int install_c_hooks(void) {
    int hits = 0, misses = 0;
    for (size_t i = 0; i < sizeof(g_hooks)/sizeof(g_hooks[0]); i++) {
        hook_entry *e = &g_hooks[i];
        uintptr_t addr = resolve_sym(e->mangled, e->bare);
        if (!addr) { misses++; continue; }
        
        int rc = litehook_hook_function((void *)addr, e->replacement);
        
        if (rc == 0) hits++;
        else misses++;
    }
    return hits * 1000 + misses;
}
#endif

// ============================================================
// INIT
// ============================================================
__attribute__((constructor))
static void anogs_killer_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < 200 && !g_anogs_hdr; i++) {
                find_anogs_image();
                if (!g_anogs_hdr) usleep(50000);
            }

            install_objc_hooks();

#if FULL_DISABLE_ANOGS
            int packed = install_c_hooks();
            NSLog(@"[anogs-killer] c-hooks: %d hits, %d misses", packed / 1000, packed % 1000);
#endif
            NSLog(@"[anogs-killer] armed");
        });
    }
}
