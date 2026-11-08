// anogs killer — comprehensive bypass
// covers detection, MRPCS reporting, and anti-hook vectors

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import <unistd.h>

extern "C" {
    #import "litehook.h"
}

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
// EXPORT-TRIE SCANNER
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
    return [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
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
// SAFE C REPLACEMENTS (Detection & Memory)
// ============================================================
static int hk_is_jb(void)              { return 0; }
static int hk_ROOTED(void)             { return 0; }
static int hk_DEBUGGER_ATTACHED(void)  { return 0; }
static int hk_isDebuggerAttached(void) { return 0; }
static int hk_checkJailbreak(void)     { return 0; }
static int hk_hasCydia(void)           { return 0; }
static int hk_isJailbroken(void)       { return 0; }
static int hk_amIBeingDebugged(void)   { return 0; }

// ptrace: block PT_DENY_ATTACH
static int hk_ptrace(int r, int p, void *a, int d) { return (r == 31) ? 0 : -1; }

// Memory access blockers: prevent anti-hook checks
static int hk_task_for_pid(mach_port_name_t t, int p, mach_port_name_t *o) { return 5; } // KERN_FAILURE
static int hk_vm_read_overwrite(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, mach_vm_address_t d, mach_vm_size_t *o) { return 5; }
static int hk_vm_write(mach_port_name_t t, mach_vm_address_t a, uint32_t d, mach_vm_size_t s) { return 5; }
static int hk_vm_protect(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, int m, int p) { return 5; }
static int hk_mach_vm_protect(mach_port_name_t t, mach_vm_address_t a, mach_vm_size_t s, int m, int p) { return 5; }

// sysctl: clear debug flags
static int hk_sysctl(int *n, uint32_t l, void *o, size_t *ol, void *nw, size_t nl) { return -1; }
static int hk_sysctlbyname(const char *n, void *o, size_t *ol, void *nw, size_t nl) {
    if (n && (strstr(n, "debug") || strstr(n, "kern.proc"))) {
        if (o && ol) bzero(o, *ol);
        return 0;
    }
    return -1;
}

// dlopen/dlsym passthrough
static void *hk_dlopen(const char *n, int f)  { return NULL; }
static void *hk_dlsym(void *h, const char *n) { return NULL; }

// ============================================================
// SYMBOL TABLE (Comprehensive)
// ============================================================
typedef struct { const char *mangled; const char *bare; void *replacement; } hook_entry;

static hook_entry g_hooks[] = {
    // --- Detection ---
    { "__ZL8my_is_jbv",                                   "is_jb",                      (void*)hk_is_jb                      },
    { "__ZL9my_ROOTEDv",                                  "ROOTED",                     (void*)hk_ROOTED                     },
    { "__ZL20my_DEBUGGER_ATTACHEDv",                      "DEBUGGER_ATTACHED",          (void*)hk_DEBUGGER_ATTACHED          },
    { "__ZL21my_isDebuggerAttachedv",                     "isDebuggerAttached",         (void*)hk_isDebuggerAttached         },
    { "__ZL17my_checkJailbreakv",                         "checkJailbreak",             (void*)hk_checkJailbreak             },
    { "__ZL11my_hasCydiav",                               "hasCydia",                   (void*)hk_hasCydia                   },
    { "__ZL17my_isJailbroken_cv",                         "isJailbroken",               (void*)hk_isJailbroken               },
    { "__ZL19my_amIBeingDebuggedv",                       "amIBeingDebugged",           (void*)hk_amIBeingDebugged           },
    { "__ZL9my_ptraceiiPci",                              "ptrace",                     (void*)hk_ptrace                     },
    
    // --- Memory / Anti-Hook ---
    { "__ZL15my_task_for_pidjiPj",                        "task_for_pid",               (void*)hk_task_for_pid               },
    { "__ZL20my_vm_read_overwritejmmmPm",                 "vm_read_overwrite",          (void*)hk_vm_read_overwrite          },
    { "__ZL11my_vm_writejmmj",                            "vm_write",                   (void*)hk_vm_write                   },
    { "__ZL13my_vm_protectjmmii",                         "vm_protect",                 (void*)hk_vm_protect                 },
    { "__ZL18my_mach_vm_protectjyyii",                    "mach_vm_protect",            (void*)hk_mach_vm_protect            },
    
    // --- Syscalls ---
    { "__ZL9my_sysctlPijPvPmS0_m",                        "sysctl",                     (void*)hk_sysctl                     },
    { "__ZL15my_sysctlbynamePKcPvPmS1_m",                 "sysctlbyname",               (void*)hk_sysctlbyname               },
    
    // --- File Loading (dlopen/dlsym) ---
    { "__ZL9my_dlopenPKci",                               "dlopen",                     (void*)hk_dlopen                     },
    { "__ZL8my_dlsymPvPKc",                               "dlsym",                      (void*)hk_dlsym                      },
};

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

static int install_c_hooks(void) {
    int hits = 0, misses = 0;
    for (size_t i = 0; i < sizeof(g_hooks)/sizeof(g_hooks[0]); i++) {
        hook_entry *e = &g_hooks[i];
        uintptr_t addr = resolve_sym(e->mangled, e->bare);
        if (!addr) { misses++; continue; }
        
        // LiteHook v2 requires 2 arguments (source, target)
        int rc = litehook_hook_function((void *)addr, e->replacement);
        
        if (rc == 0) hits++;
        else misses++;
    }
    return hits * 1000 + misses;
}

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

            int packed = install_c_hooks();
            NSLog(@"[anogs-killer] comprehensive c-hooks: %d hits, %d misses", packed / 1000, packed % 1000);
            NSLog(@"[anogs-killer] armed");
        });
    }
}
