// ============================================================================
// ShadowBypass XK v9.0 — LiteHook + ObjC Swizzling (No Crash / No JB)
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>

extern "C" {
    #import "litehook.h"
}

// ============================================================
// §1 Safe C Detection Hooks (LiteHook)
// ============================================================
static int hk_is_jb(void) { return 0; }
static int hk_ROOTED(void) { return 0; }
static int hk_DEBUGGER_ATTACHED(void) { return 0; }
static int hk_isDebuggerAttached(void) { return 0; }
static int hk_checkJailbreak(void) { return 0; }
static int hk_hasCydia(void) { return 0; }
static int hk_isJailbroken(void) { return 0; }
static int hk_amIBeingDebugged(void) { return 0; }
static int hk_ptrace(int r, int p, void *a, int d) { return (r == 31) ? 0 : -1; }
static int hk_sysctl(int *n, uint32_t l, void *o, size_t *ol, void *nw, size_t nl) { return -1; }
static int hk_sysctlbyname(const char *n, void *o, size_t *ol, void *nw, size_t nl) { return -1; }

// ============================================================
// §2 ObjC Handlers (From ShadowBypass)
// ============================================================
#define DEF_NO(cls, name)  static BOOL hk_##cls##_##name(id _s, SEL _c) { return NO; }
#define DEF_YES(cls, name) static BOOL hk_##cls##_##name(id _s, SEL _c) { return YES; }
#define DEF_V1(cls, name)  static void hk_##cls##_##name(id _s, SEL _c, id _a1) {}
#define DEF_V2(cls, name)  static void hk_##cls##_##name(id _s, SEL _c, id _a1, id _a2) {}
#define DEF_ID_P0(cls, name) static id hk_##cls##_##name(id _s, SEL _c) { return nil; }

// AntiDataProxy
DEF_NO(AntiDataProxy, checkIntegrity) DEF_NO(AntiDataProxy, isIntegrityOK)
DEF_NO(AntiDataProxy, verifyData) DEF_NO(AntiDataProxy, isDataValid)
DEF_NO(AntiDataProxy, isModified) DEF_NO(AntiDataProxy, isCheat)
DEF_NO(AntiDataProxy, isSuspicious) DEF_NO(AntiDataProxy, antiCheatCheck)
DEF_NO(AntiDataProxy, securityCheck) DEF_NO(AntiDataProxy, hasRisk)
DEF_NO(AntiDataProxy, detectRisk) DEF_NO(AntiDataProxy, isRiskDetected)
DEF_YES(AntiDataProxy, isValid) DEF_YES(AntiDataProxy, isSafe)
DEF_YES(AntiDataProxy, isClean) DEF_YES(AntiDataProxy, verifyIntegrity)
DEF_YES(AntiDataProxy, verifySignature) DEF_YES(AntiDataProxy, shouldPass)
DEF_YES(AntiDataProxy, allowReport) DEF_V1(AntiDataProxy, sendData)
DEF_V1(AntiDataProxy, report) DEF_V1(AntiDataProxy, submit)
DEF_V1(AntiDataProxy, upload) DEF_V1(AntiDataProxy, dispatch)
DEF_V1(AntiDataProxy, flush)

// TssInfoReceiver
DEF_NO(TssInfoReceiver, isRooted) DEF_NO(TssInfoReceiver, isRootedDevice)
DEF_NO(TssInfoReceiver, isJailbroken) DEF_NO(TssInfoReceiver, isJailbreakDevice)
DEF_NO(TssInfoReceiver, isEmulator) DEF_NO(TssInfoReceiver, isEmulatorDevice)
DEF_NO(TssInfoReceiver, isSimulator) DEF_NO(TssInfoReceiver, isDebuggerAttached)
DEF_NO(TssInfoReceiver, isDebugged) DEF_NO(TssInfoReceiver, isModified)
DEF_NO(TssInfoReceiver, isTampered) DEF_NO(TssInfoReceiver, isInjected)
DEF_NO(TssInfoReceiver, isHooked) DEF_NO(TssInfoReceiver, hasCheat)
DEF_NO(TssInfoReceiver, hasCheatTool) DEF_NO(TssInfoReceiver, hasSuspiciousFiles)
DEF_NO(TssInfoReceiver, hasRisk) DEF_NO(TssInfoReceiver, checkEnvironment)
DEF_NO(TssInfoReceiver, checkSecurity) DEF_NO(TssInfoReceiver, checkCheat)
DEF_NO(TssInfoReceiver, detectCheat) DEF_NO(TssInfoReceiver, detectRisk)
DEF_NO(TssInfoReceiver, detectEnvironment) DEF_NO(TssInfoReceiver, isCheating)
DEF_NO(TssInfoReceiver, isCheatDetected) DEF_NO(TssInfoReceiver, isSuspicious)
DEF_NO(TssInfoReceiver, antiCheatCheck) DEF_NO(TssInfoReceiver, securityCheck)
DEF_NO(TssInfoReceiver, shouldReport) DEF_NO(TssInfoReceiver, shouldBlock)
DEF_NO(TssInfoReceiver, needReport) DEF_NO(TssInfoReceiver, needBlock)
DEF_NO(TssInfoReceiver, isBlocked) DEF_NO(TssInfoReceiver, isBanned)
DEF_YES(TssInfoReceiver, isSafe) DEF_YES(TssInfoReceiver, isClean)
DEF_YES(TssInfoReceiver, isEnvironmentClean) DEF_YES(TssInfoReceiver, isEnvironmentSafe)
DEF_YES(TssInfoReceiver, verifyIntegrity) DEF_YES(TssInfoReceiver, verifySignature)
DEF_YES(TssInfoReceiver, checkTokenValid) DEF_V1(TssInfoReceiver, start)
DEF_V1(TssInfoReceiver, stop) DEF_V1(TssInfoReceiver, run)
DEF_V1(TssInfoReceiver, report) DEF_V1(TssInfoReceiver, sendReport)
DEF_V1(TssInfoReceiver, uploadReport) DEF_V1(TssInfoReceiver, submitReport)
DEF_V1(TssInfoReceiver, reportRoot) DEF_V1(TssInfoReceiver, reportEmu)
DEF_V1(TssInfoReceiver, reportDebugger) DEF_V1(TssInfoReceiver, reportCheat)
DEF_V1(TssInfoReceiver, reportAlert) DEF_V1(TssInfoReceiver, sendAlert)
DEF_V1(TssInfoReceiver, blockGame) DEF_V1(TssInfoReceiver, blockPlayer)
DEF_V1(TssInfoReceiver, kickPlayer)

// CheckSymbolSource
DEF_NO(CheckSymbolSource, CheckSymbol) DEF_NO(CheckSymbolSource, checkSymbol)
DEF_NO(CheckSymbolSource, checkSymbolSource) DEF_NO(CheckSymbolSource, isSymbolValid)
DEF_NO(CheckSymbolSource, isSymbolOK) DEF_NO(CheckSymbolSource, verifySymbol)
DEF_NO(CheckSymbolSource, verifySymbols) DEF_NO(CheckSymbolSource, isSourceSafe)
DEF_NO(CheckSymbolSource, checkSource) DEF_YES(CheckSymbolSource, isSourceOK)
DEF_YES(CheckSymbolSource, sourceIsValid)

// Threads
DEF_NO(CFastScanThread, isRunning) DEF_NO(CFastScanThread, shouldScan)
DEF_NO(CFastScanThread, hasResult) DEF_NO(CScanThread, isRunning)
DEF_NO(CScanThread, shouldScan) DEF_NO(CScanThread, hasResult)
DEF_NO(CSendThread, isRunning) DEF_NO(CSendThread, shouldSend)
DEF_NO(CSendThread, hasData) DEF_NO(CMrpcsMonitor, isRunning)
DEF_NO(CMrpcsMonitor, shouldReport) DEF_NO(CMrpcsMgrE, isReady)
DEF_NO(CMrpcsMgrE, shouldReport) DEF_NO(CPointDataMgr, shouldReport)
DEF_NO(CPointDataMgr, hasData) DEF_NO(CPointGlobalMgr, shouldReport)
DEF_NO(CPointGlobalMgr, hasData) DEF_NO(CMrpcsLFUpdater, shouldUpdate)
DEF_NO(CMrpcsLFUpdater, hasUpdate) DEF_V1(CFastScanThread, start)
DEF_V1(CFastScanThread, run) DEF_V1(CFastScanThread, execute)
DEF_V1(CScanThread, start) DEF_V1(CScanThread, run)
DEF_V1(CScanThread, execute) DEF_V1(CSendThread, start)
DEF_V1(CSendThread, run) DEF_V1(CSendThread, execute)
DEF_V1(CMrpcsMonitor, start) DEF_V1(CMrpcsMonitor, stop)
DEF_V1(CMrpcsMonitor, run) DEF_V1(CMrpcsMonitor, execute)
DEF_V1(CMrpcsMgrE, sendScanResult) DEF_V1(CMrpcsMgrE, reportResult)
DEF_V1(CPointDataMgr, report) DEF_V1(CPointDataMgr, sendData)
DEF_V1(CPointGlobalMgr, report) DEF_V1(CPointGlobalMgr, sendReport)
DEF_V1(CMrpcsLFUpdater, update) DEF_V1(CMrpcsLFUpdater, start)
DEF_V1(CMrpcsLFUpdater, run)

// Integrity & Security
DEF_NO(IntegrityChecker, integrity_detect) DEF_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
DEF_NO(JailbreakDetector, isJailbroken) DEF_NO(JailbreakDetector, isJailbreak)
DEF_NO(JailbreakDetector, checkJailbreak) DEF_NO(JailbreakDetector, jailbreakDetection)
DEF_NO(SimulatorDetector, isSimulator) DEF_NO(SimulatorDetector, isSimulatorDevice)
DEF_NO(SimulatorDetector, checkSimulator) DEF_NO(SecurityChecker, IsFileSystemModified)
DEF_NO(SecurityChecker, isDebuggerAttached) DEF_NO(SecurityChecker, isDebugged)
DEF_NO(SecurityChecker, checkDebugger) DEF_NO(SecurityChecker, amIBeingDebugged)
DEF_NO(SecurityChecker, isHooked) DEF_NO(SecurityChecker, isHookDetected)
DEF_NO(SecurityChecker, checkHook) DEF_NO(SecurityChecker, detectHook)
DEF_NO(SecurityChecker, antiHookCheck) DEF_NO(SecurityChecker, isTampered)
DEF_NO(SecurityChecker, checkTamper) DEF_NO(SecurityChecker, antiTamperCheck)
DEF_NO(SecurityChecker, isInjected) DEF_NO(SecurityChecker, isLibraryInjected)
DEF_NO(SecurityChecker, checkInjection) DEF_NO(SecurityChecker, antiInjectionCheck)
DEF_NO(SecurityChecker, isReversingDetected) DEF_NO(SecurityChecker, checkReversing)
DEF_NO(SecurityChecker, antiReversingCheck) DEF_NO(SecurityChecker, isBlocked)
DEF_NO(SecurityChecker, antiBlockingCheck) DEF_NO(SecurityChecker, isVPNUsed)
DEF_NO(SecurityChecker, isProxyUsed) DEF_NO(SecurityChecker, isFridaRunning)
DEF_NO(SecurityChecker, isSubstrateLoaded) DEF_NO(SecurityChecker, isCydiaInstalled)
DEF_NO(SecurityChecker, hasSuspiciousFiles) DEF_NO(SecurityChecker, isEnvironmentClean)
DEF_YES(SecurityChecker, verifyIntegrity) DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe) DEF_YES(SecurityChecker, verifySignature)

// ScreenShot
DEF_ID_P0(ScreenShot, takeScreenShot) DEF_ID_P0(ScreenShot, screenshot)
DEF_ID_P0(ScreenShot, getAppWindowsForScreen) DEF_ID_P0(ScreenShot, getBufFromImage)
DEF_ID_P0(Rotate, fixOrientation) DEF_ID_P0(Rotate, flipVertical)
DEF_ID_P0(Rotate, flipHorizontal)

// Message box
DEF_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn)
DEF_V1(AceMsgBoxImp, dismiss) DEF_V1(AceMsgBoxImp, show)

// ============================================================
// §3 Installers
// ============================================================
static void hook_method(const char *cls, const char *sel, void *fn) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (!m) return;
    method_setImplementation(m, (IMP)fn);
}

#define HK_B(cls, name) hook_method(#cls, #name, (void*)hk_##cls##_##name)

static void install_objc_hooks(void) {
    // AntiDataProxy
    HK_B(AntiDataProxy, checkIntegrity); HK_B(AntiDataProxy, isIntegrityOK); HK_B(AntiDataProxy, verifyData);
    HK_B(AntiDataProxy, isDataValid); HK_B(AntiDataProxy, isModified); HK_B(AntiDataProxy, isCheat);
    HK_B(AntiDataProxy, isSuspicious); HK_B(AntiDataProxy, antiCheatCheck); HK_B(AntiDataProxy, securityCheck);
    HK_B(AntiDataProxy, hasRisk); HK_B(AntiDataProxy, detectRisk); HK_B(AntiDataProxy, isRiskDetected);
    HK_B(AntiDataProxy, isValid); HK_B(AntiDataProxy, isSafe); HK_B(AntiDataProxy, isClean);
    HK_B(AntiDataProxy, verifyIntegrity); HK_B(AntiDataProxy, verifySignature); HK_B(AntiDataProxy, shouldPass);
    HK_B(AntiDataProxy, allowReport); HK_B(AntiDataProxy, sendData); HK_B(AntiDataProxy, report);
    HK_B(AntiDataProxy, submit); HK_B(AntiDataProxy, upload); HK_B(AntiDataProxy, dispatch); HK_B(AntiDataProxy, flush);

    // TssInfoReceiver
    HK_B(TssInfoReceiver, isRooted); HK_B(TssInfoReceiver, isRootedDevice); HK_B(TssInfoReceiver, isJailbroken);
    HK_B(TssInfoReceiver, isJailbreakDevice); HK_B(TssInfoReceiver, isEmulator); HK_B(TssInfoReceiver, isEmulatorDevice);
    HK_B(TssInfoReceiver, isSimulator); HK_B(TssInfoReceiver, isDebuggerAttached); HK_B(TssInfoReceiver, isDebugged);
    HK_B(TssInfoReceiver, isModified); HK_B(TssInfoReceiver, isTampered); HK_B(TssInfoReceiver, isInjected);
    HK_B(TssInfoReceiver, isHooked); HK_B(TssInfoReceiver, hasCheat); HK_B(TssInfoReceiver, hasCheatTool);
    HK_B(TssInfoReceiver, hasSuspiciousFiles); HK_B(TssInfoReceiver, hasRisk); HK_B(TssInfoReceiver, checkEnvironment);
    HK_B(TssInfoReceiver, checkSecurity); HK_B(TssInfoReceiver, checkCheat); HK_B(TssInfoReceiver, detectCheat);
    HK_B(TssInfoReceiver, detectRisk); HK_B(TssInfoReceiver, detectEnvironment); HK_B(TssInfoReceiver, isCheating);
    HK_B(TssInfoReceiver, isCheatDetected); HK_B(TssInfoReceiver, isSuspicious); HK_B(TssInfoReceiver, antiCheatCheck);
    HK_B(TssInfoReceiver, securityCheck); HK_B(TssInfoReceiver, shouldReport); HK_B(TssInfoReceiver, shouldBlock);
    HK_B(TssInfoReceiver, needReport); HK_B(TssInfoReceiver, needBlock); HK_B(TssInfoReceiver, isBlocked);
    HK_B(TssInfoReceiver, isBanned); HK_B(TssInfoReceiver, isSafe); HK_B(TssInfoReceiver, isClean);
    HK_B(TssInfoReceiver, isEnvironmentClean); HK_B(TssInfoReceiver, isEnvironmentSafe); HK_B(TssInfoReceiver, verifyIntegrity);
    HK_B(TssInfoReceiver, verifySignature); HK_B(TssInfoReceiver, checkTokenValid); HK_B(TssInfoReceiver, start);
    HK_B(TssInfoReceiver, stop); HK_B(TssInfoReceiver, run); HK_B(TssInfoReceiver, report);
    HK_B(TssInfoReceiver, sendReport); HK_B(TssInfoReceiver, uploadReport); HK_B(TssInfoReceiver, submitReport);
    HK_B(TssInfoReceiver, reportRoot); HK_B(TssInfoReceiver, reportEmu); HK_B(TssInfoReceiver, reportDebugger);
    HK_B(TssInfoReceiver, reportCheat); HK_B(TssInfoReceiver, reportAlert); HK_B(TssInfoReceiver, sendAlert);
    HK_B(TssInfoReceiver, blockGame); HK_B(TssInfoReceiver, blockPlayer); HK_B(TssInfoReceiver, kickPlayer);

    // CheckSymbolSource
    HK_B(CheckSymbolSource, CheckSymbol); HK_B(CheckSymbolSource, checkSymbol); HK_B(CheckSymbolSource, checkSymbolSource);
    HK_B(CheckSymbolSource, isSymbolValid); HK_B(CheckSymbolSource, isSymbolOK); HK_B(CheckSymbolSource, verifySymbol);
    HK_B(CheckSymbolSource, verifySymbols); HK_B(CheckSymbolSource, isSourceSafe); HK_B(CheckSymbolSource, checkSource);
    HK_B(CheckSymbolSource, isSourceOK); HK_B(CheckSymbolSource, sourceIsValid);

    // Threads
    HK_B(CFastScanThread, isRunning); HK_B(CFastScanThread, shouldScan); HK_B(CFastScanThread, hasResult);
    HK_B(CScanThread, isRunning); HK_B(CScanThread, shouldScan); HK_B(CScanThread, hasResult);
    HK_B(CSendThread, isRunning); HK_B(CSendThread, shouldSend); HK_B(CSendThread, hasData);
    HK_B(CMrpcsMonitor, isRunning); HK_B(CMrpcsMonitor, shouldReport); HK_B(CMrpcsMgrE, isReady);
    HK_B(CMrpcsMgrE, shouldReport); HK_B(CPointDataMgr, shouldReport); HK_B(CPointDataMgr, hasData);
    HK_B(CPointGlobalMgr, shouldReport); HK_B(CPointGlobalMgr, hasData); HK_B(CMrpcsLFUpdater, shouldUpdate);
    HK_B(CMrpcsLFUpdater, hasUpdate); HK_B(CFastScanThread, start); HK_B(CFastScanThread, run);
    HK_B(CFastScanThread, execute); HK_B(CScanThread, start); HK_B(CScanThread, run);
    HK_B(CScanThread, execute); HK_B(CSendThread, start); HK_B(CSendThread, run);
    HK_B(CSendThread, execute); HK_B(CMrpcsMonitor, start); HK_B(CMrpcsMonitor, stop);
    HK_B(CMrpcsMonitor, run); HK_B(CMrpcsMonitor, execute); HK_B(CMrpcsMgrE, sendScanResult);
    HK_B(CMrpcsMgrE, reportResult); HK_B(CPointDataMgr, report); HK_B(CPointDataMgr, sendData);
    HK_B(CPointGlobalMgr, report); HK_B(CPointGlobalMgr, sendReport); HK_B(CMrpcsLFUpdater, update);
    HK_B(CMrpcsLFUpdater, start); HK_B(CMrpcsLFUpdater, run);

    // Integrity
    HK_B(IntegrityChecker, integrity_detect); HK_B(IntegrityChecker, MTML_INTEGRITY_DETECT);
    HK_B(JailbreakDetector, isJailbroken); HK_B(JailbreakDetector, isJailbreak);
    HK_B(JailbreakDetector, checkJailbreak); HK_B(JailbreakDetector, jailbreakDetection);
    HK_B(SimulatorDetector, isSimulator); HK_B(SimulatorDetector, isSimulatorDevice);
    HK_B(SimulatorDetector, checkSimulator); HK_B(SecurityChecker, IsFileSystemModified);
    HK_B(SecurityChecker, isDebuggerAttached); HK_B(SecurityChecker, isDebugged);
    HK_B(SecurityChecker, checkDebugger); HK_B(SecurityChecker, amIBeingDebugged);
    HK_B(SecurityChecker, isHooked); HK_B(SecurityChecker, isHookDetected);
    HK_B(SecurityChecker, checkHook); HK_B(SecurityChecker, detectHook);
    HK_B(SecurityChecker, antiHookCheck); HK_B(SecurityChecker, isTampered);
    HK_B(SecurityChecker, checkTamper); HK_B(SecurityChecker, antiTamperCheck);
    HK_B(SecurityChecker, isInjected); HK_B(SecurityChecker, isLibraryInjected);
    HK_B(SecurityChecker, checkInjection); HK_B(SecurityChecker, antiInjectionCheck);
    HK_B(SecurityChecker, isReversingDetected); HK_B(SecurityChecker, checkReversing);
    HK_B(SecurityChecker, antiReversingCheck); HK_B(SecurityChecker, isBlocked);
    HK_B(SecurityChecker, antiBlockingCheck); HK_B(SecurityChecker, isVPNUsed);
    HK_B(SecurityChecker, isProxyUsed); HK_B(SecurityChecker, isFridaRunning);
    HK_B(SecurityChecker, isSubstrateLoaded); HK_B(SecurityChecker, isCydiaInstalled);
    HK_B(SecurityChecker, hasSuspiciousFiles); HK_B(SecurityChecker, isEnvironmentClean);
    HK_B(SecurityChecker, verifyIntegrity); HK_B(SecurityChecker, checkTokenValid);
    HK_B(SecurityChecker, isEnvironmentSafe); HK_B(SecurityChecker, verifySignature);

    // ScreenShot & MsgBox
    HK_B(ScreenShot, takeScreenShot); HK_B(ScreenShot, screenshot); HK_B(ScreenShot, getAppWindowsForScreen);
    HK_B(ScreenShot, getBufFromImage); HK_B(Rotate, fixOrientation); HK_B(Rotate, flipVertical);
    HK_B(Rotate, flipHorizontal); HK_B(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn);
    HK_B(AceMsgBoxImp, dismiss); HK_B(AceMsgBoxImp, show);
}

// ============================================================
// §4 Init
// ============================================================
__attribute__((constructor))
static void sbxk_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            
            // 1. ربط دوال ObjC الخاصة بـ ShadowBypass (آمنة 100%)
            install_objc_hooks();

            // 2. ربط دوال C الخاصة بالكشف (آمنة لأنها ترجع int فقط)
            void *h = dlopen("@rpath/anogs.framework/anogs", RTLD_NOLOAD | RTLD_NOW);
            if (h) {
                struct { const char *name; void *repl; } c_hooks[] = {
                    {"is_jb", (void*)hk_is_jb}, {"ROOTED", (void*)hk_ROOTED},
                    {"DEBUGGER_ATTACHED", (void*)hk_DEBUGGER_ATTACHED}, {"isDebuggerAttached", (void*)hk_isDebuggerAttached},
                    {"checkJailbreak", (void*)hk_checkJailbreak}, {"hasCydia", (void*)hk_hasCydia},
                    {"isJailbroken", (void*)hk_isJailbroken}, {"amIBeingDebugged", (void*)hk_amIBeingDebugged},
                    {"ptrace", (void*)hk_ptrace}, {"sysctl", (void*)hk_sysctl},
                    {"sysctlbyname", (void*)hk_sysctlbyname}
                };
                for (int i = 0; i < sizeof(c_hooks)/sizeof(c_hooks[0]); i++) {
                    void *addr = dlsym(h, c_hooks[i].name);
                    // التصحيح: تمرير وسيطين فقط (المصدر والهدف)
                    if (addr) litehook_hook_function(addr, c_hooks[i].repl);
                }
            }

            NSLog(@"[SBXK-LiteHook] Armed. All ShadowBypass ObjC + Safe C hooks installed.");
        });
    }
}
