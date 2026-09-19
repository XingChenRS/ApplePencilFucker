//  PencilGen1Compat — let Apple Pencil (1st generation) pair with iPads Apple
//  did not list, by clearing accessoryd's model gate.
//
//  accessoryd decides whether the Lightning Pencil may pair over its wire:
//
//      BOOL isApplePencilGen1Supported(void)                      // 0x1000700CC
//      {
//          // obfuscated name == base64(md5("MGCopyAnswer"+"DeviceSupportsApplePencil"))
//          if ( !MGGetBoolAnswer(CFSTR("yhHcB0iH0d1XzPO/CFd3ow")) )
//              return NO;
//          CFStringRef model = MGCopyAnswer(CFSTR("ProductType"));
//          return MGGetBoolAnswer(CFSTR("DeviceSupports9Pin"))     // 9-pin Lightning
//              || CFEqual(model, CFSTR("iPad13,18"))               // iPad 10 Wi-Fi
//              || CFEqual(model, CFSTR("iPad13,19"));              // iPad 10 Cellular
//      }
//
//  When the attached accessory is an Apple Pencil (model A1603) and this returns
//  NO, accessoryd shows "Accessory Not Supported" and skips the pairing start
//  (ACCBLEPairingServer accessoryBLEPairingAttached:, 0x10014E36C) — the
//  handshake that hands the Bluetooth link key to the iPad, which is why a
//  manually paired pencil loses its link key on every disconnect.
//
//  Both MobileGestalt keys are read exactly once in the whole daemon — and
//  neither exists in the on-disk MobileGestalt cache (both are hardware/runtime
//  derived), so answering them in-process is the only way to change this
//  decision. That is also why the hook is scoped to accessoryd instead of
//  patching MobileGestalt itself, which would affect every process.

#import <Foundation/Foundation.h>
#import <os/log.h>

// libMobileGestalt (private framework, no public header). Declared here so the
// Logos hook below has a symbol to reference; the link resolves it at load time
// because tweaks link with -undefined dynamic_lookup.
extern Boolean MGGetBoolAnswer(CFStringRef key);

static os_log_t gLog;
static CFStringRef gKeyPencilGate;   // obfuscated key: DeviceSupportsApplePencil
static CFStringRef gKeyNinePin;      // DeviceSupports9Pin
static int gCalls;

// Trailing diagnostics for the host daemon: it is started on demand and there is
// no log(1) on iOS 16, so the interesting part of a failed attempt is written to
// a file that can be read over SSH.
static void pgnote(const char *fmt, ...)
{
    FILE *f = fopen("/tmp/PencilGen1Compat.log", "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// Built lazily rather than in a constructor: with several constructors in one
// image their relative order is up to the linker, and the hook must never run
// before its comparison keys exist.
static void pgInitKeys(void)
{
    if (!gKeyPencilGate)
        gKeyPencilGate = CFStringCreateWithCString(kCFAllocatorDefault,
                                                   "yhHcB0iH0d1XzPO/CFd3ow",
                                                   kCFStringEncodingUTF8);
    if (!gKeyNinePin)
        gKeyNinePin = CFStringCreateWithCString(kCFAllocatorDefault,
                                                "DeviceSupports9Pin",
                                                kCFStringEncodingUTF8);
}

%hookf(Boolean, MGGetBoolAnswer, CFStringRef key)
{
    pgInitKeys();

    if (gCalls < 32) {
        gCalls++;
        pgnote("call %d: key=%p gate=%p nine=%p", gCalls,
               (void *)key, (void *)gKeyPencilGate, (void *)gKeyNinePin);
    }

    if (key) {
        if (gKeyPencilGate && CFEqual(key, gKeyPencilGate)) {
            pgnote("-> forcing DeviceSupportsApplePencil = true");
            os_log(gLog, "forcing DeviceSupportsApplePencil -> true");
            return true;
        }
        if (gKeyNinePin && CFEqual(key, gKeyNinePin)) {
            pgnote("-> forcing DeviceSupports9Pin = true");
            os_log(gLog, "forcing DeviceSupports9Pin -> true");
            return true;
        }
    }
    return %orig;
}

%ctor
{
    gLog = os_log_create("com.xingchenrs.pencilgen1", "tweak");

    // accessoryd is started on demand (launchd matches USB / OOB-pairing
    // events), so a beacon makes it obvious whether ElleKit injected the tweak
    // into the process that is actually handling the pencil.
    FILE *beacon = fopen("/tmp/PencilGen1Compat.loaded", "w");
    if (beacon) {
        fprintf(beacon, "pid=%d\n", getpid());
        fclose(beacon);
    }
    pgnote("loaded into accessoryd (pid %d)", getpid());
    os_log(gLog, "loaded into accessoryd (pid %d)", getpid());
}
