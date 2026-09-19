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
//  (iAP2BLEPairing _startFeatureFromDevice, 0x10014E36C), which is the wired
//  out-of-band handshake that hands the Bluetooth link key to the iPad — the
//  reason a manually paired pencil loses its link key on every disconnect.
//
//  Both MobileGestalt keys are read exactly once in the whole daemon — and neither
//  key exists in the on-disk MobileGestalt cache (both are hardware/runtime derived),
//  so answering them in-process is the only way to change this decision. That is also
//  why the hook is scoped to accessoryd instead of patching MobileGestalt itself, which
//  would affect every process on the device.

#import <Foundation/Foundation.h>
#import <os/log.h>

static os_log_t gLog;

static CFStringRef gKeyPencilGate;   // obfuscated MG key guarding the check
static CFStringRef gKeyNinePin;      // "DeviceSupports9Pin"

%hookf(Boolean, MGGetBoolAnswer, CFStringRef key)
{
    if (key) {
        if (gKeyPencilGate && CFEqual(key, gKeyPencilGate)) {
            os_log(gLog, "forcing %{public}@ -> true", key);
            return true;
        }
        if (gKeyNinePin && CFEqual(key, gKeyNinePin)) {
            os_log(gLog, "forcing DeviceSupports9Pin -> true");
            return true;
        }
    }
    return %orig;
}

%ctor
{
    gLog = os_log_create("com.xingchenrs.pencilgen1", "tweak");
    gKeyPencilGate = CFStringCreateWithCString(kCFAllocatorDefault,
                                               "yhHcB0iH0d1XzPO/CFd3ow",
                                               kCFStringEncodingUTF8);
    gKeyNinePin = CFSTR("DeviceSupports9Pin");
    os_log(gLog, "loaded into accessoryd (pid %d)", getpid());
}
