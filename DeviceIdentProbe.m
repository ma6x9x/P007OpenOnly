#import "DeviceIdentProbe.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import "P007Board.h"

#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <fcntl.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <UIKit/UIKit.h>

static NSString *sysctl_s(const char *name) {
    size_t n = 0;
    if (sysctlbyname(name, NULL, &n, NULL, 0) != 0 || n == 0) return @"?";
    char *b = calloc(1, n + 1);
    if (!b) return @"?";
    sysctlbyname(name, b, &n, NULL, 0);
    NSString *s = [NSString stringWithUTF8String:b];
    free(b);
    return s ?: @"?";
}

@implementation DeviceIdentProbe

+ (NSString *)runIdentity {
    NSMutableString *out = [NSMutableString string];
    struct utsname u;
    uname(&u);
    NSString *machine = sysctl_s("hw.machine");
    NSString *osver = sysctl_s("kern.osversion");
    NSString *osrel = sysctl_s("kern.osrelease");
    UIDevice *d = UIDevice.currentDevice;
    [out appendFormat:@"time %@\n", LabLocalMilitaryNow()];
    [out appendString:@"=== DEVICE IDENTITY (dual-test gate) ===\n"];
    [out appendFormat:@"hw.machine     %@\n", machine];
    [out appendFormat:@"uname.machine  %s\n", u.machine];
    [out appendFormat:@"UIDevice       %@ %@\n", d.model, d.systemVersion];
    [out appendFormat:@"kern.osversion %@\n", osver];
    [out appendFormat:@"kern.osrelease %@\n", osrel];
    [out appendFormat:@"sysname        %s\n", u.sysname];
    [out appendFormat:@"release        %s\n", u.release];

    [out appendString:[LabDeviceProfile identBlock]];
    [[P007Board shared] refreshIdentity];
    [out appendFormat:@"kread signal   %@\n", [P007Board shared].kreadSignal];
    [out appendString:[LabDeviceProfile proveMatrix]];
    [out appendString:[LabDeviceProfile slideDestMap]];
    [out appendString:[LabDeviceProfile writeClassMap]];
    [out appendString:[LabDeviceProfile patchOracleMap]];
    [out appendString:[LabDeviceProfile oracleTable]];
    [out appendFormat:@"QueueCreate expect: %@\n", [LabDeviceProfile expectQueueCreate]];
    [out appendFormat:@"P010 last-ref:      %@\n", [LabDeviceProfile expectP010LastRef]];
    [out appendFormat:@"P009 PathB expect:  %@\n", [LabDeviceProfile expectP009PathB]];
    [out appendFormat:@"64788 expect:       %@\n", [LabDeviceProfile expect64788]];
    [out appendFormat:@"AVE OPEN expect:    %@\n", [LabDeviceProfile expectAVEOpen]];
    [out appendFormat:@"NECP expect:        %@\n", [LabDeviceProfile expectNecpReach]];

    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"device_ident_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        const char *s = [out UTF8String];
        write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return out;
}

@end
