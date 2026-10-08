#import "LabLocalTime.h"

NSString *LabLocalMilitaryNow(void) {
    static NSDateFormatter *fmt;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [NSDateFormatter new];
        fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        fmt.timeZone = [NSTimeZone localTimeZone];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss z";
    });
    return [fmt stringFromDate:[NSDate date]];
}
