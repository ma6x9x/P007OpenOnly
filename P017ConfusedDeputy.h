//
//  P017ConfusedDeputy.h
//  P007OpenOnly
//

#import <Foundation/Foundation.h>
@interface P017ConfusedDeputy : NSObject
/// Runs calib+race. Returns in-memory status (includes BUILD id) so UI
/// does not depend on the stale Documents recovery view.
+ (NSString *)tap;
@end
