//
//  P022.h
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/29/26.
//


//
//  P022_GameCenter_Sandbox_Escape.h
//  P007OpenOnly
//
//  CVE-2026-64740: Game Center path traversal → sandbox escape.
//  F77 has NO validation of ".." in _GKImageCachePathForSubdirectoryAndFilename.
//  G71 added rangeOfString checks — confirming F77 is vulnerable.
//  NOT KRW. Sandbox escape class only.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P022GC_GameCenter_Sandbox_Escape : NSObject

+ (instancetype)sharedInstance;
+ (void)tap;

@end

NS_ASSUME_NONNULL_END
