//
//  P037AVEPaintProbe.h
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/30/26.
//


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P037AVEPaintProbe : NSObject

/// P037: AVE Sink A 32-bit mul wrap -> OOB DMA paint
/// Wrap dims small enough for CVPixelBufferCreate.
+ (NSString *)tap NS_SWIFT_NAME(tap());

@end

NS_ASSUME_NONNULL_END
