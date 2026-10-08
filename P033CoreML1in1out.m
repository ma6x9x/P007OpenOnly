#import "P033CoreML1in1out.h"
#import "LabLocalTime.h"

#import <CoreML/CoreML.h>
#import <fcntl.h>
#import <math.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P033_BUILD @"p033-coreml-1in1out"

static NSMutableString *p033_buf;
static int p033_fd = -1;

static void p033_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p033_buf)
            [p033_buf appendString:out];
        if (p033_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p033_fd, s, strlen(s));
        }
    }
}

static NSURL *p033_modelURL(void)
{
    NSBundle *b = [NSBundle mainBundle];
    NSURL *u = [b URLForResource:@"simple_1in1out" withExtension:@"mlmodelc"];
    if (u)
        return u;
    u = [b URLForResource:@"simple_1in1out" withExtension:@"mlpackage"];
    if (u)
        return u;
    return [b URLForResource:@"simple_1in1out" withExtension:@"mlmodel"];
}

static void p033_finish_session(BOOL sessionHeader)
{
    if (sessionHeader && p033_fd >= 0) {
        fcntl(p033_fd, F_FULLFSYNC);
        close(p033_fd);
        p033_fd = -1;
    }
}

static NSString *p033_runPredict(BOOL sessionHeader)
{
    if (sessionHeader) {
        p033_buf = [NSMutableString string];
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p033_coreml_1in1out_log.txt"];
        if (p033_fd >= 0)
            close(p033_fd);
        p033_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        p033_log(@"=== p033 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P033_BUILD);
        p033_log(@"1-in/1-out CoreML ABI only. n=2. No 254. No ProgramSendRequest.");
    }

    // ARC: no goto across __strong inits — early-return + finish helper.
    NSURL *url = p033_modelURL();
    if (!url) {
        p033_log(@"FAIL no simple_1in1out.mlmodelc in bundle — rebuild after adding P007OpenOnly/simple_1in1out.mlmodelc");
        p033_log(@"Do NOT add .mlmodel to the sync folder (coremlc breaks). Ship precompiled .mlmodelc only.");
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }
    p033_log(@"model url=%@", url.lastPathComponent);

    MLModelConfiguration *cfg = [[MLModelConfiguration alloc] init];
    cfg.computeUnits = MLComputeUnitsCPUAndNeuralEngine;
    NSError *err = nil;
    MLModel *model = [MLModel modelWithContentsOfURL:url configuration:cfg error:&err];
    if (!model) {
        p033_log(@"FAIL MLModel load: %@", err);
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }

    MLModelDescription *d = model.modelDescription;
    p033_log(@"inputs=%@", d.inputDescriptionsByName.allKeys);
    p033_log(@"outputs=%@", d.outputDescriptionsByName.allKeys);
    MLFeatureDescription *inDesc = d.inputDescriptionsByName[@"input"];
    MLFeatureDescription *outDesc = d.outputDescriptionsByName[@"output"];
    p033_log(@"input type=%ld constraint=%@", (long)inDesc.type, inDesc.multiArrayConstraint);
    p033_log(@"output type=%ld constraint=%@", (long)outDesc.type, outDesc.multiArrayConstraint);

    if (@available(iOS 17.4, *)) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block MLComputePlan *plan = nil;
        __block NSError *planErr = nil;
        [MLComputePlan loadContentsOfURL:url
                           configuration:cfg
                       completionHandler:^(MLComputePlan *p, NSError *e) {
                           plan = p;
                           planErr = e;
                           dispatch_semaphore_signal(sem);
                       }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC));
        if (planErr)
            p033_log(@"computePlan err=%@", planErr);
        else if (plan)
            p033_log(@"computePlan loaded (inspect Xcode console for NE vs CPU)");
        else
            p033_log(@"computePlan nil (timeout or unsupported)");
    }

    NSError *arrErr = nil;
    MLMultiArray *arr = [[MLMultiArray alloc] initWithShape:@[ @1, @1 ]
                                                   dataType:MLMultiArrayDataTypeFloat32
                                                      error:&arrErr];
    if (!arr) {
        p033_log(@"FAIL MLMultiArray: %@", arrErr);
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }
    arr[0] = @(3.0);

    NSError *fpErr = nil;
    MLDictionaryFeatureProvider *fp =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:@{ @"input": [MLFeatureValue featureValueWithMultiArray:arr] }
                                                          error:&fpErr];
    if (!fp) {
        p033_log(@"FAIL feature provider: %@", fpErr);
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }

    NSError *predErr = nil;
    id<MLFeatureProvider> pred = [model predictionFromFeatures:fp error:&predErr];
    if (!pred) {
        p033_log(@"FAIL prediction: %@", predErr);
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }

    MLFeatureValue *outv = [pred featureValueForName:@"output"];
    MLMultiArray *outa = outv.multiArrayValue;
    if (!outa) {
        p033_log(@"FAIL no output multiArray; keys=%@", pred.featureNames);
        p033_finish_session(sessionHeader);
        return p033_buf ?: @"";
    }
    double got = outa[0].doubleValue;
    p033_log(@"predict input=3.0 output=%.6f (expect ~6.0)", got);
    if (fabs(got - 6.0) < 0.05)
        p033_log(@"ABI OK numeric (CPU or NE). n=2. Does not prove 43748.");
    else
        p033_log(@"WARN numeric mismatch — model ran but not x*2");
    p033_log(@"If this succeeded, CoreML opened ANE-or-CPU path and filled sel3 slots itself.");
    p033_log(@"UNVERIFIED: whether this prediction used H11ANEIn type=1 vs CPU.");

    p033_finish_session(sessionHeader);
    return p033_buf ?: @"";
}

@implementation P033CoreML1in1out

+ (NSString *)tap {
    return p033_runPredict(YES);
}

+ (NSString *)predictOnce {
    NSMutableString *saved = p033_buf;
    int savedfd = p033_fd;
    p033_buf = [NSMutableString string];
    p033_fd = -1;
    p033_runPredict(NO);
    NSString *s = [p033_buf copy];
    p033_buf = saved;
    p033_fd = savedfd;
    return s ?: @"";
}

@end
