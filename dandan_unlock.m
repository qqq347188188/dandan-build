//
//  dandan_unlock.m  (v2)
//  蛋蛋不语 VIP 解锁 dylib —— 复刻 dandanvip_unlock.js (v1.1.0)
//
//  v2 相比 v1 的改进：
//   1. 同时 hook 两种 NSURLSession 用法：
//        - dataTaskWith...:completionHandler:  （completion 模式，如原生/部分库）
//        - sessionWithConfiguration:delegate:  （delegate 模式，如 Alamofire/AFNetworking）
//   2. 匹配放宽：host == 38.76.202.248，或 URL 含 "profiles"
//   3. 除顶层外，也尝试 patch 常见嵌套容器 data/result/user/profile/info
//   4. 把每个被拦截的 URL 写入日志文件，便于定位（见文末路径）
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdarg.h>

// ================= 日志 =================
static NSString *DDLogPath(void) {
    static NSString *p;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        p = [dir stringByAppendingPathComponent:@"dandan_unlock.log"];
    });
    return p;
}

static void DLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[dandan_unlock] %@", msg);
    @try {
        NSString *line = [NSString stringWithFormat:@"%@  %@\n", [NSDate date], msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:DDLogPath()];
        if (!fh) {
            [line writeToFile:DDLogPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    } @catch (__unused NSException *e) {}
}

// ================= 注入逻辑 =================
static NSDictionary *VIP_PATCH(void) {
    return @{
        @"vip_status":    @YES,
        @"vip_level":     @3,
        @"vip_expire_at": @"2099-09-19T22:21:06.147807+00:00",
        @"username":      @"TG@Curtinp118",
        @"avatar_url":    @"https://i.ibb.co/NgghpGgn/11zon-A9-CBAC35-2-CA3-4-E7-F-923-D-7304-EEB40635.webp"
    };
}

static BOOL isTargetURL(NSURL *url) {
    if (!url) return NO;
    if ([url.host isEqualToString:@"38.76.202.248"]) return YES;
    if ([[url absoluteString] rangeOfString:@"profiles" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static void patchDict(NSMutableDictionary *d) {
    [d addEntriesFromDictionary:VIP_PATCH()];
}

static NSData *maybePatch(NSData *data, NSURL *url) {
    if (!isTargetURL(url)) return data;
    if (!data || data.length == 0) return data;

    NSError *e = nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&e];
    if (e || !json) {
        DLog(@"命中但非 JSON: %@", url.absoluteString);
        return data;
    }

    if ([json isKindOfClass:[NSArray class]]) {
        for (id it in (NSArray *)json)
            if ([it isKindOfClass:[NSMutableDictionary class]]) patchDict(it);
    } else if ([json isKindOfClass:[NSMutableDictionary class]]) {
        patchDict(json);
        for (NSString *k in @[@"data", @"result", @"user", @"profile", @"info"]) {
            id v = ((NSMutableDictionary *)json)[k];
            if ([v isKindOfClass:[NSMutableDictionary class]]) patchDict(v);
        }
    }

    NSData *out = [NSJSONSerialization dataWithJSONObject:json options:0 error:&e];
    DLog(@"已注入 VIP: %@", url.absoluteString);
    return out ?: data;
}

// ================= completion 模式 hook =================
typedef void (^SessionCompletion)(NSData *data, NSURLResponse *response, NSError *error);

static id (*orig_dataTaskWithRequest)(id, SEL, id, id);
static id (*orig_dataTaskWithURL)(id, SEL, id, id);

static id hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithRequest(self, _cmd, req, completion);
    NSURL *url = req.URL;
    return orig_dataTaskWithRequest(self, _cmd, req, ^(NSData *d, NSURLResponse *r, NSError *err){
        NSURL *ru = r.URL ?: url;
        DLog(@"completion 响应: %@", ru.absoluteString);
        completion(maybePatch(d, ru), r, err);
    });
}

static id hook_dataTaskWithURL(id self, SEL _cmd, NSURL *url, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithURL(self, _cmd, url, completion);
    return orig_dataTaskWithURL(self, _cmd, url, ^(NSData *d, NSURLResponse *r, NSError *err){
        NSURL *ru = r.URL ?: url;
        DLog(@"completion 响应: %@", ru.absoluteString);
        completion(maybePatch(d, ru), r, err);
    });
}

// ================= delegate 模式 hook =================
@interface DDProxy : NSObject
@property (nonatomic, weak)   id real;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSMutableData *> *buf;
@end

@implementation DDProxy
- (instancetype)initWithReal:(id)real {
    if ((self = [super init])) { _real = real; _buf = [NSMutableDictionary dictionary]; }
    return self;
}
- (BOOL)respondsToSelector:(SEL)sel {
    if (sel == @selector(URLSession:dataTask:didReceiveData:) ||
        sel == @selector(URLSession:task:didCompleteWithError:)) return YES;
    return [self.real respondsToSelector:sel];
}
- (id)forwardingTargetForSelector:(SEL)sel { return self.real; }

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data {
    NSMutableData *b = self.buf[@(task.taskIdentifier)];
    if (!b) { b = [NSMutableData data]; self.buf[@(task.taskIdentifier)] = b; }
    [b appendData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    NSMutableData *b = self.buf[@(task.taskIdentifier)];
    [self.buf removeObjectForKey:@(task.taskIdentifier)];
    NSURL *u = task.originalRequest.URL ?: task.currentRequest.URL;
    DLog(@"delegate 完成: %@  len=%lu", u.absoluteString, (unsigned long)b.length);

    if (b.length && [self.real respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)]) {
        NSData *patched = maybePatch(b, u);
        [(id<NSURLSessionDataDelegate>)self.real URLSession:session dataTask:(NSURLSessionDataTask *)task didReceiveData:patched];
    }
    if ([self.real respondsToSelector:@selector(URLSession:task:didCompleteWithError:)]) {
        [(id<NSURLSessionTaskDelegate>)self.real URLSession:session task:task didCompleteWithError:error];
    }
}
@end

static id (*orig_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);

static id hook_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *queue) {
    if (delegate && ![delegate isKindOfClass:[DDProxy class]]) {
        DDProxy *proxy = [[DDProxy alloc] initWithReal:delegate];
        DLog(@"包装 delegate: %@", NSStringFromClass([delegate class]));
        return orig_sessionWithConfig(self, _cmd, cfg, proxy, queue);
    }
    return orig_sessionWithConfig(self, _cmd, cfg, delegate, queue);
}

// ================= 安装 =================
__attribute__((constructor)) static void dandan_unlock_init(void) {
    Class cls = objc_getClass("NSURLSession");
    if (!cls) return;

    Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (m1) { orig_dataTaskWithRequest = (id(*)(id,SEL,id,id))method_getImplementation(m1);
              method_setImplementation(m1, (IMP)hook_dataTaskWithRequest); }

    Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (m2) { orig_dataTaskWithURL = (id(*)(id,SEL,id,id))method_getImplementation(m2);
              method_setImplementation(m2, (IMP)hook_dataTaskWithURL); }

    Method m3 = class_getClassMethod(cls, @selector(sessionWithConfiguration:delegate:delegateQueue:));
    if (m3) { orig_sessionWithConfig = (id(*)(id,SEL,id,id,id))method_getImplementation(m3);
              method_setImplementation(m3, (IMP)hook_sessionWithConfig); }

    DLog(@"=== dandan_unlock v2 已加载 ===");
}
