//
//  dandan_unlock.m  (v4)
//  蛋蛋不语 VIP 解锁 dylib
//
//  目标接口：http://38.76.202.248:8000//rest/v1/profiles?select=*&id=eq.<uuid>  (Supabase/PostgREST)
//  返回 JSON 里含 vip_status / vip_level / vip_expire_at。
//
//  v4：
//   - 往 WKWebView 注入 JS，重写 fetch / XMLHttpRequest，在 JS 层把返回 JSON 改成 VIP 值；
//   - 注入点用 WKWebViewConfiguration.userContentController 的 getter（覆盖所有创建方式）；
//   - 加日志探测：App 是否真的创建了 WKWebView / 是否为 Flutter；
//   - 保留 NSURLSession 原生 hook 兜底。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
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

// ================= 注入到网页的 JS（整段不含双引号） =================
static NSString *DandanJS(void) {
    static NSString *js;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        js = @"(function(){if(window.__dandan){return;}window.__dandan=1;try{var P={vip_status:true,vip_level:3,vip_expire_at:'2099-09-19T22:21:06.147807+00:00'};function T(u){return typeof u==='string'&&(u.indexOf('38.76.202.248')>-1||u.indexOf('/profiles')>-1);}function patch(t){try{var j=JSON.parse(t);var p=function(o){if(o&&typeof o==='object'){Object.assign(o,P);}};if(Array.isArray(j)){j.forEach(p);}else{p(j);}return JSON.stringify(j);}catch(e){return t;}}var of=window.fetch;if(of){window.fetch=function(i,n){var u=(typeof i==='string')?i:((i&&i.url)||'');return of.apply(this,arguments).then(function(r){if(!T(u)){return r;}return r.clone().text().then(function(t){var b=patch(t);var h=new Headers(r.headers);h.delete('content-length');return new Response(b,{status:r.status,statusText:r.statusText,headers:h});}).catch(function(){return r;});});};}var oo=XMLHttpRequest.prototype.open;var os=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.open=function(m,u){this.__du=u;return oo.apply(this,arguments);};XMLHttpRequest.prototype.send=function(){var x=this;x.addEventListener('readystatechange',function(){if(x.readyState===4&&T(x.__du)){try{var b=patch(x.responseText);Object.defineProperty(x,'responseText',{configurable:true,get:function(){return b;}});}catch(e){}}});return os.apply(this,arguments);};}catch(e){}})();";
    });
    return js;
}

// ================= WKWebView 注入 =================
static const void *kDandanUCCKey = &kDandanUCCKey;

static void dandanAttach(WKUserContentController *ucc) {
    if (!ucc) return;
    if (objc_getAssociatedObject(ucc, kDandanUCCKey)) return;
    objc_setAssociatedObject(ucc, kDandanUCCKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    WKUserScript *s = [[WKUserScript alloc] initWithSource:DandanJS()
                                             injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                          forMainFrameOnly:NO];
    [ucc addUserScript:s];
    DLog(@"[WKWebView] 已注入 userScript");
}

static void dandanAddScript(WKWebViewConfiguration *config) {
    if (!config) return;
    WKUserContentController *ucc = config.userContentController;
    if (!ucc) { ucc = [[WKUserContentController alloc] init]; config.userContentController = ucc; }
    dandanAttach(ucc);
}

// 主注入点：- [WKWebViewConfiguration userContentController] （任何 WKWebView 加载前都会读它）
static id (*orig_uccGetter)(id, SEL);
static id hook_uccGetter(id self, SEL _cmd) {
    id ucc = orig_uccGetter(self, _cmd);
    @try { dandanAttach(ucc); } @catch (__unused NSException *e) {}
    return ucc;
}

static id (*orig_wvInit)(id, SEL, CGRect, id);
static id hook_wvInit(id self, SEL _cmd, CGRect frame, id config) {
    DLog(@"[WKWebView] initWithFrame:configuration:");
    @try { dandanAddScript(config); } @catch (__unused NSException *e) {}
    return orig_wvInit(self, _cmd, frame, config);
}

static id (*orig_wvLoadRequest)(id, SEL, NSURLRequest *);
static id hook_wvLoadRequest(id self, SEL _cmd, NSURLRequest *req) {
    DLog(@"[WKWebView] loadRequest: %@", req.URL.absoluteString);
    @try { dandanAddScript([(WKWebView *)self configuration]); } @catch (__unused NSException *e) {}
    return orig_wvLoadRequest(self, _cmd, req);
}

// ================= 原生网络 hook（兜底） =================
static NSDictionary *VIP_PATCH(void) {
    return @{
        @"vip_status":    @YES,
        @"vip_level":     @3,
        @"vip_expire_at": @"2099-09-19T22:21:06.147807+00:00"
    };
}

static BOOL isTargetURL(NSURL *url) {
    if (!url) return NO;
    if ([url.host isEqualToString:@"38.76.202.248"]) return YES;
    if ([[url absoluteString] rangeOfString:@"profiles" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static NSData *maybePatch(NSData *data, NSURL *url) {
    if (!isTargetURL(url) || !data || data.length == 0) return data;
    NSError *e = nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&e];
    if (e || !json) return data;
    NSDictionary *patch = VIP_PATCH();
    if ([json isKindOfClass:[NSArray class]]) {
        for (id it in (NSArray *)json)
            if ([it isKindOfClass:[NSMutableDictionary class]]) [it addEntriesFromDictionary:patch];
    } else if ([json isKindOfClass:[NSMutableDictionary class]]) {
        [json addEntriesFromDictionary:patch];
    }
    NSData *out = [NSJSONSerialization dataWithJSONObject:json options:0 error:&e];
    DLog(@"原生层已注入 VIP: %@", url.absoluteString);
    return out ?: data;
}

typedef void (^SessionCompletion)(NSData *data, NSURLResponse *response, NSError *error);
static id (*orig_dataTaskWithRequest)(id, SEL, id, id);
static id (*orig_dataTaskWithURL)(id, SEL, id, id);

static id hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithRequest(self, _cmd, req, completion);
    NSURL *url = req.URL;
    return orig_dataTaskWithRequest(self, _cmd, req, ^(NSData *d, NSURLResponse *r, NSError *err){
        completion(maybePatch(d, r.URL ?: url), r, err);
    });
}
static id hook_dataTaskWithURL(id self, SEL _cmd, NSURL *url, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithURL(self, _cmd, url, completion);
    return orig_dataTaskWithURL(self, _cmd, url, ^(NSData *d, NSURLResponse *r, NSError *err){
        completion(maybePatch(d, r.URL ?: url), r, err);
    });
}

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
    if (b.length && [self.real respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)]) {
        [(id<NSURLSessionDataDelegate>)self.real URLSession:session dataTask:(NSURLSessionDataTask *)task didReceiveData:maybePatch(b, u)];
    }
    if ([self.real respondsToSelector:@selector(URLSession:task:didCompleteWithError:)]) {
        [(id<NSURLSessionTaskDelegate>)self.real URLSession:session task:task didCompleteWithError:error];
    }
}
@end

static id (*orig_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *queue) {
    if (delegate && ![delegate isKindOfClass:[DDProxy class]]) {
        return orig_sessionWithConfig(self, _cmd, cfg, [[DDProxy alloc] initWithReal:delegate], queue);
    }
    return orig_sessionWithConfig(self, _cmd, cfg, delegate, queue);
}

// ================= 安装 =================
__attribute__((constructor)) static void dandan_unlock_init(void) {
    Class cls = objc_getClass("NSURLSession");
    if (cls) {
        Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
        if (m1) { orig_dataTaskWithRequest = (id(*)(id,SEL,id,id))method_getImplementation(m1);
                  method_setImplementation(m1, (IMP)hook_dataTaskWithRequest); }
        Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
        if (m2) { orig_dataTaskWithURL = (id(*)(id,SEL,id,id))method_getImplementation(m2);
                  method_setImplementation(m2, (IMP)hook_dataTaskWithURL); }
        Method m3 = class_getClassMethod(cls, @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (m3) { orig_sessionWithConfig = (id(*)(id,SEL,id,id,id))method_getImplementation(m3);
                  method_setImplementation(m3, (IMP)hook_sessionWithConfig); }
    }

    Class wv = objc_getClass("WKWebView");
    if (wv) {
        Method mi = class_getInstanceMethod(wv, @selector(initWithFrame:configuration:));
        if (mi) { orig_wvInit = (id(*)(id,SEL,CGRect,id))method_getImplementation(mi);
                  method_setImplementation(mi, (IMP)hook_wvInit); }
        Method ml = class_getInstanceMethod(wv, @selector(loadRequest:));
        if (ml) { orig_wvLoadRequest = (id(*)(id,SEL,id))method_getImplementation(ml);
                  method_setImplementation(ml, (IMP)hook_wvLoadRequest); }
    }
    Class wvc = objc_getClass("WKWebViewConfiguration");
    if (wvc) {
        Method mg = class_getInstanceMethod(wvc, @selector(userContentController));
        if (mg) { orig_uccGetter = (id(*)(id,SEL))method_getImplementation(mg);
                  method_setImplementation(mg, (IMP)hook_uccGetter); }
    }

    DLog(@"=== dandan_unlock v4 已加载 (WKWebView=%s, Flutter=%s) ===",
         wv ? "yes" : "no",
         (NSClassFromString(@"FlutterViewController") || NSClassFromString(@"FlutterEngine")) ? "yes" : "no");
}
