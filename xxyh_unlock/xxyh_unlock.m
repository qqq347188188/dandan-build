//
//  xxyh_unlock.m —— 小熊油耗 VIP 解锁（iOS 原生版）
//
//  目标接口：
//    http(s)://www.xiaoxiongyouhao.com/api/vip/index.php
//
//  做法：swizzle NSURLSession 的 dataTask 两个 completionHandler 入口
//        （以及老版 AFNetworking 的 NSURLConnection sendAsynchronousRequest 兜底），
//        命中目标 URL 时对响应体做 3 处替换（等价于圈X 脚本）：
//          vip_state":\d              -> vip_state":2
//          membership_days":\d+       -> membership_days":888
//          vip_valid_till_date":"..." -> vip_valid_till_date":"9999年08月31日"
//        改完换新 NSData 回调给 App，长度可变，无任何等长约束。
//
//  日志：沙盒 Documents/xxyh_unlock.log
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// ============================ 日志 ============================
static NSString *LogPath(void) {
    static NSString *p; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        p = [d stringByAppendingPathComponent:@"xxyh_unlock.log"];
    });
    return p;
}

static void LLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[xxyh] %@", m);
    @try {
        NSString *line = [NSString stringWithFormat:@"%@  %@\n", [NSDate date], m];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:LogPath()];
        if (!fh) [line writeToFile:LogPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (__unused NSException *e) {}
}

// ============================ 目标判定 ============================
static BOOL isTargetURL(NSURL *u) {
    if (!u) return NO;
    if (![u.host.lowercaseString isEqualToString:@"www.xiaoxiongyouhao.com"]) return NO;
    return [u.path.lowercaseString containsString:@"/api/vip/index.php"];
}

// ============================ 响应改写 ============================
static NSString *rx(NSString *s, NSString *pattern, NSString *templ) {
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL];
    if (!re) return s;
    return [re stringByReplacingMatchesInString:s options:0
                                          range:NSMakeRange(0, s.length)
                                   withTemplate:templ];
}

static NSData *patchBody(NSData *data) {
    if (!data.length) return data;
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) s = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    if (!s) { LLog(@"响应不是文本，跳过 (%lu bytes)", (unsigned long)data.length); return data; }

    NSString *before = s;
    s = rx(s, @"vip_state\":\\d",        @"vip_state\":2");
    s = rx(s, @"membership_days\":\\d+", @"membership_days\":888");
    s = rx(s, @"vip_valid_till_date\":\"[^\"]*\"",
                                         @"vip_valid_till_date\":\"9999年08月31日\"");
    if ([s isEqualToString:before]) {
        LLog(@"未发现可改字段（原文前 300 字）：%@",
             before.length > 300 ? [before substringToIndex:300] : before);
        return data;
    }
    NSData *nd = [s dataUsingEncoding:NSUTF8StringEncoding];
    LLog(@"改写完成：原 %lu 字节 -> 新 %lu 字节", (unsigned long)data.length, (unsigned long)nd.length);
    return nd;
}

// 包一层 completionHandler：命中则改 body
typedef void (^XXYHComp)(NSData *, NSURLResponse *, NSError *);
static id wrapCompletion(NSURL *u, id completion) {
    if (!completion) return completion;
    XXYHComp orig = (XXYHComp)completion;
    return ^(NSData *d, NSURLResponse *resp, NSError *err) {
        NSHTTPURLResponse *h = (NSHTTPURLResponse *)resp;
        LLog(@"响应 %@ status=%ld len=%lu err=%@",
             u.absoluteString, (long)h.statusCode, (unsigned long)d.length,
             err.localizedDescription ?: @"-");
        NSData *nd = (err || !d) ? d : patchBody(d);
        orig(nd, resp, err);
    };
}

// ============================ swizzle ============================
static void swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { LLog(@"[warn] 找不到方法 %@", NSStringFromSelector(sel)); return; }
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    LLog(@"[hook] %@", NSStringFromSelector(sel));
}

static id (*o_dt_req_c)(id, SEL, NSURLRequest *, id);
static id my_dt_req_c(id self, SEL _cmd, NSURLRequest *req, id completion) {
    NSURL *u = req.URL;
    if (!isTargetURL(u)) return o_dt_req_c(self, _cmd, req, completion);
    LLog(@"★ 命中请求 %@", u.absoluteString);
    return o_dt_req_c(self, _cmd, req, wrapCompletion(u, completion));
}

static id (*o_dt_url_c)(id, SEL, NSURL *, id);
static id my_dt_url_c(id self, SEL _cmd, NSURL *u, id completion) {
    if (!isTargetURL(u)) return o_dt_url_c(self, _cmd, u, completion);
    LLog(@"★ 命中请求 %@", u.absoluteString);
    return o_dt_url_c(self, _cmd, u, wrapCompletion(u, completion));
}

// 无 completionHandler 的 dataTask（delegate 模式）：先记录，万一走这条路再补 hook
static int g_delegCount = 0;
static id (*o_dt_req)(id, SEL, NSURLRequest *);
static id my_dt_req(id self, SEL _cmd, NSURLRequest *req) {
    if (isTargetURL(req.URL)) LLog(@"[注意] 目标请求走了 delegate 模式 %@", req.URL.absoluteString);
    else if (++g_delegCount <= 10) LLog(@"[task] %@", req.URL.absoluteString);
    return o_dt_req(self, _cmd, req);
}

// 老 AFNetworking（NSURLConnection）兜底
static void (*o_conn_async)(id, SEL, NSURLRequest *, NSOperationQueue *, id);
static void my_conn_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *q, id completion) {
    NSURL *u = req.URL;
    if (!isTargetURL(u)) { o_conn_async(self, _cmd, req, q, completion); return; }
    LLog(@"★ 命中请求(NSURLConnection) %@", u.absoluteString);
    id block = wrapCompletion(u, completion);
    o_conn_async(self, _cmd, req, q, block);
}

// ============================ delegate 模式（v2 核心） ============================
// App 用 dataTaskWithRequest: + 自己的 delegate 收数据。
// 做法：hook sessionWithConfiguration:delegate:delegateQueue:，对 delegate 的类做
//       类级 swizzle：didReceiveData 攒包不给 App，didComplete 时改好整份再回调。
static NSMutableDictionary<NSValue *, NSMutableData *> *g_acc;
static NSMutableSet<NSString *> *g_swizzledClasses;
static NSMutableDictionary<NSString *, NSValue *> *g_origData;
static NSMutableDictionary<NSString *, NSValue *> *g_origDone;

static NSValue *taskKey(id task) { return [NSValue valueWithNonretainedObject:task]; }

static IMP origOf(NSMutableDictionary<NSString *, NSValue *> *store, id self) {
    NSValue *v = store[NSStringFromClass(object_getClass(self))];
    return v ? (IMP)v.pointerValue : NULL;
}

static void my_didReceiveData(id self, SEL _cmd, NSURLSession *session,
                              NSURLSessionDataTask *task, NSData *data) {
    if (isTargetURL(task.originalRequest.URL)) {
        NSValue *k = taskKey(task);
        @synchronized (g_acc) {
            NSMutableData *acc = g_acc[k];
            if (!acc) { acc = [NSMutableData data]; g_acc[k] = acc; }
            [acc appendData:data];
        }
        return;                      // 攒着，先不给 App
    }
    IMP o = origOf(g_origData, self);
    if (o) ((void (*)(id, SEL, id, id, id))o)(self, _cmd, session, task, data);
}

static void my_didComplete(id self, SEL _cmd, NSURLSession *session,
                           NSURLSessionTask *task, NSError *error) {
    if (isTargetURL(task.originalRequest.URL)) {
        NSMutableData *acc = nil;
        NSValue *k = taskKey(task);
        @synchronized (g_acc) { acc = g_acc[k]; [g_acc removeObjectForKey:k]; }
        if (acc && acc.length) {
            LLog(@"★ 攒包完成 %lu 字节，开始改写", (unsigned long)acc.length);
            NSData *patched = patchBody(acc);
            IMP oData = origOf(g_origData, self);
            if (oData)
                ((void (*)(id, SEL, id, id, id))oData)(
                    self, @selector(URLSession:dataTask:didReceiveData:), session, task, patched);
        }
    }
    IMP o = origOf(g_origDone, self);
    if (o) ((void (*)(id, SEL, id, id, id))o)(self, _cmd, session, task, error);
}

static void swizzleDelegateMethods(Class cls, NSString *cn) {
    Method m1 = class_getInstanceMethod(cls, @selector(URLSession:dataTask:didReceiveData:));
    if (m1) {
        g_origData[cn] = [NSValue valueWithPointer:method_getImplementation(m1)];
        method_setImplementation(m1, (IMP)my_didReceiveData);
    } else {
        class_addMethod(cls, @selector(URLSession:dataTask:didReceiveData:),
                        (IMP)my_didReceiveData, "v@:@@@");
    }
    Method m2 = class_getInstanceMethod(cls, @selector(URLSession:task:didCompleteWithError:));
    if (m2) {
        g_origDone[cn] = [NSValue valueWithPointer:method_getImplementation(m2)];
        method_setImplementation(m2, (IMP)my_didComplete);
    } else {
        class_addMethod(cls, @selector(URLSession:task:didCompleteWithError:),
                        (IMP)my_didComplete, "v@:@@@");
    }
    LLog(@"[delegate] 已 hook 代理类 %@", cn);
}

static id (*o_session)(id, SEL, id, id, id);
static id my_session(id self, SEL _cmd, id config, id delegate, id queue) {
    id r = o_session(self, _cmd, config, delegate, queue);
    if (delegate) {
        NSString *cn = NSStringFromClass(object_getClass(delegate));
        @synchronized (g_swizzledClasses) {
            if (![g_swizzledClasses containsObject:cn]) {
                [g_swizzledClasses addObject:cn];
                swizzleDelegateMethods(object_getClass(delegate), cn);
            }
        }
    }
    return r;
}

// ============================ 入口 ============================
__attribute__((constructor)) static void xxyh_init(void) {
    LLog(@"========== xxyh_unlock v2 已加载 ==========");
    g_acc           = [NSMutableDictionary dictionary];
    g_swizzledClasses = [NSMutableSet set];
    g_origData      = [NSMutableDictionary dictionary];
    g_origDone      = [NSMutableDictionary dictionary];
    Class ss = objc_getClass("NSURLSession");
    if (ss) {
        swizzle(ss, @selector(dataTaskWithRequest:completionHandler:),
                (IMP)my_dt_req_c, (IMP *)&o_dt_req_c);
        swizzle(ss, @selector(dataTaskWithURL:completionHandler:),
                (IMP)my_dt_url_c, (IMP *)&o_dt_url_c);
        swizzle(ss, @selector(dataTaskWithRequest:),
                (IMP)my_dt_req, (IMP *)&o_dt_req);
        swizzle(ss, @selector(sessionWithConfiguration:delegate:delegateQueue:),
                (IMP)my_session, (IMP *)&o_session);
    }
    Class conn = objc_getClass("NSURLConnection");
    if (conn) {
        swizzle(conn, @selector(sendAsynchronousRequest:queue:completionHandler:),
                (IMP)my_conn_async, (IMP *)&o_conn_async);
    }
    LLog(@"========== 就绪：打开 App 进 VIP/我的页面 ==========");
}
