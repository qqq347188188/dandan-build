//
//  dandan_unlock.m
//  蛋蛋不语 VIP 解锁 dylib —— 复刻 QuantumultX script-response-body 逻辑
//
//  原理：swizzle NSURLSession 的 completionHandler 方法，在 App 拿到响应体之前，
//  对命中 host=38.76.202.248:8000 且 path 含 "profiles" 的 HTTP 响应 JSON，
//  强制注入 VIP_PATCH 字段（与原始 JS 的 Object.assign 行为 1:1 一致）。
//
//  不依赖 CydiaSubstrate / ElleKit，纯 ObjC runtime，可直接用 TrollFools 注入任意 App。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// 与原始 dandanvip_unlock.js 的 VIP_PATCH 保持一致
static NSDictionary *VIP_PATCH(void) {
    return @{
        @"vip_status":    @YES,
        @"vip_level":     @3,
        @"vip_expire_at": @"2099-09-19T22:21:06.147807+00:00",
        @"username":      @"TG@Curtinp118",
        @"avatar_url":    @"https://i.ibb.co/NgghpGgn/11zon-A9-CBAC35-2-CA3-4-E7-F-923-D-7304-EEB40635.webp"
    };
}

// 仅对目标接口响应做改写；其余请求原样返回
static NSData *patchIfProfile(NSData *data, NSURL *url) {
    if (!data || !url) return data;
    if (![url.host isEqualToString:@"38.76.202.248"]) return data;
    if (url.port && url.port.integerValue != 8000) return data;
    if ([url.path rangeOfString:@"profiles" options:NSCaseInsensitiveSearch].location == NSNotFound) return data;

    NSError *e = nil;
    // 注意：NSURLSession 交给 completionHandler 的 NSData 已经是解压后的明文 JSON
    id json = [NSJSONSerialization JSONObjectWithData:data
                                              options:NSJSONReadingMutableContainers
                                                error:&e];
    if (e || !json) {
        NSLog(@"[dandan_unlock] JSON 解析失败，跳过改写");
        return data;
    }

    NSDictionary *patch = VIP_PATCH();
    if ([json isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)json)
            if ([item isKindOfClass:[NSMutableDictionary class]])
                [item addEntriesFromDictionary:patch];
    } else if ([json isKindOfClass:[NSMutableDictionary class]]) {
        // 1:1 复刻 JS 的 Object.assign(obj, VIP_PATCH)
        [(NSMutableDictionary *)json addEntriesFromDictionary:patch];
    }

    NSData *out = [NSJSONSerialization dataWithJSONObject:json options:0 error:&e];
    if (out) NSLog(@"[dandan_unlock] VIP 字段已注入");
    return out ?: data;
}

typedef void (^SessionCompletion)(NSData *data, NSURLResponse *response, NSError *error);

static id (*orig_dataTaskWithRequest)(id, SEL, id, id);
static id (*orig_dataTaskWithURL)(id, SEL, id, id);

static id hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithRequest(self, _cmd, req, completion);
    NSURL *url = req.URL;
    return orig_dataTaskWithRequest(self, _cmd, req, ^(NSData *d, NSURLResponse *r, NSError *err){
        NSData *patched = patchIfProfile(d, r.URL ?: url);
        completion(patched, r, err);
    });
}

static id hook_dataTaskWithURL(id self, SEL _cmd, NSURL *url, SessionCompletion completion) {
    if (!completion) return orig_dataTaskWithURL(self, _cmd, url, completion);
    return orig_dataTaskWithURL(self, _cmd, url, ^(NSData *d, NSURLResponse *r, NSError *err){
        NSData *patched = patchIfProfile(d, r.URL ?: url);
        completion(patched, r, err);
    });
}

__attribute__((constructor)) static void dandan_unlock_init(void) {
    Class cls = objc_getClass("NSURLSession");
    if (!cls) return;

    Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (m1) {
        orig_dataTaskWithRequest = (id(*)(id,SEL,id,id))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hook_dataTaskWithRequest);
    }

    Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (m2) {
        orig_dataTaskWithURL = (id(*)(id,SEL,id,id))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hook_dataTaskWithURL);
    }

    NSLog(@"[dandan_unlock] 已加载，开始拦截 profiles 接口");
}
