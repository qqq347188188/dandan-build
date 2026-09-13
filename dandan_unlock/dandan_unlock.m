//
//  dandan_unlock.m  (v6)
//  蛋蛋不语 VIP 解锁 dylib —— Flutter 套壳版（socket 层，非阻塞安全版）
//
//  目标：http://38.76.202.248:8000//rest/v1/profiles?select=*&id=eq.<uuid>
//  做法：fishhook 勾住 connect / write / read。
//        - connect 到 38.76.202.248:8000 的 socket 打标记；
//        - write 时改写请求：HTTP/1.1 -> HTTP/1.0（避免 chunked/长连接），
//          Accept-Encoding -> identity（避免 gzip）；
//        - read 时：只处理"本次读到的就是一个完整响应"的情况，就地改写后返回；
//          不完整则原样返回（不影响 App 正常联网）。
//        全程不阻塞、不攒包，最大限度避免卡线程/闪退。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

static void DLog(NSString *fmt, ...);

// ============================ fishhook ============================
#ifdef __LP64__
typedef struct mach_header_64     fbt_mach_header;
typedef struct segment_command_64 fbt_segment_command;
typedef struct section_64         fbt_section;
typedef struct nlist_64           fbt_nlist;
#define FBT_LC_SEG LC_SEGMENT_64
#else
typedef struct mach_header        fbt_mach_header;
typedef struct segment_command    fbt_segment_command;
typedef struct section            fbt_section;
typedef struct nlist              fbt_nlist;
#define FBT_LC_SEG LC_SEGMENT
#endif

struct fbt_rebinding { const char *name; void *replacement; void **replaced; };
struct fbt_entry { struct fbt_rebinding *r; size_t n; struct fbt_entry *next; };
static struct fbt_entry *fbt_head;
static const char *g_cur_img = "";
static char g_rb_log[16384];
static void rb_note(const char *sym, const char *img) {
    size_t cur = strlen(g_rb_log);
    if (cur > 15000 || !sym || !img) return;
    snprintf(g_rb_log + cur, sizeof(g_rb_log) - cur, "%s @ %s\n", sym, img);
}

static int fbt_prepend(struct fbt_rebinding rb[], size_t n) {
    struct fbt_entry *e = (struct fbt_entry *)malloc(sizeof(struct fbt_entry));
    if (!e) return -1;
    e->r = (struct fbt_rebinding *)malloc(sizeof(struct fbt_rebinding) * n);
    if (!e->r) { free(e); return -1; }
    memcpy(e->r, rb, sizeof(struct fbt_rebinding) * n);
    e->n = n; e->next = fbt_head; fbt_head = e;
    return 0;
}

// 把 [addr, addr+len) 所在页改成可写；失败返回 0
static int fbt_make_writable(void *addr, size_t len) {
    if (!addr || len == 0) return 0;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    uintptr_t end   = ((uintptr_t)addr + len + (uintptr_t)ps - 1) & ~(uintptr_t)(ps - 1);
    return mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE) == 0;
}

static void fbt_do_section(struct fbt_entry *rb, fbt_section *sect,
                           intptr_t slide, fbt_nlist *symtab, char *strtab, uint32_t *indirect) {
    if (!sect || sect->size == 0) return;
    uint32_t *idx = indirect + sect->reserved1;
    void **bind = (void **)((uintptr_t)slide + sect->addr);
    if (!bind) return;
    // iOS 上 __DATA_CONST 是只读段，直接写会 SIGBUS，先改成可写
    if (!fbt_make_writable(bind, (size_t)sect->size)) return;
    for (uint32_t i = 0; i < sect->size / sizeof(void *); i++) {
        uint32_t si = idx[i];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL ||
            si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        uint32_t off = symtab[si].n_un.n_strx;
        char *name = strtab + off;
        if (strnlen(name, 2) < 2) continue;
        for (struct fbt_entry *cur = rb; cur; cur = cur->next) {
            for (size_t j = 0; j < cur->n; j++) {
                if (strcmp(&name[1], cur->r[j].name) == 0) {
                    if (cur->r[j].replaced && bind[i] != cur->r[j].replacement)
                        *(cur->r[j].replaced) = bind[i];
                    bind[i] = cur->r[j].replacement;
                    rb_note(cur->r[j].name, g_cur_img);
                    goto next_sym;
                }
            }
        }
    next_sym:;
    }
}

static void fbt_image(struct fbt_entry *rb, const struct mach_header *h, intptr_t slide) {
    Dl_info info; if (dladdr(h, &info) == 0) return;
    g_cur_img = info.dli_fname ? info.dli_fname : "";
    fbt_segment_command *cur = NULL, *linkedit = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    uintptr_t p = (uintptr_t)h + sizeof(fbt_mach_header);
    for (uint32_t i = 0; i < h->ncmds; i++, p += cur->cmdsize) {
        cur = (fbt_segment_command *)p;
        if (cur->cmd == FBT_LC_SEG) {
            if (strcmp(cur->segname, SEG_LINKEDIT) == 0) linkedit = cur;
        } else if (cur->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur;
        } else if (cur->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur;
        }
    }
    if (!symtab_cmd || !dysymtab_cmd || !linkedit || !dysymtab_cmd->nindirectsyms) return;
    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    fbt_nlist *symtab = (fbt_nlist *)(base + symtab_cmd->symoff);
    char *strtab = (char *)(base + symtab_cmd->stroff);
    uint32_t *indirect = (uint32_t *)(base + dysymtab_cmd->indirectsymoff);
    p = (uintptr_t)h + sizeof(fbt_mach_header);
    for (uint32_t i = 0; i < h->ncmds; i++, p += cur->cmdsize) {
        cur = (fbt_segment_command *)p;
        if (cur->cmd != FBT_LC_SEG) continue;
        if (strcmp(cur->segname, SEG_DATA) != 0 && strcmp(cur->segname, "__DATA_CONST") != 0) continue;
        for (uint32_t j = 0; j < cur->nsects; j++) {
            fbt_section *s = (fbt_section *)(p + sizeof(fbt_segment_command)) + j;
            if ((s->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                (s->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                fbt_do_section(rb, s, slide, symtab, strtab, indirect);
            }
        }
    }
}

static void fbt_image_cb(const struct mach_header *h, intptr_t slide) {
    fbt_image(fbt_head, h, slide);
}

static int fbt_rebind(struct fbt_rebinding rb[], size_t n) {
    if (fbt_prepend(rb, n) < 0) return -1;
    if (!fbt_head->next) {
        _dyld_register_func_for_add_image(fbt_image_cb);
    } else {
        for (uint32_t i = 0; i < _dyld_image_count(); i++)
            fbt_image(fbt_head, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}

// ============================ 日志 ============================
static NSString *DDLogPath(void) {
    static NSString *p; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        p = [d stringByAppendingPathComponent:@"dandan_unlock.log"];
    });
    return p;
}
static void DLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[dandan_unlock] %@", m);
    @try {
        NSString *line = [NSString stringWithFormat:@"%@  %@\n", [NSDate date], m];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:DDLogPath()];
        if (!fh) [line writeToFile:DDLogPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (__unused NSException *e) {}
}

// ============================ 工具 ============================
static const void *fb_memmem(const void *hay, size_t hl, const void *needle, size_t nl) {
    if (!nl || hl < nl) return NULL;
    const unsigned char *h = (const unsigned char *)hay;
    for (size_t i = 0; i + nl <= hl; i++)
        if (memcmp(h + i, needle, nl) == 0) return h + i;
    return NULL;
}

static long parse_content_length(const unsigned char *b, size_t hdrEnd) {
    static const char *key = "content-length:";
    const size_t keyLen = 15;
    size_t i = 0;
    while (i < hdrEnd) {
        size_t j = i;
        while (j + 1 < hdrEnd && !(b[j] == '\r' && b[j + 1] == '\n')) j++;
        size_t lineLen = (j < hdrEnd) ? (j - i) : (hdrEnd - i);
        if (lineLen > keyLen) {
            int ok = 1;
            for (size_t k = 0; k < keyLen; k++) {
                unsigned char c = b[i + k];
                if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
                if (c != (unsigned char)key[k]) { ok = 0; break; }
            }
            if (ok) {
                long v = 0; int seen = 0;
                for (size_t k = keyLen; k < lineLen; k++) {
                    unsigned char c = b[i + k];
                    if (c >= '0' && c <= '9') { v = v * 10 + (c - '0'); seen = 1; }
                    else if (seen) break;
                }
                return seen ? v : 0;
            }
        }
        if (j >= hdrEnd) break;
        i = j + 2;
    }
    return -1;
}

static int response_complete(const unsigned char *b, size_t len) {
    const unsigned char *p = (const unsigned char *)fb_memmem(b, len, "\r\n\r\n", 4);
    if (!p) return 0;
    size_t hdrEnd = (size_t)(p - b) + 4;
    long cl = parse_content_length(b, hdrEnd);
    if (cl < 0) return 0;
    return (len >= hdrEnd + (size_t)cl);
}

// ============================ 响应改写 ============================
static NSData *patched_response(NSData *raw) {
    const unsigned char *b = (const unsigned char *)raw.bytes;
    size_t len = raw.length;
    if (len < 4) return raw;
    const unsigned char *p = (const unsigned char *)fb_memmem(b, len, "\r\n\r\n", 4);
    if (!p) return raw;
    size_t hdrEnd = (size_t)(p - b) + 4;
    if (hdrEnd > len) return raw;
    if (fb_memmem(b, hdrEnd, "chunked", 7)) return raw;

    NSData *body = [NSData dataWithBytes:(b + hdrEnd) length:(len - hdrEnd)];
    NSError *e = nil;
    id json = [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingMutableContainers error:&e];
    if (e || !json) return raw;

    NSDictionary *P = @{ @"vip_status": @YES,
                         @"vip_level":  @3,
                         @"vip_expire_at": @"2099-09-19T22:21:06.147807+00:00" };
    if ([json isKindOfClass:[NSArray class]]) {
        for (id it in (NSArray *)json)
            if ([it isKindOfClass:[NSMutableDictionary class]]) [it addEntriesFromDictionary:P];
    } else if ([json isKindOfClass:[NSMutableDictionary class]]) {
        [(NSMutableDictionary *)json addEntriesFromDictionary:P];
    }
    NSData *nb = [NSJSONSerialization dataWithJSONObject:json options:0 error:&e];
    if (!nb || nb.length == 0) return raw;

    {
        long clOld = parse_content_length(b, hdrEnd);
        char po[161] = {0}, pn2[161] = {0};
        size_t olen = (len - hdrEnd) < 160 ? (len - hdrEnd) : 160;
        size_t nlen = nb.length < 160 ? nb.length : 160;
        memcpy(po, b + hdrEnd, olen);
        memcpy(pn2, nb.bytes, nlen);
        DLog(@"[resp] CL_old=%ld hdr=%lu body_old=%lu body_new=%lu", clOld, (unsigned long)hdrEnd,
             (unsigned long)(len - hdrEnd), (unsigned long)nb.length);
        DLog(@"[resp] old=%s", po);
        DLog(@"[resp] new=%s", pn2);
    }

    NSString *hs = [[NSString alloc] initWithData:[NSData dataWithBytes:b length:hdrEnd]
                                         encoding:NSISOLatin1StringEncoding];
    if (!hs) return raw;
    NSMutableArray *lines = [[hs componentsSeparatedByString:@"\r\n"] mutableCopy];
    BOOL rep = NO;
    for (NSUInteger i = 0; i < lines.count; i++) {
        if ([((NSString *)lines[i]).lowercaseString hasPrefix:@"content-length:"]) {
            lines[i] = [NSString stringWithFormat:@"Content-Length: %lu", (unsigned long)nb.length];
            rep = YES;
        }
    }
    if (!rep && lines.count > 0)
        [lines insertObject:[NSString stringWithFormat:@"Content-Length: %lu", (unsigned long)nb.length]
                    atIndex:lines.count - 1];

    NSMutableData *out = [NSMutableData data];
    [out appendData:[[lines componentsJoinedByString:@"\r\n"] dataUsingEncoding:NSISOLatin1StringEncoding]];
    [out appendData:nb];
    return out;
}

// ============================ 请求改写 ============================
static NSData *rewrite_request(const void *buf, size_t len) {
    if (!buf || len == 0) return [NSData data];
    const unsigned char *b = (const unsigned char *)buf;
    static const char *key = "accept-encoding:";
    const size_t keyLen = 16;
    long ki = -1;
    for (size_t i = 0; i + keyLen <= len; i++) {
        int ok = 1;
        for (size_t k = 0; k < keyLen; k++) {
            unsigned char c = b[i + k];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
            if (c != (unsigned char)key[k]) { ok = 0; break; }
        }
        if (ok) { ki = (long)i; break; }
    }
    // 关键：必须保持请求长度一字不变，否则会破坏 Dart 非阻塞 socket 的写状态机 / HTTP 流
    NSMutableData *m = [NSMutableData dataWithBytes:buf length:len];
    unsigned char *mb = (unsigned char *)m.mutableBytes;
    size_t n = m.length;
    if (ki >= 0) {
        size_t j = (size_t)ki + keyLen;
        while (j < n && (mb[j] == ' ' || mb[j] == '\t')) j++;
        size_t v = j;
        while (v < n && mb[v] != '\r' && mb[v] != '\n') v++;
        if (v > j) memset(mb + j, 'x', v - j);   // 未知编码 -> 服务器按 identity 处理（不压缩）
    }
    // 注意：不再把 HTTP/1.1 改成 HTTP/1.0。
    // 降级会让服务器响应后关闭连接，而 Dart 的 HttpClient 仍按 keep-alive 复用该连接，
    // 导致 "Connection closed while receiving data"。这里保持请求版本不变。
    return m;
}

// ============================ 连接状态 ============================
#define MAXFD 4096
typedef struct {
    int tracked;         // 连到目标服务器
    int patch;           // 当前请求是 profiles
    unsigned char *out;  // 改写后变长、暂存的剩余字节
    size_t outLen, outPos;
} Conn;
static Conn g_conn[MAXFD];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_inside = 0;
static int g_seen_connect = 0, g_seen_read = 0, g_seen_write = 0;

static void conn_reset(Conn *c) {
    if (c->out) { free(c->out); c->out = NULL; }
    c->outLen = c->outPos = 0;
}

// ============================ 原函数指针 ============================
static int    (*o_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t(*o_read)(int, void *, size_t);
static ssize_t(*o_write)(int, const void *, size_t);

static const char *TARGET_IP = "38.76.202.248";
static const int   TARGET_PORT = 8000;

// ============================ WKWebView 注入（对付 H5 壳） ============================
static NSString *DandanJS(void) {
    static NSString *js; static dispatch_once_t o;
    dispatch_once(&o, ^{
        js = @"(function(){if(window.__dandan){return;}window.__dandan=1;try{var P={vip_status:true,vip_level:3,vip_expire_at:'2099-09-19T22:21:06.147807+00:00'};function T(u){return typeof u==='string'&&(u.indexOf('38.76.202.248')>-1||u.indexOf('/profiles')>-1);}function patch(t){try{var j=JSON.parse(t);var p=function(o){if(o&&typeof o==='object'){Object.assign(o,P);}};if(Array.isArray(j)){j.forEach(p);}else{p(j);}return JSON.stringify(j);}catch(e){return t;}}var of=window.fetch;if(of){window.fetch=function(i,n){var u=(typeof i==='string')?i:((i&&i.url)||'');return of.apply(this,arguments).then(function(r){if(!T(u)){return r;}return r.clone().text().then(function(t){var b=patch(t);var h=new Headers(r.headers);h.delete('content-length');return new Response(b,{status:r.status,statusText:r.statusText,headers:h});}).catch(function(){return r;});});};}var oo=XMLHttpRequest.prototype.open;var os=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.open=function(m,u){this.__du=u;return oo.apply(this,arguments);};XMLHttpRequest.prototype.send=function(){var x=this;x.addEventListener('readystatechange',function(){if(x.readyState===4&&T(x.__du)){try{var b=patch(x.responseText);Object.defineProperty(x,'responseText',{configurable:true,get:function(){return b;}});}catch(e){}}});return os.apply(this,arguments);};}catch(e){}})();";
    });
    return js;
}

static const void *kDandanKey = &kDandanKey;

static void dandanAttach(WKUserContentController *ucc) {
    if (!ucc) return;
    if (objc_getAssociatedObject(ucc, kDandanKey)) return;
    objc_setAssociatedObject(ucc, kDandanKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    WKUserScript *s = [[WKUserScript alloc] initWithSource:DandanJS()
                                             injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                          forMainFrameOnly:NO];
    [ucc addUserScript:s];
    DLog(@"[WKWebView] 已注入 userScript");
}

static void dandanAddConfig(WKWebViewConfiguration *config) {
    if (!config) return;
    WKUserContentController *ucc = config.userContentController;
    if (!ucc) { ucc = [[WKUserContentController alloc] init]; config.userContentController = ucc; }
    dandanAttach(ucc);
}

static id (*o_uccGetter)(id, SEL);
static id my_uccGetter(id self, SEL _cmd) {
    id ucc = o_uccGetter(self, _cmd);
    @try { dandanAttach(ucc); } @catch (__unused NSException *e) {}
    return ucc;
}

static id (*o_wvInit)(id, SEL, CGRect, id);
static id my_wvInit(id self, SEL _cmd, CGRect frame, id config) {
    DLog(@"[WKWebView] initWithFrame:configuration:");
    @try { dandanAddConfig(config); } @catch (__unused NSException *e) {}
    return o_wvInit(self, _cmd, frame, config);
}

static id (*o_wvLoad)(id, SEL, NSURLRequest *);
static id my_wvLoad(id self, SEL _cmd, NSURLRequest *req) {
    DLog(@"[WKWebView] loadRequest: %@", req.URL.absoluteString);
    @try { dandanAddConfig([(WKWebView *)self configuration]); } @catch (__unused NSException *e) {}
    return o_wvLoad(self, _cmd, req);
}

// ============================ Hooks ============================
static int my_connect(int fd, const struct sockaddr *addr, socklen_t al) {
    if (g_inside || !o_connect) return o_connect(fd, addr, al);
    if (!g_seen_connect) { g_seen_connect = 1; DLog(@"[hook] my_connect 首次被调用"); }
    g_inside = 1;
    int r = o_connect(fd, addr, al);
    int cerrno = errno;
    // 非阻塞 socket 的 connect 会返回 -1/EINPROGRESS（连接在后台继续），也算成功
    int ok = (r == 0) || (r == -1 && cerrno == EINPROGRESS);
    if (ok && addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
        int port = ntohs(s->sin_port);
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        if (port == TARGET_PORT && strcmp(ip, TARGET_IP) == 0 && fd >= 0 && fd < MAXFD) {
            pthread_mutex_lock(&g_lock);
            conn_reset(&g_conn[fd]);
            g_conn[fd].tracked = 1; g_conn[fd].patch = 0;
            pthread_mutex_unlock(&g_lock);
            DLog(@"[socket] 命中目标连接 fd=%d %s:%d", fd, ip, TARGET_PORT);
        }
    }
    g_inside = 0;
    return r;
}

static ssize_t my_write(int fd, const void *buf, size_t len) {
    if (g_inside || !o_write) return o_write(fd, buf, len);
    if (!g_seen_write) { g_seen_write = 1; DLog(@"[hook] my_write 首次被调用"); }
    int tracked = 0;
    if (fd >= 0 && fd < MAXFD) tracked = g_conn[fd].tracked;
    if (!tracked || !buf || !len) return o_write(fd, buf, len);
    g_inside = 1;

    ssize_t r;
    if (1) {
        int isProfile = fb_memmem(buf, len, "profiles", 8) ? 1 : 0;
        NSData *nb = rewrite_request(buf, len);
        pthread_mutex_lock(&g_lock);
        if (fd >= 0 && fd < MAXFD) { conn_reset(&g_conn[fd]); g_conn[fd].tracked = 1; g_conn[fd].patch = isProfile; }
        pthread_mutex_unlock(&g_lock);
        r = o_write(fd, nb.bytes, nb.length);
    } else {
        r = o_write(fd, buf, len);
    }
    g_inside = 0;
    return r;
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (g_inside || !o_read) return o_read(fd, buf, count);
    if (!g_seen_read) { g_seen_read = 1; DLog(@"[hook] my_read 首次被调用"); }
    int tracked = 0, patch = 0;
    if (fd >= 0 && fd < MAXFD) { tracked = g_conn[fd].tracked; patch = g_conn[fd].patch; }
    if (!tracked || !patch || !buf || count == 0) return o_read(fd, buf, count);
    g_inside = 1;

    ssize_t r;

    // 先吐上次没吐完的
    pthread_mutex_lock(&g_lock);
    Conn *c = &g_conn[fd];
    if (c->out && c->outPos < c->outLen) {
        size_t n = c->outLen - c->outPos; if (n > count) n = count;
        memcpy(buf, c->out + c->outPos, n); c->outPos += n;
        if (c->outPos >= c->outLen) { free(c->out); c->out = NULL; c->outLen = c->outPos = 0; }
        pthread_mutex_unlock(&g_lock);
        g_inside = 0;
        return (ssize_t)n;
    }
    pthread_mutex_unlock(&g_lock);

    // 只读一次，不阻塞
    r = o_read(fd, buf, count);
    if (r <= 0) { g_inside = 0; return r; }

    // 只有本次读到的是一个完整响应才改写，否则原样放过
    if (!response_complete((const unsigned char *)buf, (size_t)r)) {
        g_inside = 0;
        return r;
    }

    NSData *raw = [NSData dataWithBytesNoCopy:buf length:(size_t)r freeWhenDone:NO];
    NSData *out = patched_response(raw);
    if (out == raw) { g_inside = 0; return r; }   // 没能改写，原样返回

    size_t ol = out.length;
    DLog(@"[socket] 响应改写 fd=%d %lu -> %lu", fd, (unsigned long)r, (unsigned long)ol);
    if (ol <= count) {
        memcpy(buf, out.bytes, ol);
        g_inside = 0;
        return (ssize_t)ol;
    }
    // 变长了：超出的部分暂存，下次 read 再给
    memcpy(buf, out.bytes, count);
    pthread_mutex_lock(&g_lock);
    Conn *c2 = &g_conn[fd];
    if (c2->out) free(c2->out);
    c2->out = (unsigned char *)malloc(ol - count);
    if (c2->out) {
        memcpy(c2->out, (const unsigned char *)out.bytes + count, ol - count);
        c2->outLen = ol - count; c2->outPos = 0;
    } else { c2->outLen = c2->outPos = 0; }
    pthread_mutex_unlock(&g_lock);
    g_inside = 0;
    return (ssize_t)count;
}

// ============================ 入口 ============================
__attribute__((constructor)) static void dandan_unlock_init(void) {
    o_connect = (int(*)(int,const struct sockaddr*,socklen_t))dlsym(RTLD_DEFAULT, "connect");
    o_read    = (ssize_t(*)(int,void*,size_t))dlsym(RTLD_DEFAULT, "read");
    o_write   = (ssize_t(*)(int,const void*,size_t))dlsym(RTLD_DEFAULT, "write");

    struct fbt_rebinding rb[] = {
        { "connect", (void *)my_connect, (void **)&o_connect },
        { "read",    (void *)my_read,    (void **)&o_read },
        { "write",   (void *)my_write,   (void **)&o_write },
    };
    int ret = fbt_rebind(rb, sizeof(rb) / sizeof(rb[0]));
    if (g_rb_log[0]) DLog(@"[rebind] 已替换:\n%s", g_rb_log);

    Class wv = objc_getClass("WKWebView");
    if (wv) {
        Method mi = class_getInstanceMethod(wv, @selector(initWithFrame:configuration:));
        if (mi) { o_wvInit = (id(*)(id,SEL,CGRect,id))method_getImplementation(mi); method_setImplementation(mi, (IMP)my_wvInit); }
        Method ml = class_getInstanceMethod(wv, @selector(loadRequest:));
        if (ml) { o_wvLoad = (id(*)(id,SEL,id))method_getImplementation(ml); method_setImplementation(ml, (IMP)my_wvLoad); }
    }
    Class wvc = objc_getClass("WKWebViewConfiguration");
    if (wvc) {
        Method mg = class_getInstanceMethod(wvc, @selector(userContentController));
        if (mg) { o_uccGetter = (id(*)(id,SEL))method_getImplementation(mg); method_setImplementation(mg, (IMP)my_uccGetter); }
    }

    DLog(@"=== dandan_unlock v15 已加载 (rebind=%d, Flutter=%s, WKWebView=%s) ===", ret,
         (NSClassFromString(@"FlutterViewController") || NSClassFromString(@"FlutterEngine")) ? "yes" : "no",
         wv ? "yes" : "no");
}
