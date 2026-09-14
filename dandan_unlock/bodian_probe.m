//
//  bodian_probe.m  (v3 —— 进程内 MITM)
//  波点音乐（Flutter 套壳）—— 把"圈X 的 MITM"搬进 App 进程内
//
//  原理：
//    Dart/NSURLSession 发起的 https 请求，在 connect() 时目标 IP:443 被重定向到
//    本 dylib 在 127.0.0.1 起的本地 TLS 服务器；
//    本地服务器用自签 CA 签发的证书（SAN 覆盖目标域名）完成 TLS 终止，
//    拿到明文 HTTP 后原样转发到真实服务器，再把响应原样返回给 App。
//
//  v3 目标（第一步）：验证握手 + 透明转发 + 抓明文。
//    改写（bdyy.js 逻辑）留到 STAGE 2，在 forwardRequest() 里接 JSC 即可。
//
//  日志：
//    Documents/bodian_mitm.log  —— 运行/诊断
//    Documents/bodian_resp.log  —— 拦截到的响应原文（截断 64KB）
//
//  开关（ Documents/ 下）：
//    bodian_mitm_off        存在 => 完全跳过 MITM（App 行为不变）
//    bodian_mitm_hosts.txt  每行一条规则（# 注释）：以点开头=后缀匹配，否则精确/后缀匹配
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>

#include <stdarg.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#import "bodian_cert.h"

// ============================ fishhook ============================
#ifdef __LP64__
typedef struct mach_header_64     fbt_mach_header;
typedef struct segment_command_64 fbt_segment_command;
typedef struct section_64         fbt_section_t;
typedef struct nlist_64           fbt_nlist;
#define FBT_LC_SEG LC_SEGMENT_64
#else
typedef struct mach_header        fbt_mach_header;
typedef struct segment_command    fbt_segment_command;
typedef struct section            fbt_section_t;
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
    snprintf(g_rb_log + cur, sizeof(g_rb_log) - cur, "    %s @ %s\n", sym, img);
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

static int fbt_make_writable(void *addr, size_t len) {
    if (!addr || len == 0) return 0;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    uintptr_t end   = ((uintptr_t)addr + len + (uintptr_t)ps - 1) & ~(uintptr_t)(ps - 1);
    return mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE) == 0;
}

static void fbt_do_section(struct fbt_entry *rb, fbt_section_t *sect,
                           intptr_t slide, fbt_nlist *symtab, char *strtab, uint32_t *indirect) {
    if (!sect || sect->size == 0) return;
    uint32_t *idx = indirect + sect->reserved1;
    void **bind = (void **)((uintptr_t)slide + sect->addr);
    if (!bind) return;
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
            fbt_section_t *s = (fbt_section_t *)(p + sizeof(fbt_segment_command)) + j;
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
static NSString *SandboxPath(NSString *name) {
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [d stringByAppendingPathComponent:name];
}
static NSString *ProbeLogPath(void) { return SandboxPath(@"bodian_mitm.log"); }
static NSString *RespLogPath(void)  { return SandboxPath(@"bodian_resp.log"); }

static void appendFile(NSString *path, NSString *text) {
    if (!path || !text) return;
    @try {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        else { [fh seekToEndOfFile]; [fh writeData:[text dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (__unused NSException *e) {}
}

static void DLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[bodian_mitm] %@", m);
    appendFile(ProbeLogPath(), [NSString stringWithFormat:@"%@  %@\n", [NSDate date], m]);
}

static void Dump(NSString *name, NSData *data) {
    if (!data.length) return;
    NSData *d = data;
    if (d.length > 65536) d = [d subdataWithRange:NSMakeRange(0, 65536)];
    NSString *t = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!t) t = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
    if (!t) return;
    appendFile(RespLogPath(), [NSString stringWithFormat:
        @"\n===== %@  (%lu bytes) =====\n%@\n", name, (unsigned long)d.length, t]);
}

// ============================ 目标 host / IP 集合 ============================
static NSMutableSet *g_targetHosts;
static NSMutableSet *g_targetIPs;
static NSMutableSet *g_targetIP6;
static pthread_mutex_t g_ipLock = PTHREAD_MUTEX_INITIALIZER;

static BOOL isTargetHost(NSString *host) {
    if (!host.length) return NO;
    NSString *h = host.lowercaseString;
    @synchronized (g_targetHosts) {
        for (NSString *rule in g_targetHosts) {
            NSString *search = [rule hasPrefix:@"."] ? rule : [@"." stringByAppendingString:rule];
            if ([h isEqualToString:rule] || [h hasSuffix:search]) return YES;
        }
    }
    return NO;
}
static void addTargetIP(NSString *ip) {
    if (!ip) return;
    pthread_mutex_lock(&g_ipLock); [g_targetIPs addObject:ip]; pthread_mutex_unlock(&g_ipLock);
}
static void addTargetIP6(NSString *ip) {
    if (!ip) return;
    pthread_mutex_lock(&g_ipLock); [g_targetIP6 addObject:ip]; pthread_mutex_unlock(&g_ipLock);
}
static BOOL isTargetIP(struct in_addr a) {
    char ip[64]; inet_ntop(AF_INET, &a, ip, sizeof ip);
    pthread_mutex_lock(&g_ipLock); BOOL r = [g_targetIPs containsObject:@(ip)]; pthread_mutex_unlock(&g_ipLock); return r;
}
static BOOL isTargetIP6(struct in6_addr a) {
    char ip[64]; inet_ntop(AF_INET6, &a, ip, sizeof ip);
    pthread_mutex_lock(&g_ipLock); BOOL r = [g_targetIP6 containsObject:@(ip)]; pthread_mutex_unlock(&g_ipLock); return r;
}

static void initTargetHosts(void) {
    g_targetHosts = [NSMutableSet set];
    g_targetIPs   = [NSMutableSet set];
    g_targetIP6   = [NSMutableSet set];
    NSArray *builtin = @[ @".kuwo.cn", @".kuwo.com", @".l.qq.com", @".tencentmusic.com",
                          @"xs.gdt.qq.com", @"tmeadcomm.y.qq.com" ];
    for (NSString *r in builtin) [g_targetHosts addObject:r];
    NSString *path = SandboxPath(@"bodian_mitm_hosts.txt");
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
    if (content.length) {
        for (NSString *line in [content componentsSeparatedByString:@"\n"]) {
            NSString *t = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (t.length && ![t hasPrefix:@"#"]) [g_targetHosts addObject:t];
        }
        DLog(@"[mitm] 已加载自定义 hosts 规则，共 %lu 条", (unsigned long)g_targetHosts.count);
    }
}

// ============================ 证书（自签 CA 签发的服务器身份） ============================
// kSecImportExportPassphrase / kSecImportItemIdentity / kSecImportItemCertChain
// 未在公共头声明，但运行期字符串值即下列三个，直接用 CFSTR 等价物。
#define kImportPassphrase CFSTR("passphrase")
#define kImportIdentity  CFSTR("identity")
#define kImportCertChain CFSTR("certChain")
extern OSStatus SecPKCS12Import(CFDataRef inPKCS12Data, CFDictionaryRef options, CFArrayRef *items);

static CFArrayRef g_serverCerts = NULL;

static void loadIdentity(void) {
    NSString *b64 = [NSString stringWithUTF8String:kBodianP12B64];
    NSData *p12 = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!p12.length) { DLog(@"[cert] P12 内嵌数据为空"); return; }
    CFMutableDictionaryRef opts = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(opts, kImportPassphrase, CFSTR("bodian"));
    CFArrayRef items = NULL;
    OSStatus st = SecPKCS12Import((__bridge CFDataRef)p12, opts, &items);
    CFRelease(opts);
    if (st != noErr || !items || CFArrayGetCount(items) == 0) {
        DLog(@"[cert] SecPKCS12Import 失败 st=%d", (int)st);
        if (items) CFRelease(items);
        return;
    }
    CFDictionaryRef item = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef ident = (SecIdentityRef)CFDictionaryGetValue(item, kImportIdentity);
    if (!ident) { DLog(@"[cert] 导入项中没有 identity"); CFRelease(items); return; }
    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    SecCertificateRef leaf = NULL;
    if (SecIdentityCopyCertificate(ident, &leaf) == noErr && leaf) {
        CFArrayAppendValue(certs, leaf);
        CFRelease(leaf);
    }
    CFArrayRef chain = CFArrayRef(CFDictionaryGetValue(item, kImportCertChain));
    if (chain) {
        for (CFIndex i = 0; i < CFArrayGetCount(chain); i++) {
            SecCertificateRef c = (SecCertificateRef)CFArrayGetValueAtIndex(chain, i);
            if (c && !CFArrayContainsValue(certs, CFRangeMake(0, CFArrayGetCount(certs)), c))
                CFArrayAppendValue(certs, c);
        }
    }
    g_serverCerts = certs;
    CFRelease(items);
    DLog(@"[cert] 身份加载成功，证书链 %ld 张", (long)CFArrayGetCount(certs));
}

// ============================ SecureTransport IO ============================
// 对所有 SSLContext（本地服务端 / 上游客户端）通用：fd 由 SSLConnectionRef 传入
static OSStatus mitmRead(SSLConnectionRef conn, void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    size_t want = *len, got = 0;
    *len = 0;
    while (got < want) {
        ssize_t r = read(fd, (char *)data + got, want - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) { *len = got; return errSSLClosedGraceful; }
        if (errno == EINTR) continue;
        *len = got;
        return errSSLClosedAbort;
    }
    *len = got;
    return noErr;
}

static OSStatus mitmWrite(SSLConnectionRef conn, const void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    size_t want = *len, sent = 0;
    *len = 0;
    while (sent < want) {
        ssize_t r = write(fd, (const char *)data + sent, want - sent);
        if (r > 0) { sent += (size_t)r; continue; }
        if (r == 0) break;
        if (errno == EINTR) continue;
        *len = sent;
        return errSSLClosedAbort;
    }
    *len = sent;
    return noErr;
}

static SSLContextRef makeServerCtx(int fd) {
    SSLContextRef ctx = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
    if (!ctx) return NULL;
    SSLSetIOFuncs(ctx, mitmRead, mitmWrite);
    SSLSetConnection(ctx, (SSLConnectionRef)(intptr_t)fd);
    SSLSetCertificate(ctx, g_serverCerts);
    return ctx;
}

static SSLContextRef makeClientCtx(int fd, NSString *host) {
    SSLContextRef ctx = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    if (!ctx) return NULL;
    SSLSetIOFuncs(ctx, mitmRead, mitmWrite);
    SSLSetConnection(ctx, (SSLConnectionRef)(intptr_t)fd);
    SSLSetPeerDomainName(ctx, host.UTF8String, strlen(host.UTF8String ?: ""));
    return ctx;
}

static void setSockTimeout(int fd, int sec) {
    struct timeval tv; tv.tv_sec = sec; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

// ============================ connect / getaddrinfo hook ============================
static int (*o_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int (*o_connect)(int, const struct sockaddr *, socklen_t);
static int (*o_socket)(int, int, int);

static int g_localPort = 0;
static int g_ipv6Up = 0;
static volatile int g_mitmEnabled = 0;

static int my_getaddrinfo(const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
    int r = o_getaddrinfo(node, service, hints, res);
    if (r == 0 && node && res && *res) {
        NSString *host = [NSString stringWithUTF8String:node];
        if (isTargetHost(host)) {
            int n4 = 0, n6 = 0;
            for (struct addrinfo *ai = *res; ai; ai = ai->ai_next) {
                char ip[64] = {0};
                if (ai->ai_family == AF_INET && ai->ai_addr) {
                    inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof ip);
                    addTargetIP(@(ip)); n4++;
                } else if (ai->ai_family == AF_INET6 && ai->ai_addr) {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, ip, sizeof ip);
                    addTargetIP6(@(ip)); n6++;
                }
            }
            DLog(@"[dns] 目标域名 %s -> IPv4x%d IPv6x%d（已登记，connect 时重定向）", node, n4, n6);
        }
    }
    return r;
}

static int my_connect(int fd, const struct sockaddr *addr, socklen_t al) {
    if (g_mitmEnabled && g_localPort && addr && al >= sizeof(struct sockaddr_in)) {
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
            int port = ntohs(s->sin_port);
            if (port == 443 && isTargetIP(s->sin_addr)) {
                struct sockaddr_in lo;
                memcpy(&lo, s, sizeof lo);
                lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                lo.sin_port = htons((uint16_t)g_localPort);
                int r = o_connect(fd, (const struct sockaddr *)&lo, sizeof lo);
                char ip[64] = {0};
                inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
                DLog(@"[mitm] 重定向 %s:443 -> 127.0.0.1:%d (fd=%d ret=%d)", ip, g_localPort, fd, r);
                return r;
            }
        } else if (addr->sa_family == AF_INET6 && g_ipv6Up &&
                   al >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)addr;
            int port = ntohs(s6->sin6_port);
            if (port == 443 && isTargetIP6(s6->sin6_addr)) {
                struct sockaddr_in6 lo;
                memcpy(&lo, s6, sizeof lo);
                lo.sin6_addr = in6addr_loopback;
                lo.sin6_port = htons((uint16_t)g_localPort);
                int r = o_connect(fd, (const struct sockaddr *)&lo, sizeof lo);
                DLog(@"[mitm] 重定向 [IPv6]:443 -> ::1:%d (fd=%d ret=%d)", g_localPort, fd, r);
                return r;
            }
        }
    }
    return o_connect(fd, addr, al);
}

static void installHooks(void) {
    o_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))
                    dlsym(RTLD_DEFAULT, "getaddrinfo");
    o_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
    o_socket  = (int (*)(int, int, int))dlsym(RTLD_DEFAULT, "socket");
    struct fbt_rebinding rb[4];
    size_t n = 0;
    if (o_getaddrinfo) { rb[n].name = "getaddrinfo"; rb[n].replacement = (void *)my_getaddrinfo; rb[n].replaced = (void **)&o_getaddrinfo; n++; }
    if (o_connect)     { rb[n].name = "connect";     rb[n].replacement = (void *)my_connect;     rb[n].replaced = (void **)&o_connect;     n++; }
    int ret = n ? fbt_rebind(rb, n) : -2;
    DLog(@"[rebind] fishhook ret=%d\n%s", ret, g_rb_log[0] ? g_rb_log : "");
}

// ============================ HTTP 工具 ============================
static int tlsReadUntil(SSLContextRef ctx, NSMutableData *buf, const char *term, int termLen, size_t maxBytes) {
    char tmp[8192];
    for (;;) {
        size_t got = 0;
        OSStatus s = SSLRead(ctx, tmp, sizeof tmp, &got);
        if (s == noErr && got > 0) {
            [buf appendBytes:tmp length:got];
            if (buf.length >= (size_t)termLen &&
                fb_memmem(buf.bytes, buf.length, term, (size_t)termLen)) return 0;
            if (buf.length > maxBytes) return -1;
            continue;
        }
        return -1;   // 关闭 / 错误 / 0 字节
    }
}

static int tlsReadBytes(SSLContextRef ctx, NSMutableData *buf, size_t n) {
    char tmp[8192];
    size_t remaining = n;
    while (remaining > 0) {
        size_t got = 0;
        OSStatus s = SSLRead(ctx, tmp, remaining > sizeof tmp ? sizeof tmp : remaining, &got);
        if (s != noErr || got == 0) return -1;
        [buf appendBytes:tmp length:got];
        remaining -= got;
    }
    return 0;
}

static NSDictionary *parseReq(NSData *head) {
    NSString *s = [[NSString alloc] initWithData:head encoding:NSASCIIStringEncoding];
    if (!s.length) return nil;
    NSArray *lines = [s componentsSeparatedByString:@"\r\n"];
    if (!lines.count) return nil;
    NSArray *parts = [lines[0] componentsSeparatedByString:@" "];
    if (parts.count < 3) return nil;
    NSString *method = parts[0], *path = parts[1], *host = nil;
    long cl = 0;
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *ln = lines[i];
        if ([ln hasPrefix:@"Host:"] || [ln hasPrefix:@"host:"])
            host = [[ln substringFromIndex:5] stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceCharacterSet]];
        if ([ln hasPrefix:@"Content-Length:"] || [ln hasPrefix:@"content-length:"])
            cl = [[[ln substringFromIndex:15] stringByTrimmingCharactersInSet:
                   [NSCharacterSet whitespaceCharacterSet]] longLongValue];
    }
    return @{ @"method": method, @"path": path,
              @"host": host ?: @"", @"cl": @(cl) };
}

// 去掉 Accept-Encoding / Connection，加 Connection: close（上游回完就关，读"到关为止"即可）
static NSData *buildUpstreamRequest(NSData *head, NSData *body) {
    NSString *s = [[NSString alloc] initWithData:head encoding:NSASCIIStringEncoding];
    NSMutableString *out = [NSMutableString string];
    for (NSString *ln in [s componentsSeparatedByString:@"\r\n"]) {
        if (!ln.length) continue;
        NSString *l = ln.lowercaseString;
        if ([l hasPrefix:@"accept-encoding:"] || [l hasPrefix:@"connection:"] ||
            [l hasPrefix:@"proxy-connection:"]) continue;
        [out appendFormat:@"%@\r\n", ln];
    }
    [out appendString:@"Connection: close\r\n\r\n"];
    NSMutableData *d = [[out dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    if (body.length) [d appendData:body];
    return d;
}

static NSData *errorResponse(NSString *status, NSString *msg) {
    NSString *b = msg ?: @"mitm error";
    NSString *h = [NSString stringWithFormat:
        @"HTTP/1.1 %@\r\nContent-Type: text/plain\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        status, (unsigned long)b.length];
    NSMutableData *d = [[h dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [d appendData:[b dataUsingEncoding:NSUTF8StringEncoding]];
    return d;
}

// ============================ 上游转发（核心） ============================
// 返回：上游完整响应（原样字节）。空 = 失败。
static NSData *forwardRequest(NSString *host, NSData *reqHead, NSData *reqBody) {
    struct addrinfo hints; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int r = o_getaddrinfo(host.UTF8String, "443", &hints, &res);
    if (r != 0 || !res) { DLog(@"[up] DNS 失败 %@", host); return nil; }

    int ufd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        ufd = o_socket(ai->ai_family, ai->ai_socktype ?: SOCK_STREAM, ai->ai_protocol);
        if (ufd < 0) continue;
        if (o_connect(ufd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(ufd); ufd = -1;
    }
    freeaddrinfo(res);
    if (ufd < 0) { DLog(@"[up] connect 失败 %@", host); return nil; }
    setSockTimeout(ufd, 30);

    SSLContextRef c = makeClientCtx(ufd, host);
    if (!c) { close(ufd); return nil; }
    OSStatus hs = SSLHandshake(c);
    if (hs != noErr) {
        DLog(@"[up] 上游 TLS 握手失败 %@ st=%d（若 -9800/-9807 = 证书校验问题）", host, (int)hs);
        SSLClose(c); CFRelease(c); close(ufd);
        return nil;
    }

    NSData *outReq = buildUpstreamRequest(reqHead, reqBody);
    size_t w = 0;
    OSStatus sw = SSLWrite(c, outReq.bytes, outReq.length, &w);
    if (sw != noErr) {
        DLog(@"[up] 请求发送失败 st=%d", (int)sw);
        SSLClose(c); CFRelease(c); close(ufd);
        return nil;
    }

    NSMutableData *resp = [NSMutableData data];
    char buf[16384];
    for (;;) {
        size_t got = 0;
        OSStatus s = SSLRead(c, buf, sizeof buf, &got);
        if (s == noErr && got > 0) { [resp appendBytes:buf length:got]; continue; }
        break;   // errSSLClosedGraceful / 其它错误 / 0 字节 => 到头了
    }
    SSLClose(c); CFRelease(c); close(ufd);

    // ======== STAGE 2 接入点：在这里把 resp 的明文喂给 bdyy.js 改写 ========
    return resp;
}

// ============================ 本地 TLS 服务器 ============================
static void *worker(void *arg) {
    int cfd = (int)(intptr_t)arg;
    setSockTimeout(cfd, 30);

    SSLContextRef ctx = makeServerCtx(cfd);
    if (!ctx) { close(cfd); return NULL; }
    OSStatus hs = SSLHandshake(ctx);
    if (hs != noErr) {
        DLog(@"[mitm] 客户端 TLS 握手失败 fd=%d st=%d", cfd, (int)hs);
        SSLClose(ctx); CFRelease(ctx); close(cfd);
        return NULL;
    }
    DLog(@"[mitm] ★ 客户端 TLS 握手成功 fd=%d", cfd);

    int served = 0;
    for (;;) {
        NSMutableData *head = [NSMutableData data];
        if (tlsReadUntil(ctx, head, "\r\n\r\n", 4, 64 * 1024) != 0) break;
        NSDictionary *req = parseReq(head);
        if (!req) break;
        NSString *method = req[@"method"], *path = req[@"path"], *host = req[@"host"];
        long cl = [req[@"cl"] longValue];
        DLog(@"[mitm] >> %@ http://%@%@ (body=%ld)", method, host, path, cl);
        if (!host.length) { DLog(@"[mitm] 无 Host 头，断开"); break; }

        NSMutableData *body = [NSMutableData data];
        if (cl > 0 && cl < 64 * 1024 * 1024 &&
            tlsReadBytes(ctx, body, (size_t)cl) != 0) { DLog(@"[mitm] 请求体读取失败"); break; }

        NSData *resp = forwardRequest(host, head, body);
        if (!resp.length) { DLog(@"[mitm] 上游无响应，断开"); break; }
        size_t w = 0;
        SSLWrite(ctx, resp.bytes, resp.length, &w);
        DLog(@"[mitm] << %@ %@ -> %lu 字节", method, path, (unsigned long)resp.length);
        Dump([NSString stringWithFormat:@"%@ http://%@%@", method, host, path], resp);
        served++;
        if (served > 100) break;
    }
    if (served) DLog(@"[mitm] 连接结束 fd=%d 共转发 %d 个请求", cfd, served);
    SSLClose(ctx); CFRelease(ctx); close(cfd);
    return NULL;
}

static void *acceptLoop(void *arg) {
    int lfd = (int)(intptr_t)arg;
    for (;;) {
        struct sockaddr_storage sa; socklen_t sl = sizeof sa;
        int cfd = accept(lfd, (struct sockaddr *)&sa, &sl);
        if (cfd < 0) { if (errno == EINTR) continue; break; }
        pthread_t t; pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &a, worker, (void *)(intptr_t)cfd) != 0) close(cfd);
        pthread_attr_destroy(&a);
    }
    return NULL;
}

static int makeListener(int family, const struct sockaddr *addr, socklen_t addrlen) {
    int fd = o_socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, addr, addrlen) < 0) { close(fd); return -1; }
    if (listen(fd, 128) < 0) { close(fd); return -1; }
    return fd;
}

static void startServer(void) {
    struct sockaddr_in sin; memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    int v4 = makeListener(AF_INET, (struct sockaddr *)&sin, sizeof sin);
    if (v4 < 0) { DLog(@"[mitm] IPv4 监听创建失败"); return; }
    struct sockaddr_in b; socklen_t bl = sizeof b;
    getsockname(v4, (struct sockaddr *)&b, &bl);
    g_localPort = ntohs(b.sin_port);

    int v6 = -1;
    struct sockaddr_in6 sin6; memset(&sin6, 0, sizeof sin6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_loopback;
    sin6.sin6_port = htons((uint16_t)g_localPort);
    v6 = makeListener(AF_INET6, (struct sockaddr *)&sin6, sizeof sin6);
    g_ipv6Up = (v6 >= 0);

    pthread_t t; pthread_attr_t a;
    pthread_attr_init(&a); pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &a, acceptLoop, (void *)(intptr_t)v4);
    if (v6 >= 0) { pthread_t t2; pthread_create(&t2, &a, acceptLoop, (void *)(intptr_t)v6); }
    pthread_attr_destroy(&a);
    DLog(@"[mitm] 监听 127.0.0.1:%d（IPv6=%@）", g_localPort, g_ipv6Up ? @"yes" : @"no");
}

// ============================ 入口 ============================
__attribute__((constructor)) static void bodian_mitm_init(void) {
    DLog(@"========== bodian_probe v3 (进程内 MITM) 已加载 ==========");
    if ([[NSFileManager defaultManager] fileExistsAtPath:SandboxPath(@"bodian_mitm_off")]) {
        DLog(@"[mitm] 检测到 bodian_mitm_off，本不启用（App 行为不变）");
        return;
    }
    initTargetHosts();
    loadIdentity();
    if (!g_serverCerts) { DLog(@"[cert] 无证书可用，MITM 不启用"); return; }
    installHooks();          // 先装 hook（o_socket 等先就位），此时 g_mitmEnabled=0，connect 仍直连
    startServer();
    if (!g_localPort) { DLog(@"[mitm] 服务未启动"); return; }
    g_mitmEnabled = 1;       // 服务就绪后再放行重定向
    DLog(@"========== MITM 就绪：目标 443 将被重定向到 127.0.0.1:%d ==========", g_localPort);
}
