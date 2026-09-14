//
//  bodian_probe.m  (v1)
//  波点音乐（Flutter 套壳）—— 拦截层探测 dylib
//
//  只做诊断，不修改任何数据，稳定性风险极低。
//  它回答三个问题：
//
//   Q1  目标域名(kuwo / qq) 的 API 请求，是否经过 NSURLSession？
//       -> 经过：在 NSURLSession 层 hook 即可拿到明文，好做
//   Q2  是否只有原始 socket 直连（Dart/Flutter 自带网络栈）？
//       -> 是：socket 层只有密文，必须去 hook Flutter 引擎内的 BoringSSL
//   Q3  Flutter 引擎里能不能找到 SSL_read / SSL_write 符号？
//       -> 找到：硬路还有戏；找不到：基本只能退回代理方案
//
//  日志文件：
//    Documents/bodian_probe.log  —— 诊断结论
//    Documents/bodian_resp.log   —— 抓到的目标响应原文（用于后续对齐字段）
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

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

static void DLog(NSString *fmt, ...);
static void Dump(NSString *name, NSData *data);

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
static NSString *ProbeLogPath(void) { return SandboxPath(@"bodian_probe.log"); }
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
    NSLog(@"[bodian_probe] %@", m);
    appendFile(ProbeLogPath(), [NSString stringWithFormat:@"%@  %@\n", [NSDate date], m]);
}

static void Dump(NSString *name, NSData *data) {
    if (!data.length) return;
    NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!t) t = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    if (!t) return;
    appendFile(RespLogPath(), [NSString stringWithFormat:
        @"\n===== %@  (%lu bytes) =====\n%@\n", name, (unsigned long)data.length, t]);
}

// ============================ 目标域名判定 ============================
static const char *kHostKeys[] = {
    "kuwo.cn", "kuwo.com", "bodian", "l.qq.com", "gdt.qq.com", "tencentmusic.com"
};
static BOOL hostMatched(NSString *host) {
    if (!host.length) return NO;
    NSString *h = host.lowercaseString;
    for (size_t i = 0; i < sizeof(kHostKeys) / sizeof(kHostKeys[0]); i++) {
        NSString *k = [NSString stringWithUTF8String:kHostKeys[i]];
        if ([h containsString:k]) return YES;
    }
    return NO;
}
static BOOL cstrMatched(const char *s) {
    if (!s) return NO;
    for (size_t i = 0; i < sizeof(kHostKeys) / sizeof(kHostKeys[0]); i++)
        if (strstr(s, kHostKeys[i])) return YES;
    return NO;
}

// ============================ 符号探测 ============================
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableString *g_symReport;

static BOOL nameIsSSL(const char *n) {
    return strcmp(n, "SSL_read") == 0 || strcmp(n, "SSL_write") == 0 ||
           strcmp(n, "SSL_read_ex") == 0 || strcmp(n, "SSL_write_ex") == 0 ||
           strcmp(n, "SSL_CTX_new") == 0 || strcmp(n, "SSL_get_fd") == 0 ||
           strcmp(n, "SSL_new") == 0;
}

static BOOL pathIsInteresting(const char *p, int idx) {
    if (idx == 0) return YES;                       // 主可执行文件（Flutter 引擎多半静态在这里）
    if (!p) return NO;
    NSString *s = [[NSString stringWithUTF8String:p] lowercaseString];
    return [s containsString:@"flutter"] || [s containsString:@"app.framework"] ||
           [s containsString:@"runner"];
}

static void scan_image_for_ssl(const struct mach_header *h, intptr_t slide, int idx) {
    Dl_info info; if (dladdr(h, &info) == 0) return;
    const char *img = info.dli_fname ? info.dli_fname : "?";
    BOOL interesting = pathIsInteresting(img, idx);

    fbt_segment_command *cur = NULL, *linkedit = NULL;
    struct symtab_command *symcmd = NULL;
    uintptr_t p = (uintptr_t)h + sizeof(fbt_mach_header);
    for (uint32_t i = 0; i < h->ncmds; i++, p += cur->cmdsize) {
        cur = (fbt_segment_command *)p;
        if (cur->cmd == FBT_LC_SEG) { if (strcmp(cur->segname, SEG_LINKEDIT) == 0) linkedit = cur; }
        else if (cur->cmd == LC_SYMTAB) symcmd = (struct symtab_command *)cur;
    }
    if (!symcmd) { if (interesting) DLog(@"[sym] %s : 无 LC_SYMTAB", img); return; }
    if (!linkedit) return;

    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    fbt_nlist *symtab = (fbt_nlist *)(base + symcmd->symoff);
    char *strtab = (char *)(base + symcmd->stroff);

    int found = 0;
    for (uint32_t i = 0; i < symcmd->nsyms; i++) {
        uint32_t off = symtab[i].n_un.n_strx;
        if (!off) continue;
        const char *name = strtab + off;
        const char *n = (name[0] == '_') ? name + 1 : name;
        if (nameIsSSL(n)) {
            uintptr_t addr = (uintptr_t)slide + (uintptr_t)symtab[i].n_value;
            if (g_symReport) {
                [g_symReport appendFormat:@"    %s  @ 0x%lx  (%s)\n", n, (unsigned long)addr, img];
            }
            found++;
        }
    }
    if (interesting || found)
        DLog(@"[sym] %s : nsyms=%u SSL命中=%d", img, symcmd->nsyms, found);
}

static void scan_all_images(void) {
    if (!g_symReport) g_symReport = [NSMutableString string];
    uint32_t n = _dyld_image_count();
    DLog(@"[sym] 共 %u 个已加载镜像，开始扫描符号表…", n);
    for (uint32_t i = 0; i < n; i++)
        scan_image_for_ssl(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), (int)i);
    DLog(@"[sym] ==== SSL 符号扫描结果 ====\n%@    (空 = 符号被 strip，只能靠特征码/内联 hook)",
         g_symReport.length ? g_symReport : @"");
}

static void check_dlsym(void) {
    const char *names[] = { "SSL_read", "SSL_write", "SSL_CTX_new", "SSL_new", "SSL_get_fd" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        void *p = dlsym(RTLD_DEFAULT, names[i]);
        if (p) {
            Dl_info di;
            const char *img = (dladdr(p, &di) != 0 && di.dli_fname) ? di.dli_fname : "?";
            DLog(@"[dlsym] %s 已导出 -> %p  (%s)", names[i], p, img);
        } else {
            DLog(@"[dlsym] %s 未导出", names[i]);
        }
    }
}

// ============================ getaddrinfo / connect 探测 ============================
#define MAX_IPS 128
static char g_ips[MAX_IPS][46];
static int  g_ipCount = 0;

static int  (*o_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int  (*o_connect)(int, const struct sockaddr *, socklen_t);

static BOOL knownIP(const char *ip) {
    if (!ip) return NO;
    pthread_mutex_lock(&g_lock);
    BOOL hit = NO;
    for (int i = 0; i < g_ipCount; i++) if (strcmp(g_ips[i], ip) == 0) { hit = YES; break; }
    pthread_mutex_unlock(&g_lock);
    return hit;
}
static void rememberIP(const char *ip) {
    if (!ip) return;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_ipCount; i++) if (strcmp(g_ips[i], ip) == 0) { pthread_mutex_unlock(&g_lock); return; }
    if (g_ipCount < MAX_IPS) { snprintf(g_ips[g_ipCount], sizeof(g_ips[0]), "%s", ip); g_ipCount++; }
    pthread_mutex_unlock(&g_lock);
}

static int my_getaddrinfo(const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
    int r = o_getaddrinfo(node, service, hints, res);
    if (r == 0 && res && *res && cstrMatched(node)) {
        NSMutableString *sb = [NSMutableString string];
        for (struct addrinfo *ai = *res; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                char ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof(ip));
                rememberIP(ip);
                [sb appendFormat:@"%@ ", [NSString stringWithUTF8String:ip]];
            }
        }
        DLog(@"[dns] ★ 解析目标域名 %s -> %@", node ? node : "?", sb);
    }
    return r;
}

static int g_connLog = 0;
static int my_connect(int fd, const struct sockaddr *addr, socklen_t al) {
    int r = o_connect(fd, addr, al);
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
        int port = ntohs(s->sin_port);
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        if (knownIP(ip)) {
            DLog(@"[socket] ★ 直连目标 IP fd=%d %s:%d (ret=%d)", fd, ip, port, r);
        } else if (port == 443 && ++g_connLog <= 30) {
            DLog(@"[socket] connect(样本) %s:443", ip);
        }
    }
    return r;
}

// ============================ NSURLSession 探测 ============================
static int g_urlCount = 0;

static void noteURL(NSURL *u, const char *via) {
    if (!u) return;
    BOOL hit = hostMatched(u.host);
    pthread_mutex_lock(&g_lock);
    int n = ++g_urlCount;
    pthread_mutex_unlock(&g_lock);
    if (hit) DLog(@"[NSURLSession/%s] ★ 命中 %@", via, u.absoluteString);
    else if (n <= 60) DLog(@"[NSURLSession/%s] %@", via, u.absoluteString);
}

static id (*o_dt_req)(id, SEL, NSURLRequest *);
static id my_dt_req(id self, SEL _cmd, NSURLRequest *req) {
    noteURL(req.URL, "task");
    return o_dt_req(self, _cmd, req);
}

typedef void (^ProbeCompletion)(NSData *, NSURLResponse *, NSError *);
static id (*o_dt_req_c)(id, SEL, NSURLRequest *, ProbeCompletion);
static id my_dt_req_c(id self, SEL _cmd, NSURLRequest *req, ProbeCompletion completion) {
    NSURL *u = req.URL;
    noteURL(u, "completion");
    if (!completion || !hostMatched(u.host)) {
        return o_dt_req_c(self, _cmd, req, completion);
    }
    return o_dt_req_c(self, _cmd, req, ^(NSData *d, NSURLResponse *resp, NSError *err) {
        DLog(@"[NSURLSession/completion] ★ 响应 %@ status=%ld len=%lu err=%@",
             ((NSHTTPURLResponse *)resp).URL.absoluteString ?: u.absoluteString,
             (long)((NSHTTPURLResponse *)resp).statusCode, (unsigned long)d.length, err);
        Dump([NSString stringWithFormat:@"NSURLSession %@", u.absoluteString], d);
        completion(d, resp, err);
    });
}

static id (*o_dt_url_c)(id, SEL, NSURL *, ProbeCompletion);
static id my_dt_url_c(id self, SEL _cmd, NSURL *u, ProbeCompletion completion) {
    noteURL(u, "completion");
    if (!completion || !hostMatched(u.host)) {
        return o_dt_url_c(self, _cmd, u, completion);
    }
    return o_dt_url_c(self, _cmd, u, ^(NSData *d, NSURLResponse *resp, NSError *err) {
        Dump([NSString stringWithFormat:@"NSURLSession %@", u.absoluteString], d);
        completion(d, resp, err);
    });
}

static id (*o_session)(id, SEL, id, id, id);
static id my_session(id self, SEL _cmd, id config, id delegate, id queue) {
    const char *dn = delegate ? object_getClassName(delegate) : "(nil)";
    NSArray *pc = nil;
    @try { pc = [config valueForKey:@"protocolClasses"]; } @catch (__unused NSException *e) {}
    DLog(@"[NSURLSession] sessionWithConfiguration: delegate=%s protocolClasses=%@", dn, pc);
    return o_session(self, _cmd, config, delegate, queue);
}

// ============================ 入口 ============================
__attribute__((constructor)) static void bodian_probe_init(void) {
    DLog(@"========== bodian_probe v1 已加载 ==========");
    DLog(@"环境: Flutter=%s  WKWebView=%s",
         (NSClassFromString(@"FlutterViewController") || NSClassFromString(@"FlutterEngine")) ? "yes" : "no",
         objc_getClass("WKWebView") ? "yes" : "no");

    scan_all_images();
    check_dlsym();

    o_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))
                    dlsym(RTLD_DEFAULT, "getaddrinfo");
    o_connect     = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
    struct fbt_rebinding rb[] = {
        { "getaddrinfo", (void *)my_getaddrinfo, (void **)&o_getaddrinfo },
        { "connect",     (void *)my_connect,     (void **)&o_connect     },
    };
    int ret = fbt_rebind(rb, sizeof(rb) / sizeof(rb[0]));
    DLog(@"[rebind] fishhook ret=%d", ret);

    Class ns = objc_getClass("NSURLSession");
    if (ns) {
        Method m;
        m = class_getInstanceMethod(ns, @selector(dataTaskWithRequest:));
        if (m) { o_dt_req = (id(*)(id,SEL,NSURLRequest*))method_getImplementation(m);
                 method_setImplementation(m, (IMP)my_dt_req); }
        m = class_getInstanceMethod(ns, @selector(dataTaskWithRequest:completionHandler:));
        if (m) { o_dt_req_c = (id(*)(id,SEL,NSURLRequest*,ProbeCompletion))method_getImplementation(m);
                 method_setImplementation(m, (IMP)my_dt_req_c); }
        m = class_getInstanceMethod(ns, @selector(dataTaskWithURL:completionHandler:));
        if (m) { o_dt_url_c = (id(*)(id,SEL,NSURL*,ProbeCompletion))method_getImplementation(m);
                 method_setImplementation(m, (IMP)my_dt_url_c); }
        m = class_getClassMethod(ns, @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (m) { o_session = (id(*)(id,SEL,id,id,id))method_getImplementation(m);
                 method_setImplementation(m, (IMP)my_session); }
    } else {
        DLog(@"[NSURLSession] 类不存在（不太可能）");
    }

    DLog(@"========== 探测已就绪，请打开 App 并进入会员页/播放页，停留 10 秒 ==========");
}
