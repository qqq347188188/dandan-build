//
//  bodian_probe.m  (v2)
//  波点音乐（Flutter 套壳）—— 拦截层探测 dylib
//
//  只做诊断，不修改任何数据（SSL hook 只是"读一份"明文，不做改写），稳定性风险低。
//
//  v2 相对 v1 新增（关键）：
//    1. fishhook 重绑系统 /usr/lib/libboringssl.dylib 的 SSL_read / SSL_write / *_ex；
//       —— 如果 Dart 是「动态链接系统 BoringSSL」，这里就能直接抓到 bd-api.kuwo.cn 的明文
//       —— 如果抓不到，说明 Flutter 自带静态 BoringSSL（符号已 strip），dylib 方案基本无解
//    2. 记录 fishhook 到底把哪个镜像的 SSL_read 槽位改掉了（判断谁在动态链接它）
//    3. 新增 socket() hook，判断是不是 QUIC(UDP/443)，排除 HTTP/3 干扰
//    4. 对命中的 TLS 连接，把完整响应体攒齐后 dump（后续对齐字段要用）
//
//  日志：
//    Documents/bodian_probe.log —— 诊断结论
//    Documents/bodian_resp.log  —— 抓到的目标响应原文（NSURLSession 与 SSL 明文）
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

// ============================ 小工具 ============================
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
static BOOL bytesMatched(const unsigned char *b, size_t len) {
    if (!b || len < 5) return NO;
    static const char *keys[] = { "kuwo", "bd-api", "gdt.qq", "l.qq.com", "tencentmusic", "bodian" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        size_t kl = strlen(keys[i]);
        if (fb_memmem(b, len, keys[i], kl)) return YES;
    }
    return NO;
}

// ============================ 符号探测 ============================
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableString *g_symReport;

static BOOL nameIsSSL(const char *n) {
    return strcmp(n, "SSL_read") == 0 || strcmp(n, "SSL_write") == 0 ||
           strcmp(n, "SSL_read_ex") == 0 || strcmp(n, "SSL_write_ex") == 0 ||
           strcmp(n, "SSL_CTX_new") == 0 || strcmp(n, "SSL_new") == 0;
}

static BOOL pathIsInteresting(const char *p, int idx) {
    if (idx == 0) return YES;
    if (!p) return NO;
    NSString *s = [[NSString stringWithUTF8String:p] lowercaseString];
    return [s containsString:@"flutter"] || [s containsString:@"app.framework"] ||
           [s containsString:@"boringssl"];
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
    if (!symcmd || !linkedit) return;

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
            if (g_symReport) [g_symReport appendFormat:@"    %s  @ 0x%lx  (%s)\n", n, (unsigned long)addr, img];
            found++;
        }
    }
    if (found) DLog(@"[sym] %s : nsyms=%u SSL命中=%d", img, symcmd->nsyms, found);
    else if (interesting) DLog(@"[sym] %s : nsyms=%u SSL命中=0", img, symcmd->nsyms);
}

static void scan_all_images(void) {
    if (!g_symReport) g_symReport = [NSMutableString string];
    uint32_t n = _dyld_image_count();
    DLog(@"[sym] 共 %u 个已加载镜像，扫描符号表…", n);
    for (uint32_t i = 0; i < n; i++)
        scan_image_for_ssl(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), (int)i);
    DLog(@"[sym] ==== SSL 符号扫描结果 ====\n%@    (空 = 符号被 strip)",
         g_symReport.length ? g_symReport : @"");
}

static void check_dlsym(void) {
    const char *names[] = { "SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex", "SSL_CTX_new" };
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

// ============================ getaddrinfo / socket / connect ============================
#define MAX_IPS 128
static char g_ips[MAX_IPS][46];
static int  g_ipCount = 0;

static int  (*o_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int  (*o_connect)(int, const struct sockaddr *, socklen_t);
static int  (*o_socket)(int, int, int);
static unsigned char g_sockType[4096];
static int g_sockLog = 0;

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

static int my_socket(int domain, int type, int proto) {
    int fd = o_socket(domain, type, proto);
    if (fd >= 0 && fd < 4096) g_sockType[fd] = (unsigned char)(type & 0x0f);
    return fd;
}

static int my_connect(int fd, const struct sockaddr *addr, socklen_t al) {
    int r = o_connect(fd, addr, al);
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
        int port = ntohs(s->sin_port);
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        const char *kind = "?";
        if (fd >= 0 && fd < 4096) {
            int t = g_sockType[fd] & 0x0f;
            if (t == SOCK_STREAM) kind = "TCP";
            else if (t == SOCK_DGRAM) kind = "UDP";
        }
        if (knownIP(ip)) {
            DLog(@"[socket] ★ 直连目标 IP fd=%d %s %s:%d (ret=%d)", fd, kind, ip, port, r);
        } else if (port == 443 && ++g_sockLog <= 20) {
            DLog(@"[socket] connect(样本) %s %s:443", kind, ip);
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
    else if (n <= 30) DLog(@"[NSURLSession/%s] %@", via, u.absoluteString);
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
    if (!completion || !hostMatched(u.host)) return o_dt_req_c(self, _cmd, req, completion);
    return o_dt_req_c(self, _cmd, req, ^(NSData *d, NSURLResponse *resp, NSError *err) {
        DLog(@"[NSURLSession/completion] ★ 响应 %@ status=%ld len=%lu",
             u.absoluteString, (long)((NSHTTPURLResponse *)resp).statusCode, (unsigned long)d.length);
        Dump([NSString stringWithFormat:@"NSURLSession %@", u.absoluteString], d);
        completion(d, resp, err);
    });
}

static id (*o_dt_url_c)(id, SEL, NSURL *, ProbeCompletion);
static id my_dt_url_c(id self, SEL _cmd, NSURL *u, ProbeCompletion completion) {
    noteURL(u, "completion");
    if (!completion || !hostMatched(u.host)) return o_dt_url_c(self, _cmd, u, completion);
    return o_dt_url_c(self, _cmd, u, ^(NSData *d, NSURLResponse *resp, NSError *err) {
        Dump([NSString stringWithFormat:@"NSURLSession %@", u.absoluteString], d);
        completion(d, resp, err);
    });
}

static id (*o_session)(id, SEL, id, id, id);
static id my_session(id self, SEL _cmd, id config, id delegate, id queue) {
    const char *dn = delegate ? object_getClassName(delegate) : "(nil)";
    DLog(@"[NSURLSession] sessionWithConfiguration: delegate=%s", dn);
    return o_session(self, _cmd, config, delegate, queue);
}

// ============================ SSL 明文探测（v2 核心） ============================
// 关注的 TLS 连接：只存指针，判断"这个 SSL 上出现过目标域名"
#define TLS_MAX 256
static const void *g_tlsSsl[TLS_MAX];
static volatile int g_tlsHot[TLS_MAX];

static int tlsSlot(const void *ssl) {
    uintptr_t v = (uintptr_t)ssl >> 4;
    return (int)((v ^ (v >> 9) ^ (v >> 17)) & (TLS_MAX - 1));
}
static void tlsMark(const void *ssl) {
    int i = tlsSlot(ssl);
    g_tlsSsl[i] = ssl;
    g_tlsHot[i] = 1;
}
static BOOL tlsIsHot(const void *ssl) {
    int i = tlsSlot(ssl);
    return (g_tlsSsl[i] == ssl) && g_tlsHot[i];
}

// 每连接的响应攒包（用于输出完整响应体）
#define TLS_ACC 24
typedef struct { const void *ssl; NSMutableData *acc; } TlsAcc;
static TlsAcc g_acc[TLS_ACC];
static pthread_mutex_t g_tlsLock = PTHREAD_MUTEX_INITIALIZER;
static size_t g_dumpTotal = 0;
#define DUMP_LIMIT (3u * 1024u * 1024u)

static int g_sslWriteCalls = 0, g_sslReadCalls = 0, g_sslHotHits = 0;

static BOOL looksLikeHTTPReq(const unsigned char *b, size_t len) {
    static const char *ms[] = { "GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC" };
    if (len < 5) return NO;
    for (size_t i = 0; i < sizeof(ms) / sizeof(ms[0]); i++)
        if (memcmp(b, ms[i], 4) == 0) return YES;
    return NO;
}

// 解析 "\r\nHost: xxx\r\n"
static NSString *extractHost(const unsigned char *b, size_t len) {
    const unsigned char *h = (const unsigned char *)fb_memmem(b, len, "\r\nHost: ", 8);
    size_t hs = 0;
    if (h) hs = (size_t)(h - b) + 8;
    else {
        h = (const unsigned char *)fb_memmem(b, len, "\r\nhost: ", 8);
        if (!h) return nil;
        hs = (size_t)(h - b) + 8;
    }
    size_t he = hs;
    while (he < len && b[he] != '\r' && b[he] != '\n') he++;
    if (he <= hs) return nil;
    return [[NSString alloc] initWithBytes:(b + hs) length:(he - hs) encoding:NSUTF8StringEncoding];
}

static void tlsAccum(const void *ssl, const void *buf, size_t len) {
    if (g_dumpTotal > DUMP_LIMIT) return;
    pthread_mutex_lock(&g_tlsLock);
    TlsAcc *e = NULL;
    for (int i = 0; i < TLS_ACC; i++) if (g_acc[i].ssl == ssl) { e = &g_acc[i]; break; }
    if (!e) {
        for (int i = 0; i < TLS_ACC; i++) if (!g_acc[i].ssl) {
            g_acc[i].ssl = ssl;
            g_acc[i].acc = [NSMutableData data];
            e = &g_acc[i];
            break;
        }
    }
    if (!e) { pthread_mutex_unlock(&g_tlsLock); return; }

    [e->acc appendBytes:buf length:len];
    if (e->acc.length > 512 * 1024) [e->acc setLength:0];   // 异常大的包，丢弃重来

    const unsigned char *b = (const unsigned char *)e->acc.bytes;
    size_t n = e->acc.length;
    const unsigned char *sep = (const unsigned char *)fb_memmem(b, n, "\r\n\r\n", 4);
    if (!sep) { pthread_mutex_unlock(&g_tlsLock); return; }
    size_t hdrEnd = (size_t)(sep - b) + 4;
    long cl = parse_content_length(b, hdrEnd);
    if (cl < 0) {
        // chunked / 无 Content-Length：攒到一定量就原样输出（尽力而为）
        if (n < 65536) { pthread_mutex_unlock(&g_tlsLock); return; }
        cl = (long)(n - hdrEnd);
    }
    if (n < hdrEnd + (size_t)cl) { pthread_mutex_unlock(&g_tlsLock); return; }

    NSData *whole = [NSData dataWithBytes:b length:hdrEnd + (size_t)cl];
    [e->acc setLength:0];
    g_dumpTotal += whole.length;
    pthread_mutex_unlock(&g_tlsLock);

    Dump([NSString stringWithFormat:@"SSL 响应 (SSL=%p)", ssl], whole);
}

// ---------------- hook: SSL_write（明文请求） ----------------
static int (*o_SSL_write)(void *, const void *, int);
static int my_SSL_write(void *ssl, const void *buf, int num) {
    int r = o_SSL_write(ssl, buf, num);
    if (r <= 0) return r;
    if (g_sslWriteCalls++ == 0)
        DLog(@"[ssl] ★★ my_SSL_write 首次被调用（说明有代码动态链接系统 BoringSSL）");

    size_t len = (size_t)r;
    if (len < 16 || len > 256 * 1024) return r;
    const unsigned char *b = (const unsigned char *)buf;

    if (looksLikeHTTPReq(b, len)) {
        NSString *host = extractHost(b, len);
        size_t pe = 0;
        while (pe < len && b[pe] != ' ' && b[pe] != '\r') pe++;
        NSString *line = [[NSString alloc] initWithBytes:b length:(pe < 160 ? pe : 160)
                                                encoding:NSUTF8StringEncoding];
        DLog(@"[ssl] HTTP请求 host=%@ | %@", host ?: @"(?)", line ?: @"?");
        if (hostMatched(host)) {
            tlsMark(ssl);
            g_sslHotHits++;
            DLog(@"[ssl] ★★★ 命中目标 Host=%@（SSL=%p），后续响应会被记录", host, ssl);
            size_t dl = len < 2048 ? len : 2048;
            Dump([NSString stringWithFormat:@"SSL 请求 host=%@", host],
                 [NSData dataWithBytes:b length:dl]);
        }
    } else if (bytesMatched(b, len)) {
        // HTTP/2(HPACK) 或二进制帧里直接出现了目标域名字符串
        tlsMark(ssl);
        DLog(@"[ssl] ★★ 二进制帧里出现目标域名（SSL=%p），标记为关注", ssl);
    }
    return r;
}

// ---------------- hook: SSL_read（明文响应） ----------------
static int (*o_SSL_read)(void *, void *, int);
static int my_SSL_read(void *ssl, void *buf, int num) {
    int r = o_SSL_read(ssl, buf, num);
    if (r <= 0) return r;
    if (g_sslReadCalls++ == 0)
        DLog(@"[ssl] ★★ my_SSL_read 首次被调用");
    if (tlsIsHot(ssl)) tlsAccum(ssl, buf, (size_t)r);
    return r;
}

// ---------------- hook: *_ex 变体（有的库用新 API） ----------------
static int (*o_SSL_write_ex)(void *, const void *, size_t, size_t *);
static int my_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    int r = o_SSL_write_ex(ssl, buf, num, written);
    if (r == 1 && written && *written > 0 && *written <= 256 * 1024) {
        size_t len = *written;
        const unsigned char *b = (const unsigned char *)buf;
        if (g_sslWriteCalls++ == 0)
            DLog(@"[ssl] ★★ my_SSL_write_ex 首次被调用");
        if (looksLikeHTTPReq(b, len)) {
            NSString *host = extractHost(b, len);
            if (hostMatched(host)) {
                tlsMark(ssl);
                DLog(@"[ssl] ★★★ 命中目标 Host=%@（SSL=%p）", host, ssl);
            }
        }
    }
    return r;
}

static int (*o_SSL_read_ex)(void *, void *, size_t, size_t *);
static int my_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    int r = o_SSL_read_ex(ssl, buf, num, readbytes);
    if (r == 1 && readbytes && *readbytes > 0) {
        if (g_sslReadCalls++ == 0)
            DLog(@"[ssl] ★★ my_SSL_read_ex 首次被调用");
        if (tlsIsHot(ssl)) tlsAccum(ssl, buf, *readbytes);
    }
    return r;
}

// ============================ 入口 ============================
__attribute__((constructor)) static void bodian_probe_init(void) {
    DLog(@"========== bodian_probe v2 已加载 ==========");
    DLog(@"环境: Flutter=%s  WKWebView=%s",
         (NSClassFromString(@"FlutterViewController") || NSClassFromString(@"FlutterEngine")) ? "yes" : "no",
         objc_getClass("WKWebView") ? "yes" : "no");

    scan_all_images();
    check_dlsym();

    o_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))
                    dlsym(RTLD_DEFAULT, "getaddrinfo");
    o_connect     = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
    o_socket      = (int (*)(int, int, int))dlsym(RTLD_DEFAULT, "socket");
    o_SSL_write   = (int (*)(void *, const void *, int))dlsym(RTLD_DEFAULT, "SSL_write");
    o_SSL_read    = (int (*)(void *, void *, int))dlsym(RTLD_DEFAULT, "SSL_read");
    o_SSL_write_ex = (int (*)(void *, const void *, size_t, size_t *))dlsym(RTLD_DEFAULT, "SSL_write_ex");
    o_SSL_read_ex  = (int (*)(void *, void *, size_t, size_t *))dlsym(RTLD_DEFAULT, "SSL_read_ex");

    // 只对"确实拿到了原始函数指针"的符号做重绑，避免把槽位指向会崩的包装
    struct fbt_rebinding rb[8];
    size_t rbn = 0;
    if (o_SSL_write)    { rb[rbn].name = "SSL_write";    rb[rbn].replacement = (void *)my_SSL_write;    rb[rbn].replaced = (void **)&o_SSL_write;    rbn++; }
    if (o_SSL_read)     { rb[rbn].name = "SSL_read";     rb[rbn].replacement = (void *)my_SSL_read;     rb[rbn].replaced = (void **)&o_SSL_read;     rbn++; }
    if (o_SSL_write_ex) { rb[rbn].name = "SSL_write_ex"; rb[rbn].replacement = (void *)my_SSL_write_ex; rb[rbn].replaced = (void **)&o_SSL_write_ex; rbn++; }
    if (o_SSL_read_ex)  { rb[rbn].name = "SSL_read_ex";  rb[rbn].replacement = (void *)my_SSL_read_ex;  rb[rbn].replaced = (void **)&o_SSL_read_ex;  rbn++; }
    if (o_getaddrinfo)  { rb[rbn].name = "getaddrinfo";  rb[rbn].replacement = (void *)my_getaddrinfo;  rb[rbn].replaced = (void **)&o_getaddrinfo;  rbn++; }
    if (o_socket)       { rb[rbn].name = "socket";       rb[rbn].replacement = (void *)my_socket;       rb[rbn].replaced = (void **)&o_socket;       rbn++; }
    if (o_connect)      { rb[rbn].name = "connect";      rb[rbn].replacement = (void *)my_connect;      rb[rbn].replaced = (void **)&o_connect;      rbn++; }
    int ret = rbn ? fbt_rebind(rb, rbn) : -2;
    DLog(@"[rebind] fishhook ret=%d", ret);
    DLog(@"[rebind] ==== 实际被替换的符号槽位（谁在动态链接它）====\n%s    (SSL_read/SSL_write 一条都没有 => 没人动态链接系统 BoringSSL)",
         g_rb_log[0] ? g_rb_log : "");

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
    }

    DLog(@"========== 就绪：请进会员页/播放页/歌曲详情页，各停 5 秒 ==========");
}
