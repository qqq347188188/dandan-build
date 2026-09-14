//
//  dandan_hook.c —— 蛋蛋不语 Android(Flutter) VIP 解锁
//
//  原理：
//    Dart 的网络栈在 libflutter.so 里，通过 PLT/GOT 调 libc 的 connect/read/write。
//    本库启动后用 dl_iterate_phdr 找到 libflutter.so，改写它的 GOT 槽位，
//    把 connect / read / write（含 __read_chk/__write_chk/recv/send）换成我们的实现。
//      - connect: 目标 38.76.202.248:8000 的 fd 打标记；
//      - write:   标记 fd 的请求把 Accept-Encoding 值抹成 x（防 gzip，等长改写）；
//      - read:    标记 fd 且"本次读到的就是一个完整响应"时，做严格等长 JSON 改写：
//                 vip 字段变长部分向 avatar/website/username 按需借空间
//                 （与 iOS 版"动态借空间"同一套逻辑）。
//
//    只有 64 位 ABI 实装 hook；armeabi-v7a 只加载不打补丁（App 照常联网）。
//  日志：logcat，tag = dandan
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "dandan", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "dandan", __VA_ARGS__)

// ---------------- 目标 ----------------
static const char *TARGET_IP_S = "38.76.202.248";
static const int   TARGET_PORT = 8000;
#define MAXFD 4096
static volatile signed char g_conn[MAXFD];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// ---------------- 小工具 ----------------
static uint8_t *fb_find(const uint8_t *h, size_t hl, const void *nd, size_t nl) {
    if (!nl || hl < nl) return NULL;
    const uint8_t *n = (const uint8_t *)nd;
    for (size_t i = 0; i + nl <= hl; i++)
        if (h[i] == n[0] && memcmp(h + i, n, nl) == 0) return (uint8_t *)h + i;
    return NULL;
}

static long parse_content_length(const uint8_t *b, size_t hdrEnd) {
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
                uint8_t c = b[i + k];
                if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
                if (c != (uint8_t)key[k]) { ok = 0; break; }
            }
            if (ok) {
                long v = 0; int seen = 0;
                for (size_t k = keyLen; k < lineLen; k++) {
                    uint8_t c = b[i + k];
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

static int response_complete(const uint8_t *b, size_t len) {
    const uint8_t *p = fb_find(b, len, "\r\n\r\n", 4);
    if (!p) return 0;
    size_t hdrEnd = (size_t)(p - b) + 4;
    long cl = parse_content_length(b, hdrEnd);
    if (cl < 0) return 0;
    return len >= hdrEnd + (size_t)cl;
}

// Accept-Encoding 值抹成 x（等长，防 gzip）
static void neutralize_accept_encoding(uint8_t *b, size_t len) {
    static const char key[] = "accept-encoding:";
    const size_t keyLen = sizeof(key) - 1;
    if (len < keyLen + 4) return;
    char *low = (char *)malloc(len + 1);
    if (!low) return;
    for (size_t i = 0; i < len; i++) {
        char c = (char)b[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        low[i] = c;
    }
    low[len] = 0;
    char *p = strstr(low, key);
    if (p) {
        size_t off = (size_t)(p - low) + keyLen;
        while (off < len && (b[off] == ' ' || b[off] == '\t')) off++;
        while (off < len && b[off] != '\r' && b[off] != '\n') b[off++] = 'x';
    }
    free(low);
}

// ---------------- JSON 等长改写（动态借空间版） ----------------
static const char AVATAR[] =
    "https://i.ibb.co/NgghpGgn/11zon-A9-CBAC35-2-CA3-4-E7-F-923-D-7304-EEB40635.webp";
// 小柳是个超霸（UTF-8 共 18 字节，写成字节避免源码编码问题）
static const uint8_t NAME[] = {
    0xE5,0xB0,0x8F, 0xE6,0x9F,0xB3, 0xE6,0x98,0xAF,
    0xE4,0xB8,0xAA, 0xE8,0xB6,0x85, 0xE9,0x9C,0xB8
};

// 把 src 截断/补空格到正好 target 字节（不切断多字节字符）
static size_t fit_bytes(const uint8_t *src, size_t slen, size_t target, uint8_t *out, size_t cap) {
    if (target > cap) return 0;
    size_t n = 0;
    if (src && slen) {
        n = slen <= target ? slen : target;
        if (slen > target)
            while (n > 0 && n < slen && (src[n] & 0xC0) == 0x80) n--;
        memcpy(out, src, n);
    }
    while (n < target) out[n++] = ' ';
    return n;
}

// 量 JSON 字符串字段值的字节长度；找不到返回 -1
static long value_len(const uint8_t *d, size_t len, const char *key) {
    size_t kl = strlen(key);
    const uint8_t *p = fb_find(d, len, key, kl);
    if (!p) return -1;
    size_t vs = (size_t)(p - d) + kl, ve = vs;
    while (ve < len && d[ve] != '"' && d[ve] != '\\') ve++;
    if (ve >= len || d[ve] != '"') return -1;
    return (long)(ve - vs);
}

// 替换 JSON 字符串字段的值（长度可变）
static void replace_value(uint8_t *d, size_t *len, const char *key, const uint8_t *val, size_t vlen) {
    size_t kl = strlen(key);
    const uint8_t *p = fb_find(d, *len, key, kl);
    if (!p) return;
    size_t vs = (size_t)(p - d) + kl, ve = vs;
    while (ve < *len && d[ve] != '"' && d[ve] != '\\') ve++;
    if (ve >= *len || d[ve] != '"') return;
    memmove(d + vs + vlen, d + ve, *len - ve);
    memcpy(d + vs, val, vlen);
    *len = *len - (ve - vs) + vlen;
}

static int replace_all(uint8_t *d, size_t *len, const char *pat, const char *rep) {
    size_t pl = strlen(pat), rl = strlen(rep);
    int changed = 0;
    for (;;) {
        uint8_t *p = fb_find(d, *len, pat, pl);
        if (!p) break;
        size_t idx = (size_t)(p - d);
        memmove(d + idx + rl, d + idx + pl, *len - idx - pl);
        memcpy(d + idx, rep, rl);
        *len = *len - pl + rl;
        changed = 1;
    }
    return changed;
}

// 严格等长改写（动态借空间：avatar -> website -> username）
static int patch_body(uint8_t *body, size_t bodyLen) {
    if (!body || bodyLen < 8 || bodyLen > 1024 * 1024) return 0;
    uint8_t *nb = (uint8_t *)malloc(bodyLen + 8192);
    if (!nb) return 0;
    size_t nlen = bodyLen;
    memcpy(nb, body, bodyLen);

    long U = value_len(nb, nlen, "\"username\":\"");
    long A = value_len(nb, nlen, "\"avatar_url\":\"");
    long W = value_len(nb, nlen, "\"website\":\"");

    int c1 = replace_all(nb, &nlen, "\"vip_status\":false", "\"vip_status\":true");
    int c2 = replace_all(nb, &nlen, "\"vip_level\":0", "\"vip_level\":3");
    int c3 = replace_all(nb, &nlen, "\"vip_expire_at\":null",
                         "\"vip_expire_at\":\"2099-09-19T22:21:06.147807+00:00\"");
    if (!(c1 || c2 || c3)) { free(nb); return 0; }

    long need = (long)nlen - (long)bodyLen;
    int avatarDone = 0, usernameDone = 0;

    if (need > 0) {
        if (A > 0) {
            if (A - (long)(sizeof(AVATAR) - 1) >= need) {
                replace_value(nb, &nlen, "\"avatar_url\":\"", (const uint8_t *)AVATAR,
                              sizeof(AVATAR) - 1);
                need -= (A - (long)(sizeof(AVATAR) - 1));
            } else {
                replace_value(nb, &nlen, "\"avatar_url\":\"", (const uint8_t *)"", 0);
                need -= A;
            }
            avatarDone = 1;
        }
        if (need > 0 && W > 0) {
            replace_value(nb, &nlen, "\"website\":\"", (const uint8_t *)"", 0);
            need -= W;
        }
        if (need > 0 && U > 0 && (size_t)U >= (size_t)need) {
            uint8_t tmp[128];
            size_t m = fit_bytes(NAME, sizeof(NAME), (size_t)U - (size_t)need, tmp, sizeof(tmp));
            if (m == (size_t)U - (size_t)need) {
                replace_value(nb, &nlen, "\"username\":\"", tmp, m);
                usernameDone = 1;
                need = 0;
            }
        }
        if (need > 0) { free(nb); return 0; }
    }

    // 空间允许时保住自定义名字/头像（不会让 body 变长）
    if (!usernameDone && U > 0) {
        uint8_t tmp[128];
        size_t m = fit_bytes(NAME, sizeof(NAME), (size_t)U, tmp, sizeof(tmp));
        if (m == (size_t)U) replace_value(nb, &nlen, "\"username\":\"", tmp, m);
    }
    if (!avatarDone && A >= (long)(sizeof(AVATAR) - 1))
        replace_value(nb, &nlen, "\"avatar_url\":\"", (const uint8_t *)AVATAR, sizeof(AVATAR) - 1);

    if (nlen > bodyLen) { free(nb); return 0; }
    if (nlen < bodyLen) {                       // 变短了：末尾补空格（JSON 尾部空白合法）
        memset(nb + nlen, ' ', bodyLen - nlen);
        nlen = bodyLen;
    }
    memcpy(body, nb, bodyLen);
    free(nb);
    return 1;
}

// ---------------- fd 标记 ----------------
static int is_target(const struct sockaddr *addr) {
    if (!addr || addr->sa_family != AF_INET) return 0;
    struct in_addr t;
    if (inet_pton(AF_INET, TARGET_IP_S, &t) != 1) return 0;
    const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
    return s->sin_addr.s_addr == t.s_addr && ntohs(s->sin_port) == TARGET_PORT;
}

static void mark_fd(int fd) {
    if (fd >= 0 && fd < MAXFD) {
        pthread_mutex_lock(&g_lock);
        g_conn[fd] = 1;
        pthread_mutex_unlock(&g_lock);
        LOGI("tracked fd=%d", fd);
    }
}

static int fd_tracked(int fd) {
    if (fd < 0 || fd >= MAXFD) return 0;
    pthread_mutex_lock(&g_lock);
    int r = g_conn[fd];
    pthread_mutex_unlock(&g_lock);
    return r;
}

// ---------------- hook：read 侧 ----------------
static void handle_read(int fd, void *buf, ssize_t r) {
    if (r < 24) return;
    if (!fd_tracked(fd)) return;
    uint8_t *b = (uint8_t *)buf;
    const uint8_t *sep = fb_find(b, (size_t)r, "\r\n\r\n", 4);
    if (!sep) return;
    size_t hdrEnd = (size_t)(sep - b) + 4;
    if (fb_find(b, hdrEnd, "chunked", 7)) return;
    if (!response_complete(b, (size_t)r)) return;
    if (patch_body(b + hdrEnd, (size_t)r - hdrEnd))
        LOGI("response patched fd=%d len=%zd", fd, r);
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t r = read(fd, buf, count);
    handle_read(fd, buf, r);
    return r;
}

static ssize_t my_read_chk(int fd, void *buf, size_t count, size_t bufsize) {
    (void)bufsize;
    ssize_t r = read(fd, buf, count);
    handle_read(fd, buf, r);
    return r;
}

static ssize_t my_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t r = recv(fd, buf, len, flags);
    handle_read(fd, buf, r);
    return r;
}

// ---------------- hook：write 侧 ----------------
static ssize_t write_tracked(int fd, const void *buf, size_t len,
                             ssize_t (*sendfn)(int, const void *, size_t)) {
    if (!buf || len < 20 || len > 1024 * 1024) return sendfn(fd, buf, len);
    uint8_t *tmp = (uint8_t *)malloc(len);
    if (!tmp) return sendfn(fd, buf, len);
    memcpy(tmp, buf, len);
    neutralize_accept_encoding(tmp, len);
    ssize_t r = sendfn(fd, tmp, len);
    free(tmp);
    return r;
}

static ssize_t my_write(int fd, const void *buf, size_t len) {
    if (!fd_tracked(fd)) return write(fd, buf, len);
    return write_tracked(fd, buf, len, write);
}

static ssize_t my_write_chk(int fd, const void *buf, size_t count, size_t bufsize) {
    (void)bufsize;
    if (!fd_tracked(fd)) return write(fd, buf, count);
    return write_tracked(fd, buf, count, write);
}

static ssize_t my_send(int fd, const void *buf, size_t len, int flags) {
    (void)flags;
    if (!fd_tracked(fd)) return write(fd, buf, len);
    return write_tracked(fd, buf, len, write);
}

static int my_connect(int fd, const struct sockaddr *addr, socklen_t al) {
    int r = connect(fd, addr, al);
    int e = errno;
    if (((r == 0) || (r == -1 && e == EINPROGRESS)) && is_target(addr)) mark_fd(fd);
    errno = e;
    return r;
}

// ---------------- GOT 改写（只 64 位 ABI） ----------------
#if defined(__aarch64__) || defined(__x86_64__)
#define HOOK_ENABLED 1
#include <elf.h>
#include <link.h>

#if defined(__aarch64__)
#define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GLOB_DAT  R_AARCH64_GLOB_DAT
#else
#define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define R_GLOB_DAT  R_X86_64_GLOB_DAT
#endif

struct find_ctx { const char *needle; uintptr_t base; const ElfW(Dyn) *dyn; };

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct find_ctx *ctx = (struct find_ctx *)data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, ctx->needle)) return 0;
    ctx->base = info->dlpi_addr;
    for (int i = 0; i < (int)info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            ctx->dyn = (const ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            return 1;
        }
    }
    return 0;
}

static void *make_rw(void *p) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)p & ~((uintptr_t)ps - 1);
    if (mprotect((void *)a, (size_t)ps, PROT_READ | PROT_WRITE) != 0) return NULL;
    return p;
}

static int patch_rela(const ElfW(Rela) *r, uintptr_t base, uintptr_t symtab, uintptr_t strtab) {
    unsigned t = (unsigned)ELF64_R_TYPE(r->r_info);
    if (t != R_JUMP_SLOT && t != R_GLOB_DAT) return 0;
    const ElfW(Sym) *s = &((const ElfW(Sym) *)symtab)[ELF64_R_SYM(r->r_info)];
    const char *name = (const char *)strtab + s->st_name;
    void *repl = NULL;
    if      (!strcmp(name, "connect"))    repl = (void *)my_connect;
    else if (!strcmp(name, "read"))       repl = (void *)my_read;
    else if (!strcmp(name, "write"))      repl = (void *)my_write;
    else if (!strcmp(name, "recv"))       repl = (void *)my_recv;
    else if (!strcmp(name, "send"))       repl = (void *)my_send;
    else if (!strcmp(name, "__read_chk")) repl = (void *)my_read_chk;
    else if (!strcmp(name, "__write_chk"))repl = (void *)my_write_chk;
    if (!repl) return 0;
    uintptr_t off = (uintptr_t)r->r_offset;
    if (off < base) off += base;                 // vaddr -> 绝对地址
    void **slot = (void **)off;
    void *cur = *slot;
    if (cur == repl) return 1;
    if (!make_rw(slot)) { LOGE("mprotect 失败 %s", name); return 0; }
    *slot = repl;
    LOGI("hooked %s (was %p)", name, cur);
    return 1;
}

static int try_hook(void) {
    struct find_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.needle = "libflutter.so";
    if (dl_iterate_phdr(phdr_cb, &ctx) == 0 || !ctx.dyn) return 0;

    uintptr_t base = ctx.base, symtab = 0, strtab = 0, jmprel = 0, rela = 0;
    size_t pltrelsz = 0, relasz = 0;
    for (const ElfW(Dyn) *d = ctx.dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab   = d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab   = d->d_un.d_ptr; break;
            case DT_JMPREL:   jmprel   = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
            case DT_RELA:     rela     = d->d_un.d_ptr; break;
            case DT_RELASZ:   relasz   = d->d_un.d_val; break;
        }
    }
    if (!symtab || !strtab) return 0;
    if (symtab < base) symtab += base;
    if (strtab < base) strtab += base;
    if (jmprel && jmprel < base) jmprel += base;
    if (rela && rela < base) rela += base;

    int hooked = 0;
    if (jmprel && pltrelsz)
        for (size_t i = 0; i < pltrelsz / sizeof(ElfW(Rela)); i++)
            hooked += patch_rela(&((const ElfW(Rela) *)jmprel)[i], base, symtab, strtab);
    if (rela && relasz)
        for (size_t i = 0; i < relasz / sizeof(ElfW(Rela)); i++) {
            const ElfW(Rela) *r = &((const ElfW(Rela) *)rela)[i];
            if ((unsigned)ELF64_R_TYPE(r->r_info) == R_GLOB_DAT)
                hooked += patch_rela(r, base, symtab, strtab);
        }
    return hooked > 0;
}

static void *hook_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 300; i++) {          // 最多等 60 秒（libflutter 启动稍晚）
        if (try_hook()) { LOGI("libflutter.so GOT hook 完成"); return NULL; }
        usleep(200 * 1000);
    }
    LOGE("60 秒内未找到 libflutter.so，未打补丁");
    return NULL;
}
#else
#define HOOK_ENABLED 0
#endif

// ---------------- 入口 ----------------
__attribute__((constructor)) static void dandan_init(void) {
    LOGI("dandanhook v1 loaded");
#if HOOK_ENABLED
    pthread_t t;
    if (pthread_create(&t, NULL, hook_thread, NULL) == 0) pthread_detach(t);
#else
    LOGI("32-bit ABI 不实装 hook（App 照常运行）");
#endif
}
