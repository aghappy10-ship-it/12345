/* X2D II exact-build, process-local menu Loader. See THIRD_PARTY_NOTICES.txt.
 * No camera calls, sensor changes, AOT edits, executable patches or service edits.
 * Only CachedQmlUnit.data changes. Original AOT/unused pointers are preserved.
 */
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef unsigned long long u64;
struct phdr { unsigned int type, flags; u64 offset, vaddr, paddr, filesz, memsz, align; };
struct dl_info { uintptr_t base; const char *name; const struct phdr *phdr; unsigned short phnum; };
extern int dl_iterate_phdr(int (*)(struct dl_info *, size_t, void *), void *);
extern int open(const char *, int, ...);
extern int close(int);
extern ssize_t write(int, const void *, size_t);
extern long lseek(int, long, int);
extern int memcmp(const void *, const void *, size_t);
extern int strcmp(const char *, const char *);
extern char *getenv(const char *);
extern int getpid(void);
extern ssize_t readlink(const char *, char *, size_t);
extern int *__errno(void);
extern void _exit(int) __attribute__((noreturn));
extern const unsigned char stock_unit[], stock_unit_end[], extended_unit[], extended_unit_end[];
struct cached_unit { const unsigned char *data; const void *aot; const void *unused; };
struct aot_word { u64 value; unsigned int relative; };
#include "baseline.h"

enum { RDONLY=0, WRONLY=1, RDWR=2, CREAT=64, EXCL=128, NONBLOCK=2048,
       NOFOLLOW=131072, CLOEXEC=524288, ENOENT_VALUE=2 };

static void status(const char *message) {
    int pid = getpid();
    if (pid <= 0) return;
    /* Exclusive creation must refuse every existing inode, including hardlinks
     * and FIFOs. PID reuse may omit a diagnostic; it must never alter a target.
     * /tmp must be verified root-owned sticky tmpfs in the GUI namespace.
     * Other users may precreate a name there: exclusive creation fails closed. */
    char path[sizeof("/tmp/x2dii-menu.status-") + 10] = "/tmp/x2dii-menu.status-";
    char digits[10];
    unsigned int value = (unsigned int)pid, used = 0;
    do { digits[used++] = (char)('0' + value % 10); value /= 10; } while (value);
    size_t end = sizeof("/tmp/x2dii-menu.status-") - 1;
    while (used) path[end++] = digits[--used];
    path[end] = 0;
    size_t count = 0;
    while (message[count]) ++count;
    int fd = open(path, WRONLY|CREAT|EXCL|NOFOLLOW|CLOEXEC|NONBLOCK, 0600);
    if (fd >= 0) { (void)write(fd, message, count); (void)close(fd); }
}

/* Validate every load header before touching addresses derived from the ELF.
 * Build identity and the relevant complete compiled unit are also compared.
 */
static int image(struct dl_info *info, size_t size, void *out) {
    if (size < sizeof(*info)) return 0;
    if (info->name && info->name[0] && strcmp(info->name, "/system/bin/camera-gui")) return 0;
    if (!info->base || !info->phdr) return 1;
    unsigned int found = 0;
    for (unsigned int i = 0; i < info->phnum; ++i) {
        const struct phdr *p = &info->phdr[i];
        if (p->type != 1) continue;
        if (found >= LOAD_COUNT || memcmp(p, &expected_loads[found], sizeof(*p))) return 1;
        ++found;
    }
    if (found == LOAD_COUNT) *(uintptr_t *)out = info->base;
    return 1;
}

static int replace_pointer(int fd, const void *address, const void *value) {
    return lseek(fd, (long)(uintptr_t)address, 0) == (long)(uintptr_t)address &&
           write(fd, value, sizeof(void *)) == (ssize_t)sizeof(void *) &&
           !memcmp(address, value, sizeof(void *));
}

__attribute__((constructor)) static void install(void) {
    const char *enabled = getenv("X2DII_MENU_EXTENSION");
    if (!enabled || strcmp(enabled, "1")) return;
    char exe[128];
    ssize_t length = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (length <= 0 || length >= (ssize_t)sizeof(exe)-1) return;
    exe[length] = 0;
    if (strcmp(exe, "/system/bin/camera-gui")) return;

    int fd = open("/blackbox/x2dii-menu.disable", RDONLY|NOFOLLOW|CLOEXEC|NONBLOCK);
    if (fd >= 0) { (void)close(fd); status("DISABLED\n"); return; }
    /* Permission/IO/symlink errors cannot be interpreted as permission to load. */
    if (*__errno() != ENOENT_VALUE) { status("DISABLE_CHECK_FAILED\n"); return; }

    uintptr_t base = 0;
    dl_iterate_phdr(image, &base);
    if (!base) { status("IMAGE_LAYOUT_MISMATCH\n"); return; }
    struct cached_unit *cache = (struct cached_unit *)(base + CACHE_VA);
    const unsigned char *original = (const unsigned char *)(base + UNIT_VA);
    if (memcmp((const void *)(base + BUILD_NOTE_VA), expected_build_note, sizeof(expected_build_note)) ||
        (size_t)(stock_unit_end-stock_unit) != UNIT_SIZE ||
        cache->data != original || cache->aot != (const void *)(base + AOT_VA) || cache->unused ||
        memcmp(original, stock_unit, UNIT_SIZE)) { status("BUILD_MISMATCH\n"); return; }
    const u64 *aot = (const u64 *)(base + AOT_VA);
    for (unsigned int i=0; i<AOT_WORD_COUNT; ++i) {
        u64 expected = expected_aot[i].value + (expected_aot[i].relative ? base : 0);
        if (aot[i] != expected) { status("AOT_MISMATCH\n"); return; }
    }
    if ((size_t)(extended_unit_end-extended_unit) != EXTENDED_UNIT_SIZE ||
        memcmp(extended_unit, "qv4cdata", 8)) { status("PAYLOAD_MISMATCH\n"); return; }

    /* Qualification must prove /tmp mount, label, ownership, sticky mode and
     * permitted creation for this exact GUI domain. /dev uses device-labeled
     * devtmpfs, whose pinned policy lacks ordinary-file create for this domain.
     * Marker survives GUI/service restarts, but not a camera reboot. */
    int attempt = open("/tmp/x2dii-menu.attempt", WRONLY|CREAT|EXCL|NOFOLLOW|CLOEXEC|NONBLOCK, 0600);
    if (attempt < 0) { status("SKIPPED_RETRY_OR_MARKER_ERROR\n"); return; }
    if (close(attempt)) { status("MARKER_CLOSE_FAILED\n"); return; }
    fd = open("/proc/self/mem", RDWR|CLOEXEC);
    if (fd < 0) { status("MEMORY_OPEN_FAILED\n"); return; }
    const unsigned char *next = extended_unit;
    if (!replace_pointer(fd, &cache->data, &next)) {
        /* A short write may have already modified part of this one pointer. */
        int restored = replace_pointer(fd, &cache->data, &original);
        (void)close(fd);
        status(restored ? "WRITE_FAILED_RESTORED\n" : "RESTORE_FAILED_EXIT\n");
        if (!restored) _exit(78); /* Never continue with a partially changed cache. */
        return;
    }
    (void)close(fd);
    __asm__ __volatile__("dmb ish" ::: "memory");
    status("MENU_POINTER_READY\n");
}
