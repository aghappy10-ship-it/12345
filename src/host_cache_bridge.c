/* Desktop Windows x64 only. Qt 6.8.2 qqmlprivate.h defines these layouts.
 * No Python callback is entered by the QML loader thread. The tiny lock guards
 * configuration, deactivation and counters; returned units remain externally
 * pinned for process lifetime because Qt may retain their data after lookup.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#define EXPORT __declspec(dllexport)
/* No CRT is linked. Windows still calls the conventional DLL entry; no
 * allocation, locking, Python or Qt work belongs under its loader lock. */
int __stdcall _DllMainCRTStartup(void *module, unsigned long reason, void *reserved) {
    (void)module; (void)reason; (void)reserved;
    return 1;
}
typedef unsigned char (*equals_fn)(const void *, const void *);
struct cached_unit { const void *data, *aot, *unused2; };
struct cache_hook { int version; const void *lookup; };
_Static_assert(sizeof(void *) == 8, "Windows x64 required");
_Static_assert(sizeof(struct cached_unit) == 24, "Qt cached-unit layout");
_Static_assert(sizeof(struct cache_hook) == 16, "Qt registration layout");
_Static_assert(offsetof(struct cache_hook, lookup) == 8, "Qt hook pointer offset");

static atomic_flag lock = ATOMIC_FLAG_INIT;
static equals_fn comparator;
static const void *expected_url;
static const struct cached_unit *cached;
static uint64_t hits;
static unsigned active;

static void acquire(void) {
    while (atomic_flag_test_and_set_explicit(&lock, memory_order_acquire))
        __asm__ volatile("pause");
}
static void release(void) { atomic_flag_clear_explicit(&lock, memory_order_release); }

EXPORT int bridge_configure(equals_fn eq, const void *url, const struct cached_unit *unit) {
    if (!eq || !url || !unit || !unit->data || unit->aot || unit->unused2) return 0;
    acquire();
    if (active) { release(); return 0; }
    comparator = eq;
    expected_url = url;
    cached = unit;
    hits = 0;
    active = 1;
    release();
    return 1;
}

EXPORT const struct cached_unit *bridge_lookup(const void *actual) {
    const struct cached_unit *answer = 0;
    acquire();
    if (active && actual && comparator(actual, expected_url)) {
        ++hits;
        answer = cached;
    }
    release();
    return answer;
}

EXPORT int bridge_deactivate(const struct cached_unit *owner) {
    acquire();
    if (!active || owner != cached) { release(); return 0; }
    active = 0;
    comparator = 0;
    expected_url = 0;
    cached = 0;
    release();
    return 1;
}

EXPORT uint64_t bridge_hits(void) { acquire(); uint64_t n = hits; release(); return n; }
EXPORT unsigned bridge_active(void) { acquire(); unsigned n = active; release(); return n; }
EXPORT unsigned bridge_unit_size(void) { return sizeof(struct cached_unit); }
EXPORT unsigned bridge_hook_size(void) { return sizeof(struct cache_hook); }
EXPORT unsigned bridge_hook_lookup_offset(void) { return offsetof(struct cache_hook, lookup); }
