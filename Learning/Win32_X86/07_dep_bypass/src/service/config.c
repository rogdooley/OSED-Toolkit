/*
 * config.c - fake business logic. A tiny in-memory key/value store so the
 * vulnerable handler has a plausible reason to exist. None of this is
 * exploitable; it is triage noise that the analyst must read and dismiss.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "service.h"

#define CONFIG_MAX_KEYS   64
#define CONFIG_KEY_LEN    64
#define CONFIG_VAL_LEN    256

typedef struct _ConfigEntry {
    int  used;
    char key[CONFIG_KEY_LEN];
    char value[CONFIG_VAL_LEN];
} ConfigEntry;

static ConfigEntry     g_config[CONFIG_MAX_KEYS];
static CRITICAL_SECTION g_config_lock;
static int             g_config_ready = 0;

void config_init(void)
{
    if (g_config_ready)
        return;
    InitializeCriticalSection(&g_config_lock);
    memset(g_config, 0, sizeof(g_config));

    /* seed a couple of defaults so config_get has something to return */
    strcpy(g_config[0].key, "server.name");
    strcpy(g_config[0].value, "vulnsvc-lab");
    g_config[0].used = 1;

    strcpy(g_config[1].key, "server.motd");
    strcpy(g_config[1].value, "welcome");
    g_config[1].used = 1;

    g_config_ready = 1;
}

static ConfigEntry *find_entry(const char *key)
{
    int i;
    for (i = 0; i < CONFIG_MAX_KEYS; i++)
        if (g_config[i].used && strcmp(g_config[i].key, key) == 0)
            return &g_config[i];
    return NULL;
}

static ConfigEntry *alloc_entry(void)
{
    int i;
    for (i = 0; i < CONFIG_MAX_KEYS; i++)
        if (!g_config[i].used)
            return &g_config[i];
    return NULL;
}

/*
 * NOTE: config_set is reached only *after* the overflow has already occurred
 * inside parse_config_set's sscanf. It is bounded and safe in isolation; it is
 * not the bug. It exists to make the vulnerable code path look purposeful.
 */
int config_set(const char *key, const char *value)
{
    ConfigEntry *e;

    if (!g_config_ready)
        config_init();

    EnterCriticalSection(&g_config_lock);
    e = find_entry(key);
    if (!e)
        e = alloc_entry();
    if (!e) {
        LeaveCriticalSection(&g_config_lock);
        return -1;
    }
    e->used = 1;
    strncpy(e->key, key, CONFIG_KEY_LEN - 1);
    e->key[CONFIG_KEY_LEN - 1] = '\0';
    strncpy(e->value, value, CONFIG_VAL_LEN - 1);
    e->value[CONFIG_VAL_LEN - 1] = '\0';
    LeaveCriticalSection(&g_config_lock);

    log_msg("DEBUG", "config[%s] = %s", key, value);
    return 0;
}

const char *config_get(const char *key)
{
    ConfigEntry *e;
    const char *result = NULL;

    if (!g_config_ready)
        config_init();

    EnterCriticalSection(&g_config_lock);
    e = find_entry(key);
    if (e)
        result = e->value;
    LeaveCriticalSection(&g_config_lock);
    return result;
}
