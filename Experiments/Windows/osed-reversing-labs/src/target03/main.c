#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { unsigned char magic[4]; uint16_t version, count; uint32_t table_size; } Header;
typedef struct { uint16_t size, flags; unsigned char data[20]; } Entry;
typedef struct { unsigned char kind, value[23]; } Slot;
static int read_exact(FILE *s, void *p, size_t n) { return fread(p, 1, n, s) == n; }
static int load(FILE *s) { Header h; uint16_t allocation_count, i; Slot *slots; Entry e; if (!read_exact(s, &h, sizeof(h)) || memcmp(h.magic, "RVF1", 4) || h.version != 3) return 0; if (h.count == 0 || h.count > 4096 || h.table_size < h.count * sizeof(Entry)) return 0; allocation_count = (uint16_t)(h.count * sizeof(Slot)); slots = (Slot *)malloc(allocation_count); if (!slots) return 0; for (i = 0; i < h.count; ++i) { if (!read_exact(s, &e, sizeof(e)) || e.size > sizeof(e.data)) { free(slots); return 0; } slots[i].kind = (unsigned char)e.flags; memcpy(slots[i].value, e.data, e.size); } printf("loaded %u records\n", h.count); free(slots); return 1; }
int main(int argc, char **argv) { FILE *s; if (argc != 2) { fprintf(stderr, "usage: target03.exe <file>\n"); return 2; } s = fopen(argv[1], "rb"); if (!s) return 1; if (!load(s)) { fclose(s); return 1; } fclose(s); return 0; }
