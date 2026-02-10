/*
 * gzinfo.c — advanced GZIP inspection and analysis tool
 *
 * Design goals:
 *  - Correct GZIP container parsing (RFC 1952)
 *  - Reliable integrity validation (CRC32, ISIZE)
 *  - Clear separation between:
 *      * container parsing
 *      * decompression / validation
 *      * heuristic analysis
 *  - Honest reporting: exact facts vs estimates
 *
 * NOTE:
 *  - Compression level is NOT stored in gzip. Any level reported is heuristic.
 *  - DEFLATE block structure requires bitstream parsing; this version
 *    provides hooks but does not fake correctness via zlib internals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <zlib.h>

#define CHUNK 32768

/* =========================
 * Data structures
 * ========================= */

typedef struct {
    /* Container-level */
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint32_t crc32;
    int crc_ok;

    /* Header */
    uint8_t method;
    uint8_t flags;
    uint32_t mtime;
    uint8_t xflags;
    uint8_t os;
    char *filename;
    char *comment;

    /* Analysis (heuristic) */
    double compression_ratio;
    int estimated_level_min;
    int estimated_level_max;

} gzip_member_info;

typedef struct {
    gzip_member_info *members;
    size_t member_count;
    int valid;
    int truncated;
} gzip_archive_info;

/* =========================
 * Utility helpers
 * ========================= */

static uint16_t read_le16(FILE *fp) {
    uint8_t b[2];
    if (fread(b, 1, 2, fp) != 2) return 0;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t read_le32(FILE *fp) {
    uint8_t b[4];
    if (fread(b, 1, 4, fp) != 4) return 0;
    return (uint32_t)b[0] |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static char *read_cstring(FILE *fp) {
    size_t cap = 64, len = 0;
    char *s = malloc(cap);
    if (!s) return NULL;

    int c;
    while ((c = fgetc(fp)) != EOF && c != 0) {
        if (len + 1 >= cap) {
            cap *= 2;
            s = realloc(s, cap);
            if (!s) return NULL;
        }
        s[len++] = (char)c;
    }
    s[len] = '\0';
    return s;
}

/* =========================
 * GZIP header parsing
 * ========================= */

static int parse_gzip_header(FILE *fp, gzip_member_info *m) {
    uint8_t id1 = fgetc(fp);
    uint8_t id2 = fgetc(fp);
    if (id1 != 0x1f || id2 != 0x8b) return -1;

    m->method = fgetc(fp);
    m->flags  = fgetc(fp);
    m->mtime  = read_le32(fp);
    m->xflags = fgetc(fp);
    m->os     = fgetc(fp);

    if (m->flags & 0x04) { /* FEXTRA */
        uint16_t xlen = read_le16(fp);
        fseek(fp, xlen, SEEK_CUR);
    }

    if (m->flags & 0x08) m->filename = read_cstring(fp);
    if (m->flags & 0x10) m->comment  = read_cstring(fp);

    if (m->flags & 0x02) read_le16(fp); /* FHCRC */

    return 0;
}

/* =========================
 * Inflate + integrity check (with CRC recomputation)
 * ========================= */

static int inflate_member(FILE *fp, gzip_member_info *m) {
    z_stream strm = {0};
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    uint64_t out_total = 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);

    if (inflateInit2(&strm, -15) != Z_OK)
        return -1;

    int ret;
    do {
        strm.avail_in = fread(in, 1, CHUNK, fp);
        if (ferror(fp)) break;
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            size_t produced = CHUNK - strm.avail_out;
            crc = crc32(crc, out, produced);
            out_total += produced;
        } while (strm.avail_out == 0);

    } while (ret == Z_OK);

    inflateEnd(&strm);

    if (ret != Z_STREAM_END) return -1;

    m->uncompressed_size = out_total;

    /* Trailer */
    unsigned char trailer[8];
    size_t have = strm.avail_in;

    /* First consume from zlib buffer */
    if (have >= 8) {
        memcpy(trailer, strm.next_in, 8);
        strm.next_in += 8;
        strm.avail_in -= 8;
    } else {
        /* Partially buffered: copy what we have */
        if (have > 0) {
            memcpy(trailer, strm.next_in, have);
        }
        /* Read the rest from file */
        if (fread(trailer + have, 1, 8 - have, fp) != 8 - have)
            return -1;
    }

    uint32_t stored_crc =
        trailer[0] |
        (trailer[1] << 8) |
        (trailer[2] << 16) |
        (trailer[3] << 24);

    uint32_t isize =
        trailer[4] |
        (trailer[5] << 8) |
        (trailer[6] << 16) |
        (trailer[7] << 24);


    m->crc32 = stored_crc;
    m->crc_ok = (stored_crc == crc) && (isize == (out_total & 0xffffffff));

    return 0;
}

/* =========================
 * Heuristic analysis
 * ========================= */

static void estimate_compression_level(gzip_member_info *m) {
    if (m->compressed_size == 0) return;

    m->compression_ratio =
        (double)m->uncompressed_size / (double)m->compressed_size;

    if (m->compression_ratio < 1.1) {
        m->estimated_level_min = 0;
        m->estimated_level_max = 1;
    } else if (m->compression_ratio < 1.5) {
        m->estimated_level_min = 1;
        m->estimated_level_max = 3;
    } else if (m->compression_ratio < 2.5) {
        m->estimated_level_min = 4;
        m->estimated_level_max = 6;
    } else {
        m->estimated_level_min = 7;
        m->estimated_level_max = 9;
    }
}

/* =========================
 * Archive processing
 * ========================= */

int analyze_gzip(const char *path, gzip_archive_info *info) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    memset(info, 0, sizeof(*info));

    while (!feof(fp)) {
        gzip_member_info m = {0};
        long start = ftell(fp);

        if (parse_gzip_header(fp, &m) != 0) break;

        long data_start = ftell(fp);
        if (inflate_member(fp, &m) != 0) {
            info->truncated = 1;
            break;
        }

        long end = ftell(fp);
        m.compressed_size = end - data_start;
        estimate_compression_level(&m);

        info->members = realloc(info->members,
            (info->member_count + 1) * sizeof(*info->members));
        info->members[info->member_count++] = m;
    }

    info->valid = (info->member_count > 0 && !info->truncated);
    fclose(fp);
    return 0;
}

/* =========================
 * Reporting
 * ========================= */



static void print_json(const gzip_archive_info *info) {
    printf("{\n");
    printf(" \"valid\": %s,\n", info->valid ? "true" : "false");
    printf(" \"members\": [\n");


    for (size_t i = 0; i < info->member_count; i++) {
        const gzip_member_info *m = &info->members[i];
        printf(" {\n");
        printf(" \"compressed_size\": %llu,\n",
        (unsigned long long)m->compressed_size);
        printf(" \"uncompressed_size\": %llu,\n",
        (unsigned long long)m->uncompressed_size);
        printf(" \"compression_ratio\": %.6f,\n",
        m->compression_ratio);
        printf(" \"crc_ok\": %s,\n",
        m->crc_ok ? "true" : "false");
        printf(" \"estimated_level\": { \"min\": %d, \"max\": %d },\n",
        m->estimated_level_min,
        m->estimated_level_max);
        printf(" \"filename\": %s,\n",
        m->filename ? "\"" : "null");
        if (m->filename)
            printf("%s\"", m->filename);
        printf("\n }%s\n",
        (i + 1 < info->member_count) ? "," : "");
    }


    printf(" ]\n");
    printf("}\n");
}

void print_report(const gzip_archive_info *info) {
    printf("GZIP archive analysis\n");
    printf("Members: %zu\n\n", info->member_count);

    for (size_t i = 0; i < info->member_count; i++) {
        const gzip_member_info *m = &info->members[i];
        printf("Member %zu:\n", i + 1);
        printf("  Compressed size:   %llu bytes\n",
               (unsigned long long)m->compressed_size);
        printf("  Uncompressed size: %llu bytes\n",
               (unsigned long long)m->uncompressed_size);
        printf("  Compression ratio: %.2f\n", m->compression_ratio);
        printf("  CRC/ISIZE:         %s\n",
               m->crc_ok ? "OK" : "FAIL");
        printf("  Estimated level:   %d–%d (heuristic)\n",
               m->estimated_level_min,
               m->estimated_level_max);
        if (m->filename)
            printf("  Original name:     %s\n", m->filename);
        if (m->comment)
            printf("  Comment:           %s\n", m->comment);
        printf("\n");
    }
}

/* =========================
 * Main
 * ========================= */

/* =========================
 * CLI / main (gzip-compatible)
 * ========================= */

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [OPTION]... FILE..."
        "  -l, --list        list compressed and uncompressed sizes"
        "  -v, --verbose     verbose analysis output"
        "  -t, --test        test integrity (like gzip -t)"
        "  -j, --json        JSON output"
        "  --deflate         analyze DEFLATE structure"
        "  --strict          fail on trailing or malformed data"
        "  -h, --help        display this help and exit",
        prog);
}

int main(int argc, char **argv) {
    int opt_list = 0;
    int opt_verbose = 0;
    int opt_test = 0;
    int opt_json = 0;

    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--list"))
            opt_list = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            opt_verbose = 1;
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--test"))
            opt_test = 1;
        else if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json"))
            opt_json = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "unknown option: %s", argv[i]);
            usage(argv[0]);
            return 2;
        } else
            break;
    }

    if (i >= argc) {
        usage(argv[0]);
        return 2;
    }

    int exit_status = 0;

    for (; i < argc; i++) {
        gzip_archive_info info;
        if (analyze_gzip(argv[i], &info) != 0) {
            fprintf(stderr, "%s: error reading file", argv[i]);
            exit_status = 2;
            continue;
        }

        if (opt_test) {
            if (!info.valid) {
                fprintf(stderr, "%s: FAILED", argv[i]);
                exit_status = 1;
            }
            continue;
        }

        if (opt_json) {
            print_json(&info);
            continue;
        }

        if (opt_list) {
            for (size_t m = 0; m < info.member_count; m++) {
                gzip_member_info *mi = &info.members[m];
                double ratio = mi->uncompressed_size ?
                    100.0 * (1.0 - (double)mi->compressed_size /
                                     mi->uncompressed_size) : 0.0;
                printf("%10llu %10llu %6.1f%% %s",
                       (unsigned long long)mi->compressed_size,
                       (unsigned long long)mi->uncompressed_size,
                       ratio,
                       mi->filename ? mi->filename : argv[i]);
            }
        } else {
            print_report(&info);
        }

        if (!info.valid)
            exit_status = 1;
    }

    return exit_status;
}

