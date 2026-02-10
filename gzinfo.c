#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#define CHUNK 32768

typedef struct {
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint32_t stored_crc;
    uint32_t computed_crc;
    int crc_ok;
    uint8_t method;
    uint8_t flags;
    uint32_t mtime;
    uint8_t xflags;
    uint8_t os;
    char *filename;
} gzip_member_info;

typedef struct {
    gzip_member_info *members;
    size_t member_count;
} gzip_report;

/* --- Utility: Read Little Endian --- */
static uint32_t read_u32(FILE *fp) {
    uint8_t b[4];
    if (fread(b, 1, 4, fp) != 4) return 0;
    return (uint32_t)b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

static uint16_t read_u16(FILE *fp) {
    uint8_t b[2];
    if (fread(b, 1, 2, fp) != 2) return 0;
    return (uint16_t)b[0] | (b[1] << 8);
}

/* --- Forensic String Parsing --- */
static char *read_gz_string(FILE *fp) {
    size_t cap = 32, len = 0;
    char *s = malloc(cap);
    int c;
    while ((c = fgetc(fp)) != EOF && c != 0) {
        if (len + 1 >= cap) {
            cap *= 2;
            s = realloc(s, cap);
        }
        s[len++] = (char)c;
    }
    s[len] = '\0';
    return s;
}

/* --- Core Logic: Header & Inflate --- */
static int process_member(FILE *fp, gzip_member_info *m) {
    long member_start = ftell(fp);
    
    // 1. Parse Header
    uint8_t id[2];
    if (fread(id, 1, 2, fp) != 2 || id[0] != 0x1f || id[1] != 0x8b) return -1;

    m->method = fgetc(fp);
    m->flags  = fgetc(fp);
    m->mtime  = read_u32(fp);
    m->xflags = fgetc(fp);
    m->os     = fgetc(fp);

    if (m->flags & 0x04) fseek(fp, read_u16(fp), SEEK_CUR); // FEXTRA
    if (m->flags & 0x08) m->filename = read_gz_string(fp);  // FNAME
    if (m->flags & 0x10) free(read_gz_string(fp));         // FCOMMENT (skip)
    if (m->flags & 0x02) fseek(fp, 2, SEEK_CUR);           // FHCRC

    long data_start = ftell(fp);

    // 2. Inflate and Compute CRC
    z_stream strm = {0};
    unsigned char in[CHUNK], out[CHUNK];
    // -15 windowBits = Raw Deflate (no headers expected)
    if (inflateInit2(&strm, -15) != Z_OK) return -1;

    uint32_t running_crc = crc32(0L, Z_NULL, 0);
    uint64_t total_out = 0;
    int ret;

    do {
        strm.avail_in = fread(in, 1, CHUNK, fp);
        if (strm.avail_in == 0) break;
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            
            size_t produced = CHUNK - strm.avail_out;
            running_crc = crc32(running_crc, out, (uInt)produced);
            total_out += produced;
        } while (strm.avail_out == 0 && ret != Z_STREAM_END);
    } while (ret != Z_STREAM_END && !feof(fp));

    // 3. Precise Backtrack
    // Re-align the file pointer to exactly where DEFLATE ended
    fseek(fp, -(long)strm.avail_in, SEEK_CUR);
    m->compressed_size = ftell(fp) - data_start;

    // 4. Trailer Validation
    m->stored_crc = read_u32(fp);
    uint32_t stored_isize = read_u32(fp);
    
    m->uncompressed_size = total_out;
    m->computed_crc = running_crc;
    m->crc_ok = (m->stored_crc == running_crc) && 
                (stored_isize == (uint32_t)(total_out & 0xFFFFFFFF));

    inflateEnd(&strm);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.gz>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("File error"); return 1; }

    printf("Forensic Analysis for: %s\n", argv[1]);
    printf("------------------------------------------------------\n");

    int member_idx = 0;
    while (!feof(fp)) {
        gzip_member_info m = {0};
        if (process_member(fp, &m) != 0) break;

        printf("Member #%d:\n", ++member_idx);
        printf("  Filename:     %s\n", m.filename ? m.filename : "N/A");
        printf("  OS/Packer:    0x%02X / 0x%02X\n", m.os, m.xflags);
        printf("  Compressed:   %llu bytes\n", (unsigned long long)m.compressed_size);
        printf("  Uncompressed: %llu bytes\n", (unsigned long long)m.uncompressed_size);
        printf("  CRC32 Status: %s (Stored: %08X, Computed: %08X)\n", 
               m.crc_ok ? "VALID" : "INVALID", m.stored_crc, m.computed_crc);
        
        if (m.filename) free(m.filename);
        
        // Peek for next member
        int next = fgetc(fp);
        if (next == EOF) break;
        ungetc(next, fp);
    }

    fclose(fp);
    return 0;
}
