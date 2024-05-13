#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "zlib.h"

#define WINSIZE 32768U      // sliding window size
#define CHUNK 16384         // file input buffer size

// Decompression modes. These are the inflateInit2() windowBits parameter.
#define RAW -15
#define ZLIB 15
#define GZIP 31

uint64_t deflate_blocks = 0;
uint64_t gzip_members = 0;
uint64_t uncompressed_size = 0;
uint64_t compressed_size = 0;
int header_present = 0;

static const char *humanSize(uint64_t bytes)
{
    char *suffix[] = {"B", "KB", "MB", "GB", "TB"};
    char length = sizeof(suffix) / sizeof(suffix[0]);

    int i = 0;
    double dblBytes = bytes;

    if (bytes > 1024) {
        for (i = 0; (bytes / 1024) > 0 && i<length-1; i++, bytes /= 1024)
            dblBytes = bytes / 1024.0;
    }

    static char output[200];
    sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
    return output;
}

int verify_gzip(char *filename) {
    FILE *in = fopen(filename, "rb");
    if (in == NULL) {
        fprintf(stderr, "gzinfo: could not open %s for reading\n", filename);
        return 1;
    }

    // Set up inflation state.
    z_stream strm = {0};        // inflate engine (gets fired up later)
    unsigned char buf[CHUNK];   // input buffer
    unsigned char win[WINSIZE] = {0};   // output sliding window
    off_t totin = 0;            // total bytes read from input
    off_t totout = 0;           // total bytes uncompressed
    int mode = 0;               // mode: RAW, ZLIB, or GZIP (0 => not set yet)

    // Decompress from in, generating metrics along the way.
    int ret;                    // the return value from zlib, or Z_ERRNO
    off_t last;                 // last access point uncompressed offset
    do {
        // Assure available input, at least until reaching EOF.
        if (strm.avail_in == 0) {
            strm.avail_in = fread(buf, 1, sizeof(buf), in);
            totin += strm.avail_in;
            strm.next_in = buf;
            if (strm.avail_in < sizeof(buf) && ferror(in)) {
                ret = Z_ERRNO;
                break;
            }

            if (mode == 0) {
                // At the start of the input -- determine the type. Assume raw
                // if it is neither zlib nor gzip. This could in theory result
                // in a false positive for zlib, but in practice the fill bits
                // after a stored block are always zeros, so a raw stream won't
                // start with an 8 in the low nybble.
                mode = strm.avail_in == 0 ? RAW :       // empty -- will fail
                       (strm.next_in[0] & 0xf) == 8 ? ZLIB :
                       strm.next_in[0] == 0x1f ? GZIP :
                       /* else */ RAW;
                
                // Check if the header indicates a valid gzip file
                if ((strm.next_in[0] != 0x1F || strm.next_in[1] != 0x8B || strm.next_in[2] != 8) && (mode == GZIP)) {
                    fprintf(stderr, "Invalid GZIP header!\n");
                    return Z_DATA_ERROR;
                } else {
                    header_present = 1;
                }

                ret = inflateInit2(&strm, mode);
                if (ret != Z_OK)
                    break;
            }
        }

        // Assure available output. This rotates the output through, for use as
        // a sliding window on the uncompressed data.
        if (strm.avail_out == 0) {
            strm.avail_out = sizeof(win);
            strm.next_out = win;
        }

        if (mode == RAW)
            // We skip the inflate() call at the start of raw deflate data in
            // order generate an access point there. Set data_type to imitate
            // the end of a header.
            strm.data_type = 0x80;
        else {
            // Inflate and update the number of uncompressed bytes.
            unsigned before = strm.avail_out;
            ret = inflate(&strm, Z_BLOCK);
            totout += before - strm.avail_out;
        }

        if ((strm.data_type & 0xc0) == 0x80) {
            // We are at the end of a header or a non-last deflate block, so we
            // can add an access point here. Furthermore, we are either at the
            // very start for the first access point, or there has been span or
            // more uncompressed bytes since the last access point, so we want
            // to add an access point here.
            deflate_blocks++;
            last = totout;
        }

        if (ret == Z_STREAM_END && mode == GZIP &&
            (strm.avail_in || ungetc(getc(in), in) != EOF)) {
            // There is more input after the end of a gzip member. Reset the
            // inflate state to read another gzip member. On success, this will
            // set ret to Z_OK to continue decompressing.
            gzip_members++;
            ret = inflateReset2(&strm, GZIP);
        }

        // Keep going until Z_STREAM_END or error. If the compressed data ends
        // prematurely without a file read error, Z_BUF_ERROR is returned.
    } while (ret == Z_OK);
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        // An error was encountered. Return a negative
        fprintf(stderr, "gzinfo: compressed data error at %ld in %s\n", totin, filename);
        return ret == Z_NEED_DICT ? Z_DATA_ERROR : ret;
    }

    compressed_size = totin;
    uncompressed_size = totout;

    fclose(in);
    return Z_OK;
}

// Print gzip file information
void print_gzip_info(void) {
    printf("Gzip File Information:\n");
    printf("Header present: %s\n", header_present ? "Yes" : "No");
    printf("Compressed Size: %s\n", humanSize(compressed_size));
    printf("Uncompressed Size: %s\n", humanSize(uncompressed_size));
    printf("Number of Deflate Blocks: %ld\n", deflate_blocks);
    printf("Number of GZIP Members: %ld\n", gzip_members);
}

int main(int argc, char **argv) {
    // Open the input file.
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: gzinfo file.raw\n");
        return 1;
    }

    int retval = verify_gzip(argv[1]);
    if (retval < 0) {
        switch (retval) {
        case Z_MEM_ERROR:
            fprintf(stderr, "gzinfo: out of memory\n");
            break;
        case Z_BUF_ERROR:
            fprintf(stderr, "gzinfo: %s ended prematurely\n", argv[1]);
            break;
        case Z_ERRNO:
            fprintf(stderr, "gzinfo: read error on %s\n", argv[1]);
            break;
        default:
            fprintf(stderr, "gzinfo: error %d\n", retval);
        }
        return 1;
    }

    print_gzip_info();

    return 0;
}


