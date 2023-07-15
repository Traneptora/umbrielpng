/**
 * @file umbrielpng.c
 * @author Leo Izen <leo.izen@gmail.com>
 * @brief PNG Tweaker
 * @version 0.1
 * @date 2023-07-15
 *
 * BSD 3-Clause License
 *
 * Copyright (c) 2023, Leo Izen
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <error.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#define maketag(a,b,c,d) ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) |\
                         (((uint32_t)(c)) << 8) | (uint32_t)(d))

#define freep(p) do {   \
    if (p) free(p);     \
    (p) = NULL;         \
} while (0)

#define tag_IHDR maketag('I','H','D','R')
#define tag_PLTE maketag('P','L','T','E')
#define tag_IDAT maketag('I','D','A','T')
#define tag_IEND maketag('I','E','N','D')

#define tag_cICP maketag('c','I','C','P')
#define tag_iCCP maketag('i','C','C','P')
#define tag_sRGB maketag('s','R','G','B')
#define tag_cHRM maketag('c','H','R','M')
#define tag_gAMA maketag('g','A','M','A')

#define tag_fdAT maketag('f','d','A','T')
#define tag_acTL maketag('a','c','T','L')
#define tag_fcTL maketag('f','c','T','L')

#define tag_sBIT maketag('s','B','I','T')
#define tag_tRNS maketag('t','R','N','S')
#define tag_hIST maketag('h','I','S','T')

#define tag_bKGD maketag('b','K','G','D')
#define tag_eXIf maketag('e','X','I','f')
#define tag_pHYs maketag('p','H','Y','s')
#define tag_sPLT maketag('s','P','L','T')
#define tag_tIME maketag('t','I','M','E')
#define tag_tEXt maketag('t','E','X','t')
#define tag_zTXt maketag('z','T','X','t')
#define tag_iTXt maketag('i','T','X','t')

typedef struct UmbPngChunk {
    uint32_t chunk_size;
    uint32_t tag;
    uint8_t *data;
    uint32_t data_size;
    uint32_t crc32;
    size_t offset;
} UmbPngChunk;

typedef struct UmbPngChunkChain {
    UmbPngChunk *chunk;
    struct UmbPngChunkChain *prev;
    struct UmbPngChunkChain *next;
} UmbPngChunkChain;

enum UmbPngColorType {
    COLOR_GRAY = 0,
    COLOR_TRUE = 2,
    COLOR_INDEXED = 3,
    COLOR_GRAY_A = 4,
    COLOR_RGBA = 6,
};

typedef struct UmbPngScanData {
    int have_cicp;
    int have_iccp;
    int have_srgb;
    int have_gama_chrm;
    int have_plte;
    int icc_is_srgb;

    uint32_t width;
    uint32_t height;
    int depth;
    enum UmbPngColorType color;

    int sbit[4];
} UmbPngScanData;

typedef struct UmbIccCheck {
    size_t size;
    uint32_t crc32;
} UmbIccCheck;

static const char *color_names[7] = {
    "Grayscale",
    NULL,
    "RGB",
    "Indexed",
    "Grayscale + Alpha",
    NULL,
    "RGB + Alpha",
};

static const int color_channels[7] = {
    1, 0, 3, 3, 2, 0, 4,
};

static const uint8_t png_signature[8] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
};

static const UmbPngChunk default_srgb = {
    .chunk_size = 13,
    .tag = tag_sRGB,
    .data = (uint8_t[]){1},
    .data_size = 1,
    .crc32 = 0xd9c92c7f,
    .offset = 12,
};

static const uint32_t strip_chunks[8] = {
    tag_bKGD, tag_eXIf, tag_pHYs, tag_sPLT,
    tag_tIME, tag_tEXt, tag_zTXt, tag_iTXt,
};

static const UmbIccCheck known_srgb_profiles[] = {
    /* GIMP built-in sRGB */
    {672, 0x07b94f91}, {672, 0x103c272a}, {672, 0x16c98593}, {672, 0x1d533259},
    {672, 0x3085a3ae}, {672, 0x36669045}, {672, 0x41ad7657}, {672, 0x7e1f1d56},
    {672, 0xe077ec7d}, {672, 0xe5aa80d5}, {672, 0xec7778c0}, {672, 0x630a527d},
    /* libjxl synthesized sRGB */
    {536, 0x1b34acea},
    /* ColorSync 4.3 sRGB ICC Profile */
    {20420, 0x0906b828},
    /* ICC official sRGB v4 Preference */
    {60960, 0xbbef7812},
    /* ICC official sRGB v4 Preference Display Class */
    {60988, 0x306fd8ae},
    /* ICC official sRGB v4 Appearance */
    {63868, 0x8726d21c},
    /* ICC official v2 2014 sRGB */
    {3024, 0x991713d0},
    /* krita default sRGB */
    {9080, 0x0ee2c1e3},
};

static inline uint32_t tag_array_to_uint32(const uint8_t *tag) {
    uint32_t ret = tag[0];
    for (int i = 1; i < 4; i++)
        ret = (ret << 8) | tag[i];
    return ret;
}

static inline void uint32_to_tag_array(uint8_t *tag, uint32_t made) {
    for (int i = 0; i < 4; i++)
        tag[i] = (made >> (24 - (8 * i))) & 0xFF;
}

static UmbPngChunk *scan_chunk(FILE *in, const UmbPngChunk *last, char **error) {
    size_t read;
    uint8_t tag[4];
    UmbPngChunk *chunk = calloc(1, sizeof(UmbPngChunk));

    if (!chunk) {
        *error = "Allocation failed";
        return NULL;
    }

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->data_size = tag_array_to_uint32(tag);

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->tag = tag_array_to_uint32(tag);

    if (fseek(in, chunk->data_size, SEEK_CUR) < 0)
        goto fail;

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->crc32 = tag_array_to_uint32(tag);

    chunk->chunk_size = 12 + chunk->data_size;
    chunk->offset = last ? last->offset + last->chunk_size : 8;

    return chunk;

fail:
    if (feof(in)) {
        *error = NULL;
    }  else {
        perror(*error);
        *error = "Error reading chunk";
    }
    freep(chunk);
    return NULL;
}

static int read_chunk(FILE *in, UmbPngChunk *chunk, char **error) {
    int ret;
    uint8_t tag[4];
    size_t total = 0;
    uint32_t crc;

    uint32_to_tag_array(tag, chunk->tag);
    crc = crc32_z(0, tag, 4);

    if (chunk->data_size)
        chunk->data = malloc(chunk->data_size);
    if (chunk->data_size && !chunk->data) {
        fprintf(stderr, "Allocation failed\n");
        return -1;
    }

    if (chunk->data_size) {
        ret = fseek(in, chunk->offset + 8, SEEK_SET);
        if (ret < 0)
            goto fail;
    }

    while (total < chunk->data_size) {
        size_t read = fread(chunk->data + total, 1, chunk->data_size - total, in);
        if (!read)
            goto fail;
        crc = crc32_z(crc, chunk->data + total, read);
        total += read;
    }

    if (crc != chunk->crc32) {
        fprintf(stderr, "Warning: computed CRC32 %08x does not match read CRC32 %08x\n", crc, chunk->crc32);
        chunk->crc32 = crc;
    }

    return 0;

fail:
    perror(*error);
    *error = "Error reading chunk data";
    freep(chunk->data);
    return -1;
}

static int write_chunk(FILE *out, const UmbPngChunk *chunk, char **error) {
    uint8_t tag[4];
    size_t count;
    size_t total = 0;

    uint32_to_tag_array(tag, chunk->data_size);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    uint32_to_tag_array(tag, chunk->tag);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    while (total < chunk->data_size) {
        count = fwrite(chunk->data + total, 1, chunk->data_size - total, out);
        if (!count)
            goto fail;
        total += count;
    }

    uint32_to_tag_array(tag, chunk->crc32);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    return 0;

fail:
    perror(*error);
    *error = "Error writing chunk data";
    return -1;
}

static int checksum_iccp(const UmbPngChunk *iccp, UmbIccCheck *check, char **error) {
    int ret;
    uint8_t outbuf[4096];
    uint32_t crc = crc32_z(0, Z_NULL, 0);
    z_stream strm = { 0 };
    size_t max_len = iccp->data_size - 2;
    size_t name_len;
    size_t total_size = 0;

    if (iccp->data_size < 4)
        goto fail;

    if (max_len > 79)
        max_len = 79;

    name_len = strnlen((const char *)iccp->data, max_len);

    ret = inflateInit(&strm);
    if (ret != Z_OK)
        goto fail;

    if (*(iccp->data + name_len + 1))
        goto fail;

    strm.next_in = iccp->data + name_len + 2;
    strm.avail_in = iccp->data_size - name_len - 2;

    do {
        size_t have;
        strm.next_out = outbuf;
        strm.avail_out = sizeof(outbuf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            goto fail;
        have = sizeof(outbuf) - strm.avail_out;
        crc = crc32_z(crc, outbuf, have);
        total_size += have;
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    check->crc32 = crc;
    check->size = total_size;

    return 0;

fail:
    inflateEnd(&strm);
    *error = "Error analyzing iCCP chunk data";
    return -1;
}

static int parse_ihdr(const UmbPngChunk *ihdr, UmbPngScanData *data, char **error) {

    if (ihdr->data_size != 13) {
        *error = "Illegal IHDR chunk size";
        return -1;
    }

    data->width = tag_array_to_uint32(ihdr->data);
    data->height = tag_array_to_uint32(ihdr->data + 4);
    data->depth = ihdr->data[8];
    data->color = ihdr->data[9];
    if (ihdr->data[10]) {
        *error = "Illegal Compression Method";
        return -1;
    }
    if (ihdr->data[11]) {
        *error = "Illegal filter method";
        return -1;
    }

    if (ihdr->data[12] > 1) {
        *error = "Illegal interlace method";
        return -1;
    }

    switch (data->color) {
        case COLOR_INDEXED:
        case COLOR_GRAY:
            if (data->depth == 1 || data->depth == 2 || data->depth == 4)
                break;
        case COLOR_TRUE:
        case COLOR_GRAY_A:
        case COLOR_RGBA:
            if (data->depth != 8 && data->depth != 16 ||
                    data->depth == 16 && data->color == COLOR_INDEXED) {
                *error = "Illegal bit depth";
                return -1;
            }
            break;
        default:
            *error = "Illegal color type";
            return -1;
    }

    return 0;
}

/** frees everything except the base node */
static void free_chain(UmbPngChunkChain *file) {
    UmbPngChunkChain *prev = file;
    if (!file)
        return;
    do {
        prev = file;
        file = file->next;
    } while (file);
    file = prev;

    while (file) {
        if (file->chunk)
            freep(file->chunk->data);
        freep(file->chunk);
        file = file->prev;
        if (file)
            freep(file->next);
    }
}

int main(int argc, char *argv[]) {
    int ret = 0;
    const char *input = argc > 1 ? argv[1] : "-";
    const char *output = argc > 2 ? argv[2] : NULL;
    FILE *in = NULL;
    FILE *out = NULL;
    uint8_t sig[8];
    size_t count;
    UmbPngChunkChain png_file = { 0 };
    UmbPngChunkChain *curr_chain = &png_file;
    UmbPngScanData data = { 0 };
    
    if (!strcmp("-", input))
        in = stdin;
    else
        in = fopen(input, "r");
    if (!in) {
        perror(argv[0]);
        ret = 1;
        goto flush;
    }

    count = fread(sig, 8, 1, in);
    if (!count) {
        if (ferror(in))
            perror(argv[0]);
        else if (feof(in))
            fprintf(stderr, "%s: Premature end of file\n", argv[0]);
        ret = 2;
        goto flush;
    }

    if (memcmp(sig, png_signature, 8)) {
        fprintf(stderr, "%s: %s: Invalid PNG signature\n", argv[0], input);
        ret = 2;
        goto flush;
    }

    fprintf(stderr, "PNG signature found\n");

    while (1) {
        char *error = argv[0];
        uint8_t tag[5] = { 0 };
        if (!curr_chain->chunk) {
            curr_chain->chunk = scan_chunk(in, NULL, &error);
            if (!curr_chain->chunk) {
                if (!error)
                    break;
                fprintf(stderr, "%s: %s\n", argv[0], error);
                ret = 2;
                goto flush;
            }
        } else {
            UmbPngChunkChain *next = calloc(1, sizeof(UmbPngChunkChain));
            if (!next) {
                fprintf(stderr, "%s: Allocation failure\n", argv[0]);
                ret = 2;
                goto flush;
            }
            curr_chain->next = next;
            next->prev = curr_chain;
            curr_chain = next;
            curr_chain->chunk = scan_chunk(in, curr_chain->prev->chunk, &error);
            if (!curr_chain->chunk) {
                if (curr_chain->prev)
                    curr_chain->prev->next = NULL;
                freep(curr_chain);
                if (!error)
                    break;
                fprintf(stderr, "%s: %s\n", argv[0], error);
                ret = 2;
                goto flush;
            }
        }
        switch (curr_chain->chunk->tag) {
        case tag_PLTE:
            data.have_plte = 1;
            break;
        case tag_cICP:
            data.have_cicp = 1;
            break;
        case tag_sRGB:
            data.have_srgb = 1;
            break;
        case tag_iCCP:
            data.have_iccp = 1;
            break;
        case tag_gAMA:
        case tag_cHRM:
            data.have_gama_chrm = 1;
            break;
        }
        uint32_to_tag_array(tag, curr_chain->chunk->tag);
        fprintf(stderr, "Chunk: %s, Size: %u, Offset: %llu, CRC32: %08x\n",
            tag, curr_chain->chunk->chunk_size, (long long unsigned)curr_chain->chunk->offset, curr_chain->chunk->crc32);
    }

    for (curr_chain = &png_file; curr_chain; curr_chain = curr_chain->next) {
        char *error = argv[0];
        ret = read_chunk(in, curr_chain->chunk, &error);
        if (ret < 0)
            goto flush;
        if (curr_chain->chunk->tag == tag_iCCP) {
            UmbIccCheck check;
            ret = checksum_iccp(curr_chain->chunk, &check, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv[0], error);
                continue;
            }
            fprintf(stderr, "ICC Profile Length: %llu, Checksum: %08x\n", (long long unsigned)check.size, check.crc32);
            for (int i = 0; i < sizeof(known_srgb_profiles)/sizeof(known_srgb_profiles[0]); i++) {
                if (check.size == known_srgb_profiles[i].size && check.crc32 == known_srgb_profiles[i].crc32) {
                    data.icc_is_srgb = 1;
                    data.have_iccp = 0;
                    data.have_srgb = 1;
                    fprintf(stderr, "ICC profile matches known sRGB profile\n");
                }
            }
        }
        if (curr_chain->chunk->tag == tag_IHDR) {
            ret = parse_ihdr(curr_chain->chunk, &data, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv[0], error);
                continue;
            }
            fprintf(stderr, "Size: %" PRIu32 "x%" PRIu32 ", Color: %d-bit %s\n", data.width, data.height,
                data.depth, color_names[data.color]);
        }
        if (curr_chain->chunk->tag == tag_sBIT) {
            if (curr_chain->chunk->data_size != color_channels[data.color]) {
                fprintf(stderr, "%s: Warning: Illegal sBIT chunk\n", argv[0]);
                continue;
            }
            for (int i = 0; i < color_channels[data.color]; i++)
                data.sbit[i] = curr_chain->chunk->data[i];
        }
    }

    if (!output)
        goto flush;

    fclose(in);
    in = NULL;

    if (!strcmp("-", output))
        out = stdout;
    else
        out = fopen(output, "w");
    if (!out) {
        perror(argv[0]);
        ret = 1;
        goto flush;
    }

    count = fwrite(png_signature, 8, 1, out);
    if (!count) {
        perror(argv[0]);
        ret = 2;
        goto flush;
    }

    curr_chain = &png_file;
    for (curr_chain = &png_file; curr_chain; curr_chain = curr_chain->next) {
        char *error = argv[0];
        int skip = 0;
        uint8_t tag[5] = { 0 };
        for (int i = 0; i < sizeof(strip_chunks)/sizeof(strip_chunks[0]); i++) {
            if (strip_chunks[i] == curr_chain->chunk->tag) {
                skip = 1;
                break;
            }
        }
        if (curr_chain->chunk->tag == tag_hIST && !data.have_plte)
            skip = 1;
        if ((curr_chain->chunk->tag == tag_cHRM || curr_chain->chunk->tag == tag_gAMA)
                && (data.have_cicp || data.have_iccp || data.have_srgb))
            skip = 1;
        if (curr_chain->chunk->tag == tag_sRGB && (data.have_iccp || data.icc_is_srgb))
            skip = 1;
        /* not strictly spec compliant but cICP and sRGB both present is very likely just sRGB */
        if (curr_chain->chunk->tag == tag_cICP && !data.have_iccp && data.have_srgb)
            skip = 1;
        if (curr_chain->chunk->tag == tag_iCCP && data.icc_is_srgb)
            skip = 1;
        if (curr_chain->chunk->tag == tag_sBIT) {
            skip = 1;
            for (int i = 0; i < color_channels[data.color]; i++) {
                if (data.sbit[i] != data.depth) {
                    skip = 0;
                    break;
                }
            }
        }
        if (skip) {
            uint32_to_tag_array(tag, curr_chain->chunk->tag);
            fprintf(stderr, "Stripping chunk: %s\n", tag);
            continue;
        } else {
            ret = write_chunk(out, curr_chain->chunk, &error);
            if (ret < 0)
                goto flush;
        }
        if (curr_chain->chunk->tag == tag_IHDR && (data.icc_is_srgb ||
                !data.have_cicp && !data.have_srgb && !data.have_iccp && !data.have_gama_chrm)) {
            fprintf(stderr, "Inserting default sRGB chunk\n");
            ret = write_chunk(out, &default_srgb, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: %s\n", argv[0], error);
                goto flush;
            }
        }
    }

flush:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    free_chain(&png_file);
    return ret;
}
