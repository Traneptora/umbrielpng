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
#include <strings.h>

#include <zlib.h>

#define maketag(a,b,c,d) ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) |\
                         (((uint32_t)(c)) << 8) | (uint32_t)(d))
#define abs(a) ((a) < 0 ? -(a) : (a))
#define within(a,b,tolerance) (abs((a)-(b)) <= (tolerance))

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
    UmbPngChunk chunk;
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

enum UmbPngColorPrim {
    PRIM_RESERVED0,
    PRIM_BT709,
    PRIM_UNSPECIFIED,
    PRIM_RESERVED3,
    PRIM_BT470M,
    PRIM_BT470BG,
    PRIM_BT601,
    PRIM_SMPTE_ST_240,
    PRIM_FILM_C,
    PRIM_BT2020,
    PRIM_SMPTE_ST_428_1,
    PRIM_SMPTE_RP_431_2,
    PRIM_SMPTE_EG_432_1,
    PRIM_H273_22 = 22,
};

enum UmbPngColorTrc {
    TRC_RESERVED0,
    TRC_BT709,
    TRC_UNSPECIFIED,
    TRC_RESERVED3,
    TRC_GAMMA22,
    TRC_GAMMA28,
    TRC_BT601,
    TRC_SMPTE_ST_240,
    TRC_LINEAR,
    TRC_LOGARITHMIC_100,
    TRC_LOGARITHMIC_100_ROOT10,
    TRC_IEC61966_2_4,
    TRC_BT1361,
    TRC_SRGB,
    TRC_BT2020_10,
    TRC_BT2020_12,
    TRC_SMPTE_ST_2084_PQ,
    TRC_SMPTE_ST_428_1,
    TRC_ARIB_STD_B67_HLG,
};

typedef struct UmbPngScanData {
    int have_cicp;
    int have_iccp;
    int have_srgb;
    int have_chrm;
    int have_gama;
    int have_plte;
    int icc_is_srgb;
    int cicp_is_srgb;
    int chrm_is_srgb;

    uint32_t width;
    uint32_t height;
    int depth;
    enum UmbPngColorType color;

    int sbit[4];
} UmbPngScanData;

typedef struct UmbIccProfile {
    size_t size;
    uint8_t *icc_data;
} UmbIccProfile;

typedef struct UmbPngOptions {
    int verbose;
    int fix;
    const char *argv0;
    const char *input;
    const char *output;
    int force_cicp;
    int forced_prim;
    int forced_trc;
} UmbPngOptions;

static const char *const color_names[7] = {
    "Grayscale",
    "",
    "RGB",
    "Indexed",
    "Grayscale + Alpha",
    "",
    "RGB + Alpha",
};

static const int color_channels[7] = {
    1, 0, 3, 3, 2, 0, 4,
};

static const uint8_t png_signature[8] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
};

static const char *const prim_names[24] = {
    [PRIM_RESERVED0] = "Reserved0",
    [PRIM_BT709] = "BT.709",
    [PRIM_UNSPECIFIED] = "Unspecified",
    [PRIM_RESERVED3] = "Reserved3",
    [PRIM_BT470M] = "BT470M",
    [PRIM_BT470BG] = "BT470BG",
    [PRIM_BT601] = "BT.601",
    [PRIM_SMPTE_ST_240] = "SMPTE ST 240",
    [PRIM_FILM_C] = "Film Illuminant C",
    [PRIM_BT2020] = "BT.2020",
    [PRIM_SMPTE_ST_428_1] = "SMPTE ST 428",
    [PRIM_SMPTE_RP_431_2] = "SMPTE RP 431-2",
    [PRIM_SMPTE_EG_432_1] = "SMPTE EG 432-1",
    [13] = "", [14] = "", [15] = "", [16] = "", [17] = "",
    [18] = "", [19] = "", [20] = "", [21] = "",
    [PRIM_H273_22] = "H.273 22",
    [23] = NULL,
};

static const char *const trc_names[20] = {
    [TRC_RESERVED0] = "Reserved0",
    [TRC_BT709] = "BT.709",
    [TRC_UNSPECIFIED] = "Unspecified",
    [TRC_RESERVED3] = "Reserved3",
    [TRC_GAMMA22] = "Gamma 2.2",
    [TRC_GAMMA28] = "Gamma 2.8",
    [TRC_BT601] = "BT.601",
    [TRC_SMPTE_ST_240] = "SMPTE ST 240",
    [TRC_LINEAR] = "Linear",
    [TRC_LOGARITHMIC_100] = "Logarithmic 100:1",
    [TRC_LOGARITHMIC_100_ROOT10] = "Logarithmic 100sqrt(10) : 1",
    [TRC_IEC61966_2_4] = "IEC61966-2-4",
    [TRC_BT1361] = "BT.1361",
    [TRC_SRGB] = "sRGB",
    [TRC_BT2020_10] = "BT.2020 10-bit",
    [TRC_BT2020_12] = "BT.2020 12-bit",
    [TRC_SMPTE_ST_2084_PQ] = "PQ",
    [TRC_SMPTE_ST_428_1] = "SMPTE ST 428-1",
    [TRC_ARIB_STD_B67_HLG] = "HLG",
    [19] = NULL,
};

static const UmbPngChunk default_srgb_chunk = {
    .chunk_size = 13,
    .tag = tag_sRGB,
    .data = (uint8_t[]){1},
    .data_size = 1,
    .crc32 = 0xd9c92c7f,
    .offset = 12,
};

static const uint32_t default_chrm_data[8] = {
    31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000,
};

static const uint32_t strip_chunks[8] = {
    tag_bKGD, tag_eXIf, tag_pHYs, tag_sPLT,
    tag_tIME, tag_tEXt, tag_zTXt, tag_iTXt,
};

static inline uint32_t rbe32(const uint8_t *tag) {
   return maketag(tag[0],tag[1],tag[2],tag[3]);
}

static inline void wbe32(uint8_t *tag, uint32_t be32) {
    tag[0] = (be32 >> 24) & 0xFF;
    tag[1] = (be32 >> 16) & 0xFF;
    tag[2] = (be32 >> 8) & 0xFF;
    tag[3] = be32 & 0xFF;
}

static int lookup_array(const char *const *array, const char *lookup) {
    for (int i = 0; array[i]; i++) {
        if (!strcasecmp(array[i], lookup))
            return i;
    }
    return -1;
}

static int scan_chunk(FILE *in, UmbPngChunk *chunk, const UmbPngChunk *last, const char **error) {
    size_t read;
    uint8_t tag[4];

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->data_size = rbe32(tag);

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->tag = rbe32(tag);

    if (fseek(in, chunk->data_size, SEEK_CUR) < 0)
        goto fail;

    read = fread(tag, 4, 1, in);
    if (!read)
        goto fail;
    chunk->crc32 = rbe32(tag);

    chunk->chunk_size = 12 + chunk->data_size;
    chunk->offset = last ? last->offset + last->chunk_size : 8;

    return 0;

fail:
    if (feof(in)) {
        *error = NULL;
    }  else {
        perror(*error);
        *error = "Error reading chunk";
    }

    return -1;
}

static int read_chunk(FILE *in, UmbPngChunk *chunk, const char **error) {
    int ret;
    uint8_t tag[4];
    size_t total = 0;
    uint32_t crc;

    wbe32(tag, chunk->tag);
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

static int write_chunk(FILE *out, const UmbPngChunk *chunk, const char **error) {
    uint8_t tag[4];
    size_t count;
    size_t total = 0;

    wbe32(tag, chunk->data_size);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    wbe32(tag, chunk->tag);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    while (total < chunk->data_size) {
        count = fwrite(chunk->data + total, 1, chunk->data_size - total, out);
        if (!count)
            goto fail;
        total += count;
    }

    wbe32(tag, chunk->crc32);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    return 0;

fail:
    perror(*error);
    *error = "Error writing chunk data";
    return -1;
}

static int inflate_iccp(const UmbPngChunk *iccp, UmbIccProfile *profile, const char **error) {
    int ret;
    z_stream strm = { 0 };
    size_t max_len = iccp->data_size - 2;
    size_t name_len;
    size_t total_size = 0;
    size_t icc_buffer_size = 4096;
    void *temp;

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

    temp = realloc(profile->icc_data, icc_buffer_size);
    if (!temp)
        goto fail;
    profile->icc_data = temp;

    strm.next_in = iccp->data + name_len + 2;
    strm.avail_in = iccp->data_size - name_len - 2;

    do {
        size_t have;
        if (icc_buffer_size <= total_size) {
            icc_buffer_size *= 2;
            temp = realloc(profile->icc_data, icc_buffer_size);
            if (!temp)
                goto fail;
            profile->icc_data = temp;
        }
        strm.next_out = profile->icc_data + total_size;
        strm.avail_out = icc_buffer_size - total_size;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            goto fail;
        have = icc_buffer_size - total_size - strm.avail_out;
        total_size += have;
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    profile->size = total_size;

    return 0;

fail:
    inflateEnd(&strm);
    freep(profile->icc_data);
    *error = "Error analyzing iCCP chunk data";
    return -1;
}

static int matches_srgb(const UmbIccProfile *profile, const char **error) {
    uint8_t *header;
    uint32_t tag_count;
    uint8_t tag[5] = { 0 };
    int32_t wp[3] = { 0 };
    int32_t red[3] = { 0 };
    int32_t green[3] = { 0 };
    int32_t blue[3] = { 0 };

    if (profile->size < 144)
        return 0;

    if (rbe32(profile->icc_data) != profile->size) {
        *error = "ICC profile size mismatch";
        return 0;
    }

    tag_count = rbe32(profile->icc_data + 128);
    header = profile->icc_data + 132;

    for (uint32_t i = 0; i < tag_count; i++, header += 12) {
        uint32_t sig, offset, size;
        if (header + 12 > profile->icc_data + profile->size)
            return 0;
        sig = rbe32(header);
        offset = rbe32(header + 4);
        size = rbe32(header + 8);
        if (offset + size > profile->size)
            return 0;
        wbe32(tag, sig);
        if (sig == maketag('w','t','p','t')) {
            if (size != 20)
                return 0;
            sig = rbe32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            wp[0] = rbe32(profile->icc_data + offset + 8);
            wp[1] = rbe32(profile->icc_data + offset + 12);
            wp[2] = rbe32(profile->icc_data + offset + 16);
        } else if (sig == maketag('r','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = rbe32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            red[0] = rbe32(profile->icc_data + offset + 8);
            red[1] = rbe32(profile->icc_data + offset + 12);
            red[2] = rbe32(profile->icc_data + offset + 16);
        } else if (sig == maketag('g','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = rbe32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            green[0] = rbe32(profile->icc_data + offset + 8);
            green[1] = rbe32(profile->icc_data + offset + 12);
            green[2] = rbe32(profile->icc_data + offset + 16);
        } else if (sig == maketag('b','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = rbe32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            blue[0] = rbe32(profile->icc_data + offset + 8);
            blue[1] = rbe32(profile->icc_data + offset + 12);
            blue[2] = rbe32(profile->icc_data + offset + 16);
        } else if (sig == maketag('r','T','R','C') || sig == maketag('g','T','R','C') ||
                   sig == maketag('b','T','R','C')) {
            int32_t g, a, b, c, d, e = 0, f = 0;
            if (size < 12)
                return 0;
            sig = rbe32(profile->icc_data + offset);
            if (sig != maketag('p','a','r','a'))
                return 0;
            sig = rbe32(profile->icc_data + offset + 8);
            if (sig != 0x30000 && sig != 0x40000)
                return 0;
            if (size != 8 + (sig >> 13))
                return 0;
            g = rbe32(profile->icc_data + offset + 12);
            a = rbe32(profile->icc_data + offset + 16);
            b = rbe32(profile->icc_data + offset + 20);
            c = rbe32(profile->icc_data + offset + 24);
            d = rbe32(profile->icc_data + offset + 28);
            if (sig == 0x40000) {
                e = rbe32(profile->icc_data + offset + 32);
                f = rbe32(profile->icc_data + offset + 36);
            }
            if (!within(g,157286,32) || !within(a,62119,32) || !within(b,3416,32) ||
                !within(c,5072,32) || !within(d,2651,32) || !within(e,0,32) || !within(f,0,32))
                return 0;
        }
    }

    if (!within(wp[0],63190,32) || !within(wp[1],65536,32) || !within(wp[2],54061,32))
        return 0;
    if (!within(red[0],28564,32) || !within(red[1],14574,32) || !within(red[2],912,32))
        return 0;
    if (!within(green[0],25253,32) || !within(green[1],46992,32) || !within(green[2],6366,32))
        return 0;
    if (!within(blue[0],9373,32) || !within(blue[1],3971,32) || !within(blue[2],46782,32))
        return 0;

    return 1;
}

static int parse_ihdr(const UmbPngChunk *ihdr, UmbPngScanData *data, const char **error) {

    if (ihdr->data_size != 13) {
        *error = "Illegal IHDR chunk size";
        return -1;
    }

    data->width = rbe32(ihdr->data);
    data->height = rbe32(ihdr->data + 4);
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
            if ((data->depth != 8 && data->depth != 16) ||
                    (data->depth == 16 && data->color == COLOR_INDEXED)) {
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

static int write_idats(FILE *out, const UmbPngChunkChain **initial, const char **error) {
    const UmbPngChunkChain *chain = *initial;
    const UmbPngChunkChain *final = NULL;
    uint64_t total_size = 0;
    uint32_t crc = 0x35af061e; // crc32_z(0, "IDAT", 4);
    uint8_t tag[4];
    size_t count;

    for (chain = *initial; chain->chunk.tag == tag_IDAT; chain = chain->next) {
        total_size += chain->chunk.data_size;
        if (total_size >= INT32_MAX) {
            total_size -= chain->chunk.data_size;
            final = chain->prev;
            break;
        }
        final = chain;
    }

    wbe32(tag, total_size);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;
    count = fwrite("IDAT", 4, 1, out);
    if (!count)
        goto fail;

    for (chain = *initial; chain && chain->prev != final; chain = chain->next) {
        size_t tot = 0;
        while (tot < chain->chunk.data_size) {
            count = fwrite(chain->chunk.data + tot, 1, chain->chunk.data_size - tot, out);
            if (!count)
                goto fail;
            crc = crc32_z(crc, chain->chunk.data + tot, count);
            tot += count;
        }
    }

    wbe32(tag, crc);
    count = fwrite(tag, 4, 1, out);
    if (!count)
        goto fail;

    *initial = final->next;

    return 0;

fail:
    perror(*error);
    *error = "Error writing chunk data";
    return -1;
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
        freep(file->chunk.data);
        file = file->prev;
        if (file)
            freep(file->next);
    }
}

static int process_png(const char *input, const char *output, const UmbPngOptions *options) {
    int ret = 0;
    FILE *in = NULL;
    FILE *out = NULL;
    uint8_t sig[8];
    size_t count;
    size_t idat_count = 0;
    UmbPngChunkChain png_file = { 0 };
    UmbPngChunkChain *curr_chain = NULL;
    UmbPngChunkChain *initial_idat = NULL;
    UmbPngScanData data = { 0 };
    int default_srgb = 0;
    const char *argv0 = options->argv0;

    if (!strcmp("-", input))
        in = stdin;
    else
        in = fopen(input, "r");
    if (!in) {
        perror(argv0);
        ret = 1;
        goto flush;
    }

    count = fread(sig, 8, 1, in);
    if (!count) {
        if (ferror(in))
            perror(argv0);
        else if (feof(in))
            fprintf(stderr, "%s: Premature end of file\n", argv0);
        ret = 2;
        goto flush;
    }

    if (memcmp(sig, png_signature, 8)) {
        fprintf(stderr, "%s: %s: Invalid PNG signature\n", argv0, input);
        ret = 2;
        goto flush;
    }

    fprintf(stderr, "PNG signature found: %s\n", input);

    while (1) {
        const char *error = argv0;
        uint8_t tag[5] = { 0 };
        if (!curr_chain) {
            curr_chain = &png_file;
            ret = scan_chunk(in, &curr_chain->chunk, NULL, &error);
            if (ret < 0) {
                if (!error)
                    break;
                fprintf(stderr, "%s: %s\n", argv0, error);
                ret = 2;
                goto flush;
            }
        } else {
            UmbPngChunkChain *next = calloc(1, sizeof(UmbPngChunkChain));
            if (!next) {
                fprintf(stderr, "%s: Allocation failure\n", argv0);
                ret = 2;
                goto flush;
            }
            curr_chain->next = next;
            next->prev = curr_chain;
            curr_chain = next;
            ret = scan_chunk(in, &curr_chain->chunk, &curr_chain->prev->chunk, &error);
            if (ret < 0) {
                if (curr_chain->prev)
                    curr_chain->prev->next = NULL;
                freep(curr_chain);
                if (!error)
                    break;
                fprintf(stderr, "%s: %s\n", argv0, error);
                ret = 2;
                goto flush;
            }
        }
        switch (curr_chain->chunk.tag) {
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
            data.have_gama = 1;
            break;
        case tag_cHRM:
            data.have_chrm = 1;
            break;
        }
        if (curr_chain->chunk.tag != tag_IDAT || !idat_count) {
            if (idat_count > 1)
                fprintf(stderr, "Chunk: %llu more IDAT chunks\n", (long long unsigned)idat_count-1);
            wbe32(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Chunk: %s, Size: %u, Offset: %llu, CRC32: %08x\n",
                tag, curr_chain->chunk.chunk_size, (long long unsigned)curr_chain->chunk.offset,
                curr_chain->chunk.crc32);
            idat_count = curr_chain->chunk.tag == tag_IDAT ? idat_count + 1 : 0;
        } else {
            idat_count++;
        }
    }

    for (curr_chain = &png_file; curr_chain; curr_chain = curr_chain->next) {
        const char *error = argv0;
        ret = read_chunk(in, &curr_chain->chunk, &error);
        if (ret < 0)
            goto flush;
        if (curr_chain->chunk.tag == tag_iCCP) {
            UmbIccProfile profile = { 0 };
            ret = inflate_iccp(&curr_chain->chunk, &profile, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv0, error);
                freep(profile.icc_data);
                continue;
            }
            if (options->verbose)
                fprintf(stderr, "ICC Profile Length: %llu\n", (long long unsigned)profile.size);
            ret = matches_srgb(&profile, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv0, error);
                freep(profile.icc_data);
                continue;
            }
            if (ret) {
                fprintf(stderr, "ICC profile matches sRGB profile\n");
                data.icc_is_srgb = 1;
            }
            freep(profile.icc_data);
        }
        if (curr_chain->chunk.tag == tag_IHDR) {
            ret = parse_ihdr(&curr_chain->chunk, &data, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv0, error);
                continue;
            }
            fprintf(stderr, "Size: %" PRIu32 "x%" PRIu32 ", Color: %d-bit %s\n", data.width, data.height,
                data.depth, color_names[data.color]);
        } else if (curr_chain->chunk.tag == tag_sBIT) {
            if (curr_chain->chunk.data_size != color_channels[data.color]) {
                fprintf(stderr, "%s: Warning: Illegal sBIT chunk\n", argv0);
                continue;
            }
            if (options->verbose)
                fprintf(stderr, "sBIT: %d", curr_chain->chunk.data[0]);
            for (int i = 0; i < color_channels[data.color]; i++) {
                data.sbit[i] = curr_chain->chunk.data[i];
                if (options->verbose && i)
                    fprintf(stderr, ", %d", data.sbit[i]);
            }
            if (options->verbose)
                fprintf(stderr, "\n");
        } else if (curr_chain->chunk.tag == tag_cICP) {
            if (curr_chain->chunk.data_size != 4) {
                fprintf(stderr, "%s: Warning: Illegal cICP size\n", argv0);
                continue;
            }
            if (rbe32(curr_chain->chunk.data) == 0x010d0001) {
                fprintf(stderr, "cICP represents sRGB space\n");
                data.cicp_is_srgb = 1;
            }
            if (options->verbose) {
                const char *names[4];
                names[0] = curr_chain->chunk.data[0] < sizeof(prim_names)/sizeof(*prim_names)
                    ? prim_names[curr_chain->chunk.data[0]] : NULL;
                names[1] = curr_chain->chunk.data[1] < sizeof(trc_names)/sizeof(*trc_names)
                    ? trc_names[curr_chain->chunk.data[1]] : NULL;
                names[2] = curr_chain->chunk.data[2] == 0 ? "RGB" : NULL;
                names[3] = curr_chain->chunk.data[3] == 1 ? "Full" : curr_chain->chunk.data[3] == 0 ? "Limited" : NULL;
                for (int i = 0; i < 4; i++) {
                    if (!names[i])
                        names[i] = "INVALID";
                }
                fprintf(stderr, "cICP: %s, %s, %s, %s\n", names[0], names[1], names[2], names[3]);
            }
        } else if (curr_chain->chunk.tag == tag_cHRM) {
            uint32_t values[8];
            if (curr_chain->chunk.data_size != 32) {
                fprintf(stderr, "%s: Warning: Illegal cHRM size\n", argv0);
                continue;
            }
            for (int i = 0; i < 8; i++)
                values[i] = rbe32(curr_chain->chunk.data + (4 * i));
            if (!memcmp(values, default_chrm_data, sizeof(values))) {
                data.chrm_is_srgb = 1;
                fprintf(stderr, "cHRM matches sRGB space\n");
            } else if (options->verbose) {
                fprintf(stderr, "cHRM: wp: %u, %u, r: %u, %u, g: %u, %u, b: %u, %u\n", values[0], values[1],
                    values[2], values[3], values[4], values[5], values[6], values[7]);
            }
        } else if (curr_chain->chunk.tag == tag_gAMA) {
            if (curr_chain->chunk.data_size != 4) {
                fprintf(stderr, "%s: Warning: Illegal gAMA size\n", argv0);
                continue;
            }
            if (options->verbose)
                fprintf(stderr, "gAMA: %d\n", rbe32(curr_chain->chunk.data));
        }
    }

    fclose(in);
    in = NULL;

    if (!output) {
        if (!options->fix)
            goto flush;
        output = input;
    }

    if (!strcmp("-", output))
        out = stdout;
    else
        out = fopen(output, "w");
    if (!out) {
        perror(argv0);
        ret = 1;
        goto flush;
    }

    count = fwrite(png_signature, 8, 1, out);
    if (!count) {
        perror(argv0);
        ret = 2;
        goto flush;
    }

    if (options->force_cicp) {
        data.have_cicp = 1;
        if (options->forced_prim == PRIM_BT709 && options->forced_trc == TRC_SRGB)
            data.cicp_is_srgb = 1;
    }

    curr_chain = &png_file;
    default_srgb = data.cicp_is_srgb || (!data.have_cicp && (data.icc_is_srgb ||
        (!data.have_iccp && !data.have_srgb && !data.have_gama &&
        (!data.have_chrm || data.chrm_is_srgb))));
    for (curr_chain = &png_file; curr_chain; curr_chain = curr_chain->next) {
        const char *error = argv0;
        int skip = 0;
        uint8_t tag[5] = { 0 };
        for (int i = 0; i < sizeof(strip_chunks)/sizeof(strip_chunks[0]); i++) {
            if (strip_chunks[i] == curr_chain->chunk.tag) {
                skip = 1;
                break;
            }
        }
        if (curr_chain->chunk.tag == tag_hIST && !data.have_plte)
            skip = 1;
        if ((curr_chain->chunk.tag == tag_cHRM || curr_chain->chunk.tag == tag_gAMA)
                && (data.have_cicp || data.have_iccp || data.have_srgb))
            skip = 1;
        if (curr_chain->chunk.tag == tag_sRGB && (default_srgb || data.have_iccp || data.have_cicp))
            skip = 1;
        if (curr_chain->chunk.tag == tag_iCCP && (default_srgb || data.have_cicp))
            skip = 1;
        if (curr_chain->chunk.tag == tag_cICP && (default_srgb || options->force_cicp))
            skip = 1;
        if (curr_chain->chunk.tag == tag_sBIT) {
            skip = 1;
            for (int i = 0; i < color_channels[data.color]; i++) {
                if (data.sbit[i] != data.depth) {
                    skip = 0;
                    break;
                }
            }
        }
        if (curr_chain->chunk.tag == tag_IDAT) {
            if (!initial_idat)
                initial_idat = curr_chain;
        } else if (initial_idat) {
            const UmbPngChunkChain *idat_chain = initial_idat;
            do {
                fprintf(stderr, "Writing chunk: IDAT\n");
                ret = write_idats(out, &idat_chain, &error);
                if (ret < 0) {
                    fprintf(stderr, "%s: %s\n", argv0, error);
                    goto flush;
                }
            } while (idat_chain && idat_chain->chunk.tag == tag_IDAT);
            initial_idat = NULL;
        }
        if (skip) {
            wbe32(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Stripping chunk: %s\n", tag);
            continue;
        } else if (curr_chain->chunk.tag != tag_IDAT) {
            wbe32(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Writing chunk: %s\n", tag);
            ret = write_chunk(out, &curr_chain->chunk, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: %s\n", argv0, error);
                goto flush;
            }
        }

        if (curr_chain->chunk.tag == tag_IHDR && default_srgb) {
            fprintf(stderr, "Inserting default sRGB chunk\n");
            ret = write_chunk(out, &default_srgb_chunk, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: %s\n", argv0, error);
                goto flush;
            }
        } else if (curr_chain->chunk.tag == tag_IHDR && options->force_cicp) {
            uint8_t cicp_data[4] = {
                options->forced_prim,
                options->forced_trc,
                0,
                1,
            };
            uint32_t crc = crc32_z(0xc7a37c8c, cicp_data, 4);
            const UmbPngChunk forced_cicp = {
                .tag = tag_cICP,
                .offset = 12,
                .data_size = 4,
                .chunk_size = 16,
                .data = cicp_data,
                .crc32 = crc,
            };
            fprintf(stderr, "Inserting forced cICP chunk\n");
            ret = write_chunk(out, &forced_cicp, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: %s\n", argv0, error);
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

static int usage(int ret, const char *argv0) {   
    fprintf(stderr, "Usage: %s [-v | --verbose] [options] [--] <png...>\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    --fix | -o <output> | --o=<output>\n");
    fprintf(stderr, "        Fix the PNG file. --fix works in place, the others use the provided output.\n");
    fprintf(stderr, "    --cicp-prim=<primaries>\n");
    fprintf(stderr, "    --cicp-trc=<transfer>\n");
    fprintf(stderr, "        Tag the output file with a cICP chunk with the provided primaries and transfer.\n");
    return ret;
}

int main(int argc, const char *argv[]) {
    int ret = 0;
    int options_done = 0;
    int awaiting = 0;
    int input_count = 0;
    UmbPngOptions options = { 0 };
    const char *output = NULL;
    const char **input = NULL;
    options.forced_prim = -1;
    options.forced_trc = -1;
    options.argv0 = argv[0];

    if (argc < 2)
        return usage(1, argv[0]);
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' && !awaiting)
            options_done = 1;
        if (options_done) {
            input = argv + i;
            input_count = argc - i;
            break;
        }
        if (awaiting) {
            output = argv[i];
            awaiting = 0;
        } else if (!strcmp("--", argv[i])) {
            options_done = 1;
        } else if (!strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i])) {
            options.verbose = 1;
        } else if (!strcmp("--fix", argv[i])) {
            options.fix = 1;
        } else if (!strncmp("--cicp-prim=", argv[i], 12)) {
            options.forced_prim = lookup_array(prim_names, argv[i] + 12);
            if (options.forced_prim < 0)
                fprintf(stderr, "%s: Illegal cICP Primaries: %s\n", argv[0], argv[i] + 12);
        } else if (!strncmp("--cicp-trc=", argv[i], 11)) {
            options.forced_trc = lookup_array(trc_names, argv[i] + 11);
            if (options.forced_trc < 0)
                fprintf(stderr, "%s: Illegal cICP Transfer Characteristics: %s\n", argv[0], argv[i] + 11);
        } else if (!strncmp("--o=", argv[i], 4)) {
            output = argv[i] + 4;
        } else if (!strcmp("-o", argv[i])) {
            awaiting = 1;
        } else if (!strcmp("--help", argv[i])) {
            return usage(0, argv[0]);
        } else {
            fprintf(stderr, "%s: Unknown Option: %s\n", argv[0], argv[i]);
            return usage(1, argv[0]);
        }
    }

    if (options.forced_prim >= 0 && options.forced_trc >= 0)
        options.force_cicp = 1;

    if (!input)
        return usage(1, argv[0]);
    for (int i = 0; i < input_count; i++)
        ret |= process_png(input[i], output, &options);

    return ret;
}
