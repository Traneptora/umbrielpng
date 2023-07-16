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

typedef struct UmbIccProfile {
    size_t size;
    uint8_t *icc_data;
} UmbIccProfile;

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

static inline uint32_t tag_array_to_uint32(const uint8_t *tag) {
   return maketag(tag[0],tag[1],tag[2],tag[3]);
}

static inline void uint32_to_tag_array(uint8_t *tag, uint32_t made) {
    for (int i = 0; i < 4; i++)
        tag[i] = (made >> (24 - (8 * i))) & 0xFF;
}

static int scan_chunk(FILE *in, UmbPngChunk *chunk, const UmbPngChunk *last, char **error) {
    size_t read;
    uint8_t tag[4];

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

static int inflate_iccp(const UmbPngChunk *iccp, UmbIccProfile *profile, char **error) {
    int ret;
    z_stream strm = { 0 };
    size_t max_len = iccp->data_size - 2;
    size_t name_len;
    size_t total_size = 0;
    size_t icc_buffer_size = 4096;

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

    profile->icc_data = realloc(profile->icc_data, icc_buffer_size);
    if (!profile->icc_data)
        goto fail;

    strm.next_in = iccp->data + name_len + 2;
    strm.avail_in = iccp->data_size - name_len - 2;

    do {
        size_t have;
        if (icc_buffer_size <= total_size) {
            icc_buffer_size *= 2;
            profile->icc_data = realloc(profile->icc_data, icc_buffer_size);
            if (!profile->icc_data)
                goto fail;
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

static int matches_srgb(UmbIccProfile *profile, char **error) {
    uint8_t *header;
    uint32_t tag_count;
    uint8_t tag[5] = { 0 };
    int32_t wp[3] = { 0 };
    int32_t red[3] = { 0 };
    int32_t green[3] = { 0 };
    int32_t blue[3] = { 0 };

    if (profile->size < 144)
        return 0;

    if (tag_array_to_uint32(profile->icc_data) != profile->size) {
        *error = "ICC profile size mismatch";
        return 0;
    }

    tag_count = tag_array_to_uint32(profile->icc_data + 128);
    header = profile->icc_data + 132;

    for (uint32_t i = 0; i < tag_count; i++, header += 12) {
        uint32_t sig, offset, size;
        if (header + 12 > profile->icc_data + profile->size)
            return 0;
        sig = tag_array_to_uint32(header);
        offset = tag_array_to_uint32(header + 4);
        size = tag_array_to_uint32(header + 8);
        if (offset + size > profile->size)
            return 0;
        uint32_to_tag_array(tag, sig);
        if (sig == maketag('w','t','p','t')) {
            if (size != 20)
                return 0;
            sig = tag_array_to_uint32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            wp[0] = tag_array_to_uint32(profile->icc_data + offset + 8);
            wp[1] = tag_array_to_uint32(profile->icc_data + offset + 12);
            wp[2] = tag_array_to_uint32(profile->icc_data + offset + 16);
        } else if (sig == maketag('r','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = tag_array_to_uint32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            red[0] = tag_array_to_uint32(profile->icc_data + offset + 8);
            red[1] = tag_array_to_uint32(profile->icc_data + offset + 12);
            red[2] = tag_array_to_uint32(profile->icc_data + offset + 16);
        } else if (sig == maketag('g','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = tag_array_to_uint32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            green[0] = tag_array_to_uint32(profile->icc_data + offset + 8);
            green[1] = tag_array_to_uint32(profile->icc_data + offset + 12);
            green[2] = tag_array_to_uint32(profile->icc_data + offset + 16);
        } else if (sig == maketag('b','X','Y','Z')) {
            if (size != 20)
                return 0;
            sig = tag_array_to_uint32(profile->icc_data + offset);
            if (sig != maketag('X','Y','Z',' '))
                return 0;
            blue[0] = tag_array_to_uint32(profile->icc_data + offset + 8);
            blue[1] = tag_array_to_uint32(profile->icc_data + offset + 12);
            blue[2] = tag_array_to_uint32(profile->icc_data + offset + 16);
        } else if (sig == maketag('r','T','R','C') || sig == maketag('g','T','R','C') ||
                   sig == maketag('b','T','R','C')) {
            if (size < 12)
                return 0;
            sig = tag_array_to_uint32(profile->icc_data + offset);
            if (sig == maketag('p','a','r','a')) {
                uint32_t type = tag_array_to_uint32(profile->icc_data + offset + 8);
                int32_t g, a, b, c, d, e = 0, f = 0;
                if (type != 0x30000 && type != 0x40000)
                    return 0;
                if (size != 8 + (type >> 13))
                    return 0;
                g = tag_array_to_uint32(profile->icc_data + offset + 12);
                a = tag_array_to_uint32(profile->icc_data + offset + 16);
                b = tag_array_to_uint32(profile->icc_data + offset + 20);
                c = tag_array_to_uint32(profile->icc_data + offset + 24);
                d = tag_array_to_uint32(profile->icc_data + offset + 28);
                if (type == 0x40000) {
                    e = tag_array_to_uint32(profile->icc_data + offset + 32);
                    f = tag_array_to_uint32(profile->icc_data + offset + 36); 
                }
                if (!within(g,157286,32) || !within(a,62119,32) || !within(b,3416,32) ||
                    !within(c,5072,32) || !within(d,2651,32) || !within(e,0,32) || !within(f,0,32))
                    return 0;
            } else {
                return 0;
            }
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

static int write_idats(FILE *out, const UmbPngChunkChain **initial, char **error) {
    const UmbPngChunkChain *chain = *initial;
    const UmbPngChunkChain *final;
    uint64_t total_size = 0;
    uint32_t crc = crc32_z(0, "IDAT", 4);
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

    uint32_to_tag_array(tag, total_size);
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

    uint32_to_tag_array(tag, crc);
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

int main(int argc, char *argv[]) {
    int ret = 0;
    const char *input = argc > 1 ? argv[1] : "-";
    const char *output = argc > 2 ? argv[2] : NULL;
    FILE *in = NULL;
    FILE *out = NULL;
    uint8_t sig[8];
    size_t count;
    size_t idat_count = 0;
    UmbPngChunkChain png_file = { 0 };
    UmbPngChunkChain *curr_chain = NULL;
    UmbPngChunkChain *initial_idat = NULL;
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
        if (!curr_chain) {
            curr_chain = &png_file;
            ret = scan_chunk(in, &curr_chain->chunk, NULL, &error);
            if (ret < 0) {
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
            ret = scan_chunk(in, &curr_chain->chunk, &curr_chain->prev->chunk, &error);
            if (ret < 0) {
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
        case tag_cHRM:
            data.have_gama_chrm = 1;
            break;
        }
        if (curr_chain->chunk.tag != tag_IDAT || !idat_count) {
            if (idat_count > 1)
                fprintf(stderr, "Chunk: %llu more IDAT chunks\n", (long long unsigned)idat_count-1);
            uint32_to_tag_array(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Chunk: %s, Size: %u, Offset: %llu, CRC32: %08x\n",
                tag, curr_chain->chunk.chunk_size, (long long unsigned)curr_chain->chunk.offset,
                curr_chain->chunk.crc32);
            idat_count = curr_chain->chunk.tag == tag_IDAT ? idat_count + 1 : 0;
        } else {
            idat_count++;
        }
    }

    for (curr_chain = &png_file; curr_chain; curr_chain = curr_chain->next) {
        char *error = argv[0];
        ret = read_chunk(in, &curr_chain->chunk, &error);
        if (ret < 0)
            goto flush;
        if (curr_chain->chunk.tag == tag_iCCP) {
            UmbIccProfile profile = { 0 };
            ret = inflate_iccp(&curr_chain->chunk, &profile, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv[0], error);
                freep(profile.icc_data);
                continue;
            }
            fprintf(stderr, "ICC Profile Length: %llu\n", (long long unsigned)profile.size);
            ret = matches_srgb(&profile, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: Warning: %s\n", argv[0], error);
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
                fprintf(stderr, "%s: Warning: %s\n", argv[0], error);
                continue;
            }
            fprintf(stderr, "Size: %" PRIu32 "x%" PRIu32 ", Color: %d-bit %s\n", data.width, data.height,
                data.depth, color_names[data.color]);
        }
        if (curr_chain->chunk.tag == tag_sBIT) {
            if (curr_chain->chunk.data_size != color_channels[data.color]) {
                fprintf(stderr, "%s: Warning: Illegal sBIT chunk\n", argv[0]);
                continue;
            }
            for (int i = 0; i < color_channels[data.color]; i++)
                data.sbit[i] = curr_chain->chunk.data[i];
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
        if (curr_chain->chunk.tag == tag_sRGB && (data.have_iccp || data.icc_is_srgb))
            skip = 1;
        /* not strictly spec compliant but cICP and sRGB both present is very likely just sRGB */
        if (curr_chain->chunk.tag == tag_cICP && !data.have_iccp && data.have_srgb)
            skip = 1;
        if (curr_chain->chunk.tag == tag_iCCP && data.icc_is_srgb)
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
                    fprintf(stderr, "%s: %s\n", argv[0], error);
                    goto flush;
                }
            } while (idat_chain && idat_chain->chunk.tag == tag_IDAT);
            initial_idat = NULL;
        }

        if (skip) {
            uint32_to_tag_array(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Stripping chunk: %s\n", tag);
            continue;
        } else if (curr_chain->chunk.tag != tag_IDAT) {
            uint32_to_tag_array(tag, curr_chain->chunk.tag);
            fprintf(stderr, "Writing chunk: %s\n", tag);
            ret = write_chunk(out, &curr_chain->chunk, &error);
            if (ret < 0) {
                fprintf(stderr, "%s: %s\n", argv[0], error);
                goto flush;
            }
        }

        if (curr_chain->chunk.tag == tag_IHDR && (data.icc_is_srgb ||
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
