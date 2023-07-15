#include <error.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#define maketag(a,b,c,d) ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) |\
                         (((uint32_t)(c)) << 8) | (uint32_t)(d))

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

typedef struct UmbPngScanData {
    int have_cicp;
    int have_iccp;
    int have_srgb;
    int have_gama_chrm;
    int have_plte;
} UmbPngScanData;

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
    uint32_t ret = tag[0];
    for (int i = 1; i < 4; i++)
        ret = (ret << 8) | tag[i];
    return ret;
}

static inline void uint32_to_tag_array(uint8_t *tag, uint32_t made) {
    for (int i = 0; i < 4; i++)
        tag[i] = (made >> (24 - (8 * i))) & 0xFF;
}

#define freep(p) do {   \
    if (p) free(p);     \
    (p) = NULL;         \
} while (0)

UmbPngChunk *scan_chunk(FILE *in, const UmbPngChunk *last, char **error) {
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

int read_chunk(FILE *in, UmbPngChunk *chunk, char **error) {
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

int write_chunk(FILE *out, const UmbPngChunk *chunk, char **error) {
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

/** frees everything except the base node */
void free_chain(UmbPngChunkChain *file) {
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

    curr_chain = &png_file;
    while (curr_chain) {
        char *error = argv[0];
        ret = read_chunk(in, curr_chain->chunk, &error);
        if (ret < 0)
            goto flush;
        curr_chain = curr_chain->next;
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
    while (curr_chain) {
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
        if (curr_chain->chunk->tag == tag_sRGB && data.have_iccp)
            skip = 1;
        /* not strictly spec compliant but cICP and sRGB both present is very likely just sRGB */
        if (curr_chain->chunk->tag == tag_cICP && !data.have_iccp && data.have_srgb)
            skip = 1;
        if (skip) {
            uint32_to_tag_array(tag, curr_chain->chunk->tag);
            fprintf(stderr, "Stripping chunk: %s\n", tag);
        } else {
            ret = write_chunk(out, curr_chain->chunk, &error);
            if (ret < 0)
                goto flush;
        }
        if (curr_chain->chunk->tag == tag_IHDR && !data.have_cicp && !data.have_srgb
                                               && !data.have_iccp && !data.have_gama_chrm) {
            fprintf(stderr, "Inserting default sRGB chunk\n");
            ret = write_chunk(out, &default_srgb, &error);
            if (ret < 0)
                goto flush;
        }
        curr_chain = curr_chain->next;
    }

flush:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    free_chain(&png_file);
    return ret;
}
