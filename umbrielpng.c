#include <error.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

typedef struct UmbPngChunk {
    uint32_t chunk_size;
    uint32_t tag;
    uint8_t *data;
    uint32_t data_size;
    uint32_t crc32;
    size_t offset;
} UmbPngChunk;

typedef struct UmbPngFile {
    UmbPngChunk *chunk;
    struct UmbPngFile *prev;
    struct UmbPngFile *next;
} UmbPngFile;

static const uint8_t png_signature[8] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
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

    if (crc != chunk->crc32)
        fprintf(stderr, "Warning: computed CRC32 %08x does not match read CRC32 %08x\n", crc, chunk->crc32);

    return 0;

fail:
    perror(*error);
    *error = "Error reading chunk data";
    freep(chunk->data);
    return -1;
}

/** frees everything except the base node */
void free_chain(UmbPngFile *file) {
    UmbPngFile *prev = file;
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
    FILE *in = NULL;
    uint8_t sig[8];
    size_t read;
    UmbPngFile png_file = { 0 };
    UmbPngFile *curr_chain = &png_file;
    
    if (!strcmp("-", input))
        in = stdin;
    else
        in = fopen(input, "r");
    if (!in) {
        perror(argv[0]);
        ret = 1;
        goto flush;
    }

    read = fread(sig, 8, 1, in);
    if (!read) {
        perror(argv[0]);
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
            UmbPngFile *next = calloc(1, sizeof(UmbPngFile));
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

flush:
    if (in)
        fclose(in);
    free_chain(&png_file);
    return ret;
}
