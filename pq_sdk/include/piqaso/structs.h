#ifndef PIQASO_STRUCTS_H
#define PIQASO_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct piq_buffer {
    uint8_t *buffer;
    size_t   buffer_len;
};

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_STRUCTS_H */
