//
//  MacVFNBuffers.h
//  MacVFN
//
//  Created by Mads Ynddal on 25/10/2024.
//

#ifndef MacVFNBuffers_h
#define MacVFNBuffers_h
struct buffer {
    uint64_t token;
    IOMemoryDescriptor *buf_desc;
    uint64_t vaddr;
    bool in_use;
};

#define MAX_BUFFERS 256

static bool buffer_add(struct buffer *buffers, struct buffer _new){
    for (int i=0; i<MAX_BUFFERS; i++){
        if (!buffers[i].in_use){
            buffers[i] = _new;
            buffers[i].in_use = true;
            return true;
        }
    }
    return false;
}

static bool buffer_remove(struct buffer *buffers, uint64_t token){
    for (int i=0; i<MAX_BUFFERS; i++){
        struct buffer* buf = &(buffers[i]);
        if (buf->in_use && (buf->token == token)){
            buf->in_use = false;
            return true;
        }
    }
    return false;
}

static struct buffer* buffer_find(struct buffer *buffers, uint64_t token){
    for (int i=0; i<MAX_BUFFERS; i++){
        struct buffer* buf = &(buffers[i]);
        if (buf->in_use && (buf->token == token)){
            return buf;
        }
    }
    return NULL;
}

static size_t buffer_count(struct buffer *buffers){
    size_t count = 0;
    for (int i=0; i<MAX_BUFFERS; i++){
        if (buffers[i].in_use){
            count += 1;
        }
    }
    return count;
}

#endif /* MacVFNBuffers_h */
