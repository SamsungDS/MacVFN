//
//  MacVFNShared.h
//  MacVFN
//
//  Created by Mads Ynddal on 24/11/2023.
//

#ifndef MacVFNShared_h
#define MacVFNShared_h

#define MACVFN_CLIENT_VERSION 0x00010000

typedef enum
{
    NVME_INIT = 0,
    NVME_ONESHOT = 1,
    NVME_CREATE_QUEUE_PAIR = 2,
    NVME_DELETE_QUEUE_PAIR = 3,
    NVME_ALLOC_BUFFER=4,
    NVME_DEALLOC_BUFFER=5,
    NVME_POKE=6,
    NUMBER_OF_EXTERNAL_METHODS // Has to be last
} ExternalMethodType;

typedef struct {
    struct{
        uint8_t cmd[64]; // NVMe command
        uint8_t cpl[16]; // NVMe completion
        uint64_t backend_opaque; // Reserved for backend (xNVMe dev, async, etc.)
    };
    uint64_t queue_id;

    uint64_t dbuf_nbytes;
    uint64_t dbuf_offset;
    uint64_t dbuf_token;
    uint64_t dbuf_iova;

    uint64_t mbuf_nbytes;
    uint64_t mbuf_offset;
    uint64_t mbuf_token;
} NvmeSubmitCmd;

typedef struct {
    uint8_t  opcode;        // Command opcode
    uint8_t  flags;         // Command flags (fused, etc.)
    uint16_t cid;    // Command Identifier (CID)
    uint32_t nsid;          // Namespace Identifier

    uint64_t reserved1;     // Reserved (typically for future use)

    uint64_t mptr;          // Metadata Pointer
    uint64_t prp1;          // PRP Entry 1 (data pointer)
    uint64_t prp2;          // PRP Entry 2 (data pointer or PRP list)

    uint64_t slba;          // Starting LBA (Logical Block Address)
    uint16_t nlb;           // Number of Logical Blocks

    uint16_t reserved2;     // Reserved for alignment

    uint32_t cdw13;         // Command Dword 13
    uint32_t cdw14;         // Command Dword 14
    uint32_t cdw15;         // Command Dword 15
} NVMeSpecIOCommand;

typedef struct {
    uint8_t  opcode;        // Command opcode (should be NVME_OPC_DATASET_MANAGEMENT)
    uint8_t  flags;         // Command flags
    uint16_t cid;           // Command Identifier (CID)
    uint32_t nsid;          // Namespace Identifier

    uint64_t reserved1;     // Reserved

    uint64_t mptr;          // Metadata Pointer (not used for DSM)
    uint64_t prp1;          // PRP Entry 1 (pointer to range list)
    uint64_t prp2;          // PRP Entry 2 (pointer to range list continuation or PRP list)

    uint32_t nr;            // Number of Ranges (zero-based, so 0 = 1 range)
    uint32_t attributes;    // Attributes (bit 2 = deallocate)

    uint32_t reserved2[4];  // Reserved
} NVMeSpecDSMCommand;

typedef struct {
    uint32_t CA;        // Context Attributes
    uint32_t NLB;       // Number of Logical Blocks (zero-based, so 0 = 1 block)
    uint64_t SLBA;      // Starting LBA
} NVMeSpecDSMRangeData;

typedef struct {
    uint64_t NSZE;     // Namespace Size
    uint64_t NCAP;     // Namespace Capacity
    uint64_t NSUSE;    // Namespace Utilization
    uint8_t  NSFEAT;   // Namespace Features
    uint8_t  NLBAF;    // Number of LBA Formats
    uint8_t  FLBAS;    // Formatted LBA Size
    uint8_t  MC;       // Metadata Capabilities
    uint8_t  DPC;      // End-to-end Data Protection Capabilities
    uint8_t  DPS;      // End-to-end Data Protection Type Settings
    uint8_t  NMIC;     // Namespace Multi-path I/O and Namespace Sharing Capabilities
    uint8_t  RESCAP;   // Reservation Capabilities
    uint8_t  FPI;      // Format Progress Indicator
    uint8_t  DLFEAT;   // Deallocate Logical Block Features
    uint16_t NAWUN;    // Namespace Atomic Write Unit Normal
    uint16_t NAWUPF;   // Namespace Atomic Write Unit Power Fail
    uint16_t NACWU;    // Namespace Atomic Compare & Write Unit
    uint16_t NABSN;    // Namespace Atomic Boundary Size Normal
    uint16_t NABO;     // Namespace Atomic Boundary Offset
    uint16_t NABSPF;   // Namespace Atomic Boundary Size Power Fail
    uint16_t NOIOB;    // Namespace Optimal IO Boundary
    uint8_t  NVMCAP[16]; // NVM Capacity
    uint8_t  reserved1[40];
    uint8_t  NGUID[16]; // Namespace Globally Unique Identifier
    uint8_t  EUI64[8];  // IEEE Extended Unique Identifier
    struct {
        uint16_t MS;    // Metadata Size (16 bits)
        uint8_t LBADS;  // LBA Data Size
        uint8_t RP;     // Relative Performance (only lower 2 bits used)
    } LBAF[16]; // LBA Format Support (16 entries)
    uint8_t  reserved2[192];
} NVMeIdentifyNamespaceData;

#define NVME_OPC_READ             0x02
#define NVME_OPC_WRITE            0x01
#define NVME_OPC_FLUSH            0x00
#define NVME_OPC_DATASET_MANAGEMENT 0x09

#define NVME_IDENTIFY_FLBAS_INDEX_MASK 0b1111

#define NVME_IDENTIFY_CNS_NS 0x00
#define NVME_IDENTIFY_CTRL_MDTS 0x4D
#define NVME_IDENTIFY_CTRL_ONCS 0x208

#define OPAQUE_HAS_CONTEXT (1ull<<63)

typedef struct {
    // uint32_t request_id;
    IOBufferMemoryDescriptor* memory_descriptor;
    IOAddressSegment address_segment;
    uint64_t size;
    uint8_t do_unmap;
} NVMeBlockStorageCommandContext;

typedef struct {
    uint64_t id;
    uint64_t depth;
    int64_t vector;
    uint64_t flags;
} NvmeQueue;

typedef struct {
    uint64_t depth;
    volatile _Atomic uint64_t tail;
    volatile _Atomic uint64_t head;
	uint64_t buffer_size;
    uint8_t buffer[0];
} RingQueue;

static inline void queue_get_entry(RingQueue *queue, uint64_t index, NvmeSubmitCmd* cmd){
    memcpy((void*)cmd, (uint8_t*)queue->buffer + sizeof(*cmd)*index, sizeof(*cmd));
}

static inline void queue_put_entry(RingQueue *queue, uint64_t index, NvmeSubmitCmd* cmd){
    memcpy((uint8_t*)queue->buffer + sizeof(*cmd)*index, (void*)cmd, sizeof(*cmd));
}

#define QUEUE_FULL -1
#define QUEUE_EMPTY -2
#define QUEUE_ERROR -3

static inline int queue_enqueue(RingQueue *queue, NvmeSubmitCmd* cmd){
    uint64_t tail = __c11_atomic_load(&queue->tail, __ATOMIC_ACQUIRE);
	uint64_t head = __c11_atomic_load(&queue->head, __ATOMIC_RELAXED);

    if ((tail + 1) % queue->depth == head) {
        // Queue full
        return QUEUE_FULL;
    }

    queue_put_entry(queue, tail, cmd);

    uint64_t new_tail = (tail+1) % queue->depth;
    if (tail != __c11_atomic_exchange(&queue->tail, new_tail, __ATOMIC_RELEASE)){
        // No way of recovering. Somebody else modified queue at the same time.
        return QUEUE_ERROR;
    }
    return 0;
}

static inline int queue_dequeue(RingQueue *queue, NvmeSubmitCmd* cmd){
	uint64_t head = __c11_atomic_load(&queue->head, __ATOMIC_ACQUIRE);
    uint64_t tail = __c11_atomic_load(&queue->tail, __ATOMIC_RELAXED);

    if (head == tail) {
        // Queue empty
        return QUEUE_EMPTY;
    }

    queue_get_entry(queue, head, cmd);

    uint64_t new_head = (head+1) % queue->depth;
    if (head != __c11_atomic_exchange(&queue->head, new_head, __ATOMIC_RELEASE)){
        // No way of recovering. Somebody else modified queue at the same time.
        return QUEUE_ERROR;
    }
    return 0;
}

static inline bool queue_full(RingQueue *queue){
    uint64_t head = __c11_atomic_load(&queue->head, __ATOMIC_RELAXED);
    uint64_t tail = __c11_atomic_load(&queue->tail, __ATOMIC_RELAXED);
    return (tail + 1) % queue->depth == head;
}

static inline int queue_peek(RingQueue *queue){
    uint64_t head = __c11_atomic_load(&queue->head, __ATOMIC_RELAXED);
    uint64_t tail = __c11_atomic_load(&queue->tail, __ATOMIC_RELAXED);
    return ((int64_t)head - (int64_t)tail + (int64_t)queue->depth) % (int64_t)queue->depth;
}

static inline int queue_dequeue_ready(RingQueue *queue, uint64_t *head, uint64_t *tail){
    *head = __c11_atomic_load(&queue->head, __ATOMIC_RELAXED);
    *tail = __c11_atomic_load(&queue->tail, __ATOMIC_RELAXED);
    return ((int64_t)*tail - (int64_t)*head + (int64_t)queue->depth) % (int64_t)queue->depth;
}

static inline int queue_enqueue_ready(RingQueue *queue, uint64_t *head, uint64_t *tail){
    *head = __c11_atomic_load(&queue->head, __ATOMIC_RELAXED);
    *tail = __c11_atomic_load(&queue->tail, __ATOMIC_RELAXED);
    return ((int64_t)*head - (int64_t)*tail + (int64_t)queue->depth) % (int64_t)queue->depth;
}

#endif /* MacVFNShared_h */
