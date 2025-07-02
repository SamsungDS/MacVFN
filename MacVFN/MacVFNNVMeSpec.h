//
//  MacVFNNVMeSpec.h
//  MacVFN
//
//  Created by Mads Ynddal on 30/06/2025.
//

#ifndef MacVFNNVMeSpec_h
#define MacVFNNVMeSpec_h

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
    uint32_t ITPS_ITPT;
    uint32_t reserved;
} NVMeSpecAPSTData;

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

typedef struct {
    uint16_t MP;        // Maximum Power (centiwatts)
    uint8_t  Reserved1; // Reserved
    uint8_t  MPS_NOPS;  // Max Power Scale (bit 0), Non-Operational State (bit 1)
    uint32_t ENLAT;     // Entry Latency (microseconds)
    uint32_t EXLAT;     // Exit Latency (microseconds)
    uint8_t  RR;        // Relative Read Throughput
    uint8_t  RW;        // Relative Read Latency
    uint8_t  RRL;       // Relative Write Throughput
    uint8_t  RWL;       // Relative Write Latency
    uint16_t IDLP;      // Idle Power (centiwatts)
    uint8_t  Reserved2; // Reserved
    uint8_t  IPS;       // Idle Power Scale (bits 0-1), Reserved (bits 2-7)
    uint16_t ACTP;      // Active Power (centiwatts)
    uint8_t  APW;       // Active Power Workload (bits 0-1), Reserved (bits 2-7)
    uint8_t  Reserved3[9]; // Reserved
} NVMeSpecPowerStateDescriptorData;

typedef struct {
    uint16_t VID;                // 0: PCI Vendor ID
    uint16_t SSVID;              // 2: PCI Subsystem Vendor ID
    uint8_t  SN[20];             // 4: Serial Number (ASCII)
    uint8_t  MN[40];             // 24: Model Number (ASCII)
    uint8_t  FR[8];              // 64: Firmware Revision (ASCII)
    uint8_t  RAB;                // 72: Recommended Arbitration Burst
    uint8_t  IEEE[3];            // 73: IEEE OUI Identifier
    uint8_t  MIC;                // 76: Multi-Interface Capabilities
    uint8_t  MDTS;               // 77: Maximum Data Transfer Size
    uint16_t CNTLID;             // 78: Controller ID
    uint32_t VER;                // 80: Version
    uint32_t RTD3R;              // 84: RTD3 Resume Latency
    uint32_t RTD3E;              // 88: RTD3 Entry Latency
    uint32_t OAES;               // 92: Optional Asynchronous Events Supported
    uint32_t CTRATT;             // 96: Controller Attributes
    uint8_t  reserved1[156];     // 100: Reserved
    uint16_t OACS;               // 256: Optional Admin Command Support
    uint8_t  ACL;                // 258: Abort Command Limit
    uint8_t  AERL;               // 259: Asynchronous Event Request Limit
    uint8_t  FRMW;               // 260: Firmware Updates
    uint8_t  LPA;                // 261: Log Page Attributes
    uint8_t  ELPE;               // 262: Error Log Page Entries
    uint8_t  NPSS;               // 263: Number of Power States Support
    uint8_t  AVSCC;              // 264: Admin Vendor Specific Command Configuration
    uint8_t  APSTA;              // 265: Autonomous Power State Transition Attributes
    uint16_t WCTEMP;             // 266: Warning Composite Temperature Threshold
    uint16_t CCTEMP;             // 268: Critical Composite Temperature Threshold
    uint16_t MTFA;               // 270: Maximum Time for Firmware Activation
    uint32_t HMPRE;              // 272: Host Memory Buffer Preferred Size
    uint32_t HMMIN;              // 276: Host Memory Buffer Minimum Size
    uint64_t TNVMCAP[2];         // 280: Total NVM Capacity
    uint64_t UNVMCAP[2];         // 296: Unallocated NVM Capacity
    uint32_t RPMBS;              // 312: Replay Protected Memory Block Support
    uint8_t  reserved2[196];     // 316: Reserved
    uint8_t  SQES;               // 512: Submission Queue Entry Size
    uint8_t  CQES;               // 513: Completion Queue Entry Size
    uint16_t MAXCMD;             // 514: Maximum Outstanding Commands
    uint32_t NN;                 // 516: Number of Namespaces
    uint16_t ONCS;               // 520: Optional NVM Command Support
    uint16_t FUSES;              // 522: Fused Operation Support
    uint8_t  FNA;                // 524: Format NVM Attributes
    uint8_t  VWC;                // 525: Volatile Write Cache
    uint16_t AWUN;               // 526: Atomic Write Unit Normal
    uint16_t AWUPF;              // 528: Atomic Write Unit Power Fail
    uint8_t  NVSCC;              // 530: NVM Vendor Specific Command Configuration
    uint8_t  NWPC;               // 531: Namespace Write Protection Capabilities
    uint16_t ACWU;               // 532: Atomic Compare & Write Unit
    uint8_t  reserved4[2];       // 534: Reserved
    uint32_t SGLS;               // 536: SGL Support
    uint8_t  reserved5[2048-540];// 540: Reserved to reach offset 2048
    NVMeSpecPowerStateDescriptorData PSD[32]; // 2048: Power State Descriptors
} NVMeIdentifyControllerData;

typedef enum {
    NVME_OPC_FLUSH = 0x00,
    NVME_OPC_WRITE = 0x01,
    NVME_OPC_READ  = 0x02,
    NVME_OPC_DATASET_MANAGEMENT = 0x09
} NVMeOpcode;

#define NVME_IDENTIFY_FLBAS_INDEX_MASK 0b1111


#define NVME_IDENTIFY_CNS_NS 0x00

#endif /* MacVFNNVMeSpec_h */
