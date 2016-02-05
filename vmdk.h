typedef uint64_t SectorType;
typedef uint8_t Bool;

struct SparseExtentHeader {
	uint32_t	magicNumber;
	uint32_t	version;
	uint32_t	flags;
	SectorType	capacity;
	SectorType	grainSize;
	SectorType	descriptorOffset;
	SectorType	descriptorSize;
	uint32_t	numGTEsPerGT;
	SectorType	rgdOffset;
	SectorType	gdOffset;
	SectorType	overHead;
	Bool		uncleanShutdown;
	char		singleEndLineChar;
	char		nonEndLineChar;
	char		doubleEndLineChar1;
	char		doubleEndLineChar2;
	uint16_t	compressAlgorithm;
	uint8_t		pad[432];
	uint8_t		streamoptimized;	/* Not part of the spec */
} __attribute__((__packed__));

struct Marker {
	SectorType	val;
	uint32_t	size;
	union {
		uint32_t	type;
		uint8_t		data[500];
	} u;
} __attribute__((__packed__));
#define MARKERHDRSZ	((int)(sizeof(SectorType) + sizeof(uint32_t)))

#define VMDK_MAGIC	(('V' << 24) | ('M' << 16) | ('D' << 8) | 'K')

#define COMPRESSION_NONE	0
#define COMPRESSION_DEFLATE	1

#define MARKER_EOS		0
#define MARKER_GT		1
#define MARKER_GD		2
#define MARKER_FOOTER		3

#define FLAGBIT_NL		(1 << 0)
#define FLAGBIT_RGT		(1 << 1)
#define FLAGBIT_ZGGTE		(1 << 2)
#define FLAGBIT_COMPRESSED	(1 << 16)
#define FLAGBIT_MARKERS		(1 << 17)
#define SECTORSZ		512

#define SET_VMDKVER		3
#define SET_GRAINSZ		0x80UL		/* 64KB grains */
#define SET_GTESPERGT		512		/* grain tables are 4 blocks */
#define DEFLATE_STRENGTH	6

#define MIN_HEADER_OVERHEAD	0x80
