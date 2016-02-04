/*-
 * Copyright (c) 2009-2012 Brian Somers <brian@Awfulhak.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

struct mmsghdr;		/* XXX: Why do you make me do this linux? */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#ifndef __APPLE__
#include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "expand_number.h"


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

static int diag;
static int zstrength;
static uint64_t capacity;

static int
usage(void)
{
	fprintf(stderr, "usage: vmdktool [-di] [-r fn1.raw] [-s fn2.raw] "
	    "[-t sec]\n");
	fprintf(stderr, "                [[-c size] [-z zstr] -v fn3.vmdk] "
	    "file\n");
	fprintf(stderr, "       vmdktool -V\n");
	fprintf(stderr, "       -c => Use disk capacity 'size' rather than "
	    "the size of 'file'\n");
	fprintf(stderr, "       -d => Increase diagnostics\n");
	fprintf(stderr, "       -i => Show vmdk info from 'file'\n");
	fprintf(stderr, "       -r => Read random vmdk data, "
	    "write raw data to fn1.raw\n");
	fprintf(stderr, "       -s => Read stream vmdk data, "
	    "write raw data to fn2.raw\n");
	fprintf(stderr, "       -t => Show vmdk table info at sector 'sec'\n");
	fprintf(stderr, "       -V => Show the version number and exit\n");
	fprintf(stderr, "       -v => Read raw data, write vmdk data to "
	    "fn3.vmdk\n");
	fprintf(stderr, "       -z => Set the deflate strength to 'zstr'\n");
	fprintf(stderr, "       file => A raw disk or vmdk image\n");

	return 1;
}

static void
awrite(int fd, const void *buf, size_t n, const char *what)
{
	ssize_t got;
	off_t pos;

	pos = diag > 1 ? lseek(fd, 0, SEEK_CUR) : 0;
	got = write(fd, buf, n);
	if (got == -1) {
		perror("write");
		abort();
	} else if (got != (ssize_t)n) {
		fprintf(stderr, "write: tried %lu, got %ld\n", (long unsigned)n, (long)got);
		abort();
	}
	if (diag > 1)
		printf("Wrote %s of %lu bytes at offset 0x%llx\n",
		    what, (unsigned long)n, (unsigned long long)pos);
}

static size_t
aread(int fd, void *buf, size_t n)
{
	ssize_t got;

	got = read(fd, buf, n);
	if (got == -1) {
		perror("read");
		abort();
	}
	if (got != (ssize_t)n)
		memset((char *)buf + got, '\0', n - got);
	return got;
}

static void
vmdkshow(const struct SparseExtentHeader *h)
{
	char buf[SECTORSZ];

	printf("version: %d\n", h->version);
	printf("flags: 0x%08x\n", h->flags);
	*buf = '\0';
	if (h->flags & FLAGBIT_NL)
		strcat(buf, ", valid NL detect");
	if (h->flags & FLAGBIT_RGT)
		sprintf(buf + strlen(buf),
		    ", redundant grain table [0x%llu]",
		    (unsigned long long)h->rgdOffset);
	if (h->flags & FLAGBIT_ZGGTE)
		sprintf(buf + strlen(buf), ", zero-grain GTE");
	if (h->flags & FLAGBIT_COMPRESSED) {
		strcat(buf, ", compressed grains");
		switch (h->compressAlgorithm) {
		case COMPRESSION_NONE:
			strcat(buf, " [NONE]");
			break;
		case COMPRESSION_DEFLATE:
			strcat(buf, " [DEFLATE]");
			break;
		default:
			sprintf(buf + strlen(buf), " [0x%02x]",
			    h->compressAlgorithm);
			break;
		}
	}
	if (h->flags & FLAGBIT_MARKERS)
		strcat(buf, ", markers present");
	if (*buf)
		printf("       %s\n", buf + 2);

	printf("capacity: 0x%08llx sectors (%llu GB)\n",
	    (unsigned long long)h->capacity,
	    (unsigned long long)h->capacity / 2097152llu);
	printf("grainSize: 0x%08llx sectors (%llu KB)\n",
	    (unsigned long long)h->grainSize,
	    (unsigned long long)h->grainSize / 2llu);
	printf("descriptorOffset: 0x%08llx\n",
	    (unsigned long long)h->descriptorOffset);
	printf("descriptorSize: 0x%08llx sectors\n",
	    (unsigned long long)h->descriptorSize);
	printf("numGTEsPerGT: %lu\n", (unsigned long)h->numGTEsPerGT);
	if (h->gdOffset == (unsigned long long)-1)
		printf("gdOffset: set at end\n");
	else
		printf("gdOffset: 0x%08llx [%llx]\n",
		    (unsigned long long)h->gdOffset,
		    (unsigned long long)h->gdOffset * SECTORSZ);
	printf("overHead: 0x%08llx sectors (%llu KB)\n",
	    (unsigned long long)h->overHead,
	    (unsigned long long)h->overHead / 2llu);
	printf("shutdown: %sCLEAN\n", h->uncleanShutdown ? "UN" : "");
}

static void
vmdkvrfy(const struct SparseExtentHeader *h, int show)
{
	if (!(h->flags & FLAGBIT_NL))
		return;

	if (h->singleEndLineChar != '\n')
		fprintf(stderr, "singleEndLineChar: FAIL (0x%02x)\n",
		    (unsigned char)h->singleEndLineChar);
	else if (show)
		printf("singleEndLineChar: OK\n");

	if (h->nonEndLineChar != ' ')
		fprintf(stderr, "nonEndLineChar: FAIL (0x%02x)\n",
		    (unsigned char)h->nonEndLineChar);
	else if (show)
		printf("nonEndLineChar: OK\n");

	if (h->doubleEndLineChar1 != '\r')
		fprintf(stderr, "doubleEndLineChar1: FAIL (0x%02x)\n",
		    (unsigned char)h->doubleEndLineChar1);
	else if (show)
		printf("doubleEndLineChar1: OK\n");

	if (h->doubleEndLineChar2 != '\n')
		fprintf(stderr, "doubleEndLineChar2: FAIL (0x%02x)\n",
		    (unsigned char)h->doubleEndLineChar2);
	else if (show)
		printf("doubleEndLineChar2: OK\n");
}

static char *
vmdkdesc(int fd, const struct SparseExtentHeader *h)
{
	char *desc;
	size_t sz;

	assert(h->descriptorOffset);
	assert(h->descriptorSize);
	desc = malloc(h->descriptorSize * SECTORSZ + 1);
	assert(desc != NULL);

	lseek(fd, h->descriptorOffset * SECTORSZ, SEEK_SET);
	sz = h->descriptorSize * SECTORSZ;
	aread(fd, desc, sz);
	desc[sz] = '\0';

	return desc;
}

static void
vmdkdescshow(const char *desc)
{
	const char *lf, *next, *start;

	printf("\nDescriptor:\n");
	start = desc;
	while ((lf = strchr(start, '\n')) != NULL) {
		next = lf + 1;
		while (lf >= start && (*lf == '\r' || *lf == '\n'))
			lf--;
		printf("    %.*s\n", (int)(lf - start + 1), start);
		start = next;
	}
	if (*start)
		printf("    %s\n", start);
}

static int
vmdkinfo(const char *fn, int fd, struct SparseExtentHeader *h, int showddb)
{
	char *dbuf;
	off_t pos;

	pos = lseek(fd, 0, SEEK_CUR);
	aread(fd, h, sizeof *h);

	if (h->magicNumber != VMDK_MAGIC) {
		fprintf(stderr, "%s: Bad VMDK magic (got %08x, want %08x)\n",
		    fn, h->magicNumber, VMDK_MAGIC);
		return 0;
	}

	if (diag) {
		printf("Sparse Extent Header/Footer found at 0x%08llx\n",
		    (unsigned long long)pos);
		vmdkshow(h);
	}

	vmdkvrfy(h, diag);

	dbuf = vmdkdesc(fd, h);
	h->streamoptimized = strstr(dbuf, "createType=\"streamOptimized\"") ?
	    1 : 0;
	if (showddb && diag)
		vmdkdescshow(dbuf);
	free(dbuf);

	return 1;
}

static void
marker2grain(int ifd, const struct SparseExtentHeader *h,
    const struct Marker *m, unsigned char *grain, unsigned char **buf, size_t *bufsz)
{
	z_stream strm;
	ssize_t want;

	want = m->size + MARKERHDRSZ;
	if (want % SECTORSZ)
		want = (want / SECTORSZ + 1) * SECTORSZ;
	if (*bufsz < (size_t)want - MARKERHDRSZ) {
		*bufsz = want - MARKERHDRSZ;
		*buf = realloc(*buf, *bufsz);
		assert(*buf != NULL);
	}
	memcpy(*buf, &m->u, 500);
	if (want > SECTORSZ) {
		aread(ifd, *buf + 500, want - SECTORSZ);
		if (diag > 1)
			printf("Read an extra %lu bytes\n", (unsigned long)want - SECTORSZ);
	}

	if ((h->flags & FLAGBIT_COMPRESSED) &&
	    h->compressAlgorithm == COMPRESSION_DEFLATE) {
		int ret;

		memset(&strm, '\0', sizeof strm);
		ret = inflateInit(&strm);
		assert(ret == Z_OK);
		strm.avail_in = m->size;
		strm.next_in = *buf;
		strm.avail_out = h->grainSize * SECTORSZ;
		strm.next_out = grain;
		ret = inflate(&strm, Z_FINISH);
		assert(ret == Z_STREAM_END);
		assert(strm.avail_in == 0);
		assert(strm.avail_out == 0);
		inflateEnd(&strm);
		if (diag > 1)
			printf("INFLATEd grain from %lu to %llu\n",
			    (unsigned long)m->size,
			    (unsigned long long)h->grainSize * SECTORSZ);
	} else if (!(h->flags & FLAGBIT_COMPRESSED) ||
	    h->compressAlgorithm == COMPRESSION_NONE) {
		assert(m->size == h->grainSize * SECTORSZ);
		memcpy(grain, *buf, m->size);
	}
}

static int
dirblks(const struct SparseExtentHeader *h)
{
	SectorType blks;

	blks = h->capacity * SECTORSZ;
	blks = blks / h->grainSize + (blks % h->grainSize ? 1 : 0);
	blks = blks / h->numGTEsPerGT + (blks % h->numGTEsPerGT ? 1 : 0);
	blks *= sizeof(uint32_t);
	blks = blks / SECTORSZ + (blks % h->numGTEsPerGT ? 1 : 0);
	if (blks % SECTORSZ)
		blks += SECTORSZ;
	blks /= SECTORSZ;

	return blks;
}

static void
vmdkshowtable(int fd, uint32_t pos, uint32_t type,
    const struct SparseExtentHeader *h)
{
	char block[SECTORSZ];
	const char *typestr;
	uint32_t entry;
	int blk, blks;
	unsigned n;

	switch (type) {
	case MARKER_GD:
		typestr = "DIR";
		blks = dirblks(h);
		break;
	case MARKER_GT:
		typestr = "TBL";
		blks = h->numGTEsPerGT * sizeof(uint32_t) / SECTORSZ;
		break;
	default:
		return;
	}

	printf("type GRAIN %s, %d sectors\n", typestr, blks);

	lseek(fd, pos * SECTORSZ, SEEK_SET);
	for (blk = 0; blk < blks; blk++) {
		aread(fd, block, SECTORSZ);
		printf("   ");
		for (n = 0; n < SECTORSZ / 4; n++) {
			memcpy(&entry, block + n * 4, 4);
			if (n && n % 8 == 0)
				printf("\n   ");
			printf(" %08x", entry);
		}
		printf("\n");
	}
}

static void
vmdkparsestream(int ifd, struct SparseExtentHeader *h, int ofd)
{
	struct Marker *m;
	unsigned char buf[sizeof *m], *grain, *dbuf;
	SectorType mtblblks, mdirblks;
	struct SparseExtentHeader f;
	size_t dbufsz;
	off_t pos;
	int eos;
	int ret;

	pos = lseek(ifd, 0, SEEK_CUR);

	m = (struct Marker *)buf;
	dbuf = NULL;
	dbufsz = 0;
	eos = 0;
	mdirblks = dirblks(h);
	mtblblks = h->numGTEsPerGT * sizeof(uint32_t) / SECTORSZ;
	grain = malloc(h->grainSize * SECTORSZ);
	assert(grain != NULL);
	while (read(ifd, buf, sizeof buf) == sizeof buf) {
		if (eos)
			fprintf(stderr, "oops, more data after EOS...\n");
		if (diag > 1)
			printf("Pos 0x%llx (%llu): ", (unsigned long long)pos,
			    (unsigned long long)pos);
		if (m->size) {
			if (diag)
				printf("type GRAIN, %lu bytes of data, "
				    "lba %llu\n", (unsigned long)m->size,
				    (unsigned long long)m->val);
			lseek(ofd, m->val * SECTORSZ, SEEK_SET);
			marker2grain(ifd, h, m, grain, &dbuf, &dbufsz);
			if (diag > 1)
				printf("Seek output to %llu\n",
				    (unsigned long long)m->val * SECTORSZ);
			awrite(ofd, grain, h->grainSize * SECTORSZ, "grain");
		} else switch (m->u.type) {
		case MARKER_GT:
			assert(m->val == mtblblks);
			/* FALLTHRU */
		case MARKER_GD:
			if (m->u.type == MARKER_GD)
				assert(m->val == mdirblks);
			if (diag)
				vmdkshowtable(ifd, pos / SECTORSZ + 1,
				    m->u.type, h);
			else
				lseek(ifd, m->val * SECTORSZ, SEEK_CUR);
			break;

		case MARKER_FOOTER:
			if (diag)
				printf("type FOOTER, %llu sectors\n",
				    (unsigned long long)m->val);
			pos = lseek(ifd, 0, SEEK_CUR) + m->val * SECTORSZ;
			assert(sizeof f <= m->val * SECTORSZ);
			ret = vmdkinfo("<footer>", ifd, &f, 0);
			assert(ret != 0);
			if (h->gdOffset == (unsigned long long)-1)
				h->gdOffset = f.gdOffset;
			lseek(ifd, pos, SEEK_SET);
			break;

		case MARKER_EOS:
			if (diag)
				printf("type EOS\n");
			eos = 1;
			break;

		default:
			fprintf(stderr, "type <%lu>, sector 0x%llx\n",
			    (unsigned long)m->u.type,
			    (unsigned long long)m->val);
			break;
		}
		pos = lseek(ifd, 0, SEEK_CUR);
	}
	free(dbuf);
	free(grain);
}

/*
 * Read either a grain table or a grain directory entry, returning the 32bit
 * value.  The passed 'sec' is the starting sector of the table or directory
 * block.
 */
static uint32_t
readentry(int ifd, SectorType sec, SectorType entry)
{
	char buf[SECTORSZ];
	int itemsperblock;
	uint32_t val;

	itemsperblock = SECTORSZ / sizeof(uint32_t);

	lseek(ifd, (sec + entry / itemsperblock) * SECTORSZ, SEEK_SET);
	aread(ifd, buf, SECTORSZ);

	memcpy(&val, buf + 4 * (entry % 128), 4);
	return val;
}

static void
grain2raw(int ifd, const struct SparseExtentHeader *h, int ofd, SectorType n,
    unsigned char **buf, size_t *bufsz)
{
	SectorType blk, tbl;
	struct Marker m;
	unsigned char *grain;

	if ((tbl = readentry(ifd, h->gdOffset, n / h->numGTEsPerGT)) == 0)
		return;
	if ((blk = readentry(ifd, tbl, n % h->numGTEsPerGT)) <= 1)
		return;

	blk *= SECTORSZ;
	lseek(ifd, blk, SEEK_SET);
	if (diag > 1)
		printf("Pos 0x%llx (%llu): ", (unsigned long long)blk,
		    (unsigned long long)blk);
	aread(ifd, &m, sizeof m);
	assert(m.size);
	assert(m.val == n * h->grainSize);
	if (diag)
		printf("type GRAIN, %lu bytes of data, lba %llu\n",
		    (unsigned long)m.size, (unsigned long long)m.val);

	grain = malloc(h->grainSize * SECTORSZ);
	assert(grain != NULL);
	marker2grain(ifd, h, &m, grain, buf, bufsz);

	if (diag > 1)
		printf("Seek output to offset %llu\n",
		    (unsigned long long)n * h->grainSize * SECTORSZ);
	lseek(ofd, n * h->grainSize * SECTORSZ, SEEK_SET);
	awrite(ofd, grain, h->grainSize * SECTORSZ, "grain");
	free(grain);
}

static void
allgrains2raw(int ifd, const struct SparseExtentHeader *h, int ofd)
{
	SectorType grains, n;
	size_t dbufsz;
	unsigned char *dbuf;

	dbuf = NULL;
	dbufsz = 0;
	grains = h->capacity / h->grainSize;
	if (h->capacity % h->grainSize)
		grains++;
	for (n = 0; n < grains; n++)
		grain2raw(ifd, h, ofd, n, &dbuf, &dbufsz);
	free(dbuf);
}

static void
setsize(int fd, SectorType sz)
{
	struct stat st;
	int ret;

	ret = fstat(fd, &st);
	assert(ret == 0);
	if ((SectorType)st.st_size != sz * SECTORSZ) {
		lseek(fd, sz * SECTORSZ, SEEK_SET);
		awrite(fd, "", 1, "NUL byte");
		ret = ftruncate(fd, sz * SECTORSZ);
		assert(ret == 0);
	}
}

static void
zipgrain(unsigned char *grain, int ofd, struct Marker *m)
{
	z_stream strm;
	int ret;

	memset(&strm, '\0', sizeof strm);
	ret = deflateInit(&strm, zstrength);
	assert(ret == Z_OK);
	strm.avail_in = SET_GRAINSZ * SECTORSZ;
	strm.next_in = grain;
	/* Skip first marker header */
	strm.avail_out = SECTORSZ - MARKERHDRSZ;
	strm.next_out = (unsigned char *)m + MARKERHDRSZ;
	ret = Z_OK;
	while (ret == Z_OK) {
		ret = deflate(&strm, Z_FINISH);
		assert(ret == Z_OK || ret == Z_STREAM_END);
		awrite(ofd, m, sizeof *m - strm.avail_out, "compressed grain");
		strm.avail_out = SECTORSZ;
		strm.next_out = (unsigned char *)m;
	}
	deflateEnd(&strm);
}

static void
writegrain(unsigned char *grain, int ofd, SectorType sec)
{
	off_t start, end;
	struct Marker m;

	/* First marker header is overwritten below */
	m.val = 0;
	m.size = 0;

	start = lseek(ofd, 0, SEEK_CUR);
	zipgrain(grain, ofd, &m);
	end = lseek(ofd, 0, SEEK_CUR);
	if (diag > 1)
		printf("DEFLATEd grain from %lu to %lu\n",
		    SET_GRAINSZ * SECTORSZ, (unsigned long)(end - start));

	/* Go back and write the size */
	assert(end - start > MARKERHDRSZ);
	m.val = sec;
	m.size = end - start - MARKERHDRSZ;
	lseek(ofd, start, SEEK_SET);
	if (diag > 1)
		printf("Rewound to the start of the grain... ");
	awrite(ofd, &m, MARKERHDRSZ, "grain size");

	if (end % SECTORSZ)
		end = (end / SECTORSZ + 1) * SECTORSZ;
	lseek(ofd, end, SEEK_SET);
	if (diag > 1)
		printf("Moved to the end of the grain... ");
}

static void
inithdr(struct SparseExtentHeader *h)
{
	memset(h, '\0', sizeof h);
	h->magicNumber = VMDK_MAGIC;
	h->version = SET_VMDKVER;
	h->flags = FLAGBIT_NL | FLAGBIT_COMPRESSED | FLAGBIT_MARKERS;
	h->grainSize = SET_GRAINSZ;
	h->descriptorOffset = sizeof *h / SECTORSZ;
	h->descriptorSize = SECTORSZ/*sizeof descblk*/ / SECTORSZ;
	h->numGTEsPerGT = SET_GTESPERGT;
	h->rgdOffset = 0;
	h->gdOffset = -1;		/* Don't know yet */
	h->overHead = MIN_HEADER_OVERHEAD;
	if (h->overHead * SECTORSZ < sizeof *h + SECTORSZ/*sizeof descblk*/)
		h->overHead = (sizeof *h + SECTORSZ/*sizeof descblk*/) / SECTORSZ + 1;
	h->uncleanShutdown = 0;
	h->singleEndLineChar = '\n';
	h->nonEndLineChar = ' ';
	h->doubleEndLineChar1 = '\r';
	h->doubleEndLineChar2 = '\n';
	h->compressAlgorithm = COMPRESSION_DEFLATE;
}

static void
writemarker(int ofd, SectorType val, uint32_t type, const char *what)
{
	struct Marker m;

	memset(&m, '\0', sizeof m);
	m.val = val;
	m.size = 0;
	m.u.type = type;
	awrite(ofd, &m, SECTORSZ, what);
}

static void
writedescblk(int ofd, uint64_t sz)
{
	char descblk[SECTORSZ];

	memset(descblk, '\0', sizeof descblk);
	snprintf(descblk, sizeof descblk,
	    "# Disk DescriptorFile\n"
	    "version=1\n"
	    "CID=278f54ff\n"
	    "parentCID=ffffffff\n"
	    "createType=\"streamOptimized\"\n"
	    "\n"
	    "\n"
	    "# Extent description\n"
	    "RDONLY %lu SPARSE \"generated-stream.vmdk\"\n"
	    "\n"
	    "#DDB\n"
	    "ddb.virtualHWVersion = \"4\"\n"
	    "ddb.geometry.cylinders = \"%lu\"\n"
	    "ddb.geometry.heads = \"255\"\n"
	    "ddb.geometry.sectors = \"63\"\n"
	    "ddb.adapterType = \"lsilogic\"\n"
	    "ddb.toolsVersion = \"6532\"\n",
	    (unsigned long)(sz / SECTORSZ),
	    (unsigned long)(sz / 63 / 255));
	awrite(ofd, &descblk, sizeof descblk, "descriptor block");
}

char *dirbuf, *tblbuf;
size_t dirsz, tblsz;
int ndirents, ntblents;
uint64_t read_total;

static ssize_t
readgrain(int ifd, unsigned char *grain, ssize_t len)
{
	ssize_t got;
	int i;

	if (capacity && read_total >= capacity) {
		if (diag > 1)
			printf("Capacity capped at %llu\n",
			    (unsigned long long)capacity);
		got = 0;
	} else
		got = aread(ifd, grain, len);
	for (i = 0; i < got; i++)
		if (grain[i] != '\0')
			break;
	if (i == got)
		got = 0;	/* No data */
	return got;
}

static void
writedir(int ofd)
{
	uint32_t secidx;

	if (ndirents * sizeof(uint32_t) >= dirsz) {
		dirbuf = realloc(dirbuf, dirsz + SECTORSZ);
		assert(dirbuf != NULL);
		memset((char *)dirbuf + dirsz, '\0', SECTORSZ);
		dirsz += SECTORSZ;
		assert(ndirents * sizeof(uint32_t) < dirsz);
	}

	secidx = lseek(ofd, 0, SEEK_CUR) / SECTORSZ + 1;
	memcpy((char *)dirbuf + ndirents * 4, &secidx, 4);
	ndirents++;

	writemarker(ofd, tblsz / SECTORSZ, MARKER_GT,
	    "grain table marker");
	awrite(ofd, tblbuf, tblsz, "grain table");

	memset(tblbuf, '\0', tblsz);
	ntblents = 0;
}

static void
writegrains(int ifd, int ofd)
{
	read_total = 0;

	dirsz = SECTORSZ;
	dirbuf = calloc(1, dirsz);
	ndirents = 0;
	assert(dirbuf != NULL);

	tblsz = SET_GTESPERGT * sizeof(uint32_t);
	tblbuf = calloc(1, tblsz);
	ntblents = 0;
	assert(tblbuf != NULL);

	SectorType sec;
	ssize_t got;

	for (sec = 0, got = -1; got; sec += SET_GRAINSZ) {
		unsigned char grain[SET_GRAINSZ * SECTORSZ];
		uint32_t secidx;

		got = readgrain(ifd, grain, sizeof grain);
		read_total += got;

		if (got) {
			secidx = lseek(ofd, 0, SEEK_CUR) / SECTORSZ;
			memcpy((char *)tblbuf + ntblents * 4, &secidx, 4);
			ntblents++;

			writegrain(grain, ofd, sec);
		}

		if (ntblents == SET_GTESPERGT || (ntblents && !got)) {
			writedir(ofd);
		}
	}

	free(tblbuf);

	writemarker(ofd, dirsz / SECTORSZ, MARKER_GD, "grain dir marker");
	awrite(ofd, dirbuf, dirsz, "grain dir");

	free(dirbuf);
}

static void
writevmdk(int ifd, int ofd)
{
	struct SparseExtentHeader h;
	uint64_t sz;

	inithdr(&h);

	lseek(ifd, 0, SEEK_SET);
	lseek(ofd, h.overHead * SECTORSZ, SEEK_SET);

	/* 1. Write Gains */
	writegrains(ifd, ofd);

	/* 2. Compute sizes and finish header */
	h.gdOffset = (lseek(ofd, 0, SEEK_CUR) - dirsz - SECTORSZ) / SECTORSZ + 1;
	if (!capacity) {
		sz = read_total;
		if (diag > 1)
			printf("Capacity calculated as %llu\n",
			    (unsigned long long)sz);
	} else
		sz = capacity;
	h.capacity = sz / SECTORSZ;

	/* 3. Write footer */
	writemarker(ofd, sizeof h / SECTORSZ, MARKER_FOOTER, "footer marker");
	awrite(ofd, &h, sizeof h, "footer");

	/* 4. Write EOS */
	writemarker(ofd, 0, MARKER_EOS, "eos marker");

	/* 5. Write header */
	/* Go back and write the header & descriptor block at the beginning */
	lseek(ofd, 0, SEEK_SET);
	if (diag > 1)
		printf("Rewound to the start of the file... ");
	awrite(ofd, &h, sizeof h, "header");

	/* 6. Write desc block */
	writedescblk(ofd, sz);
}

int
main(int argc, char **argv)
{
	const char *randomfn, *streamfn, *vmdkfn;
	char block[SECTORSZ], *dbuf, *end;
	int ch, ifd, outspec, ofd, opti;
	struct SparseExtentHeader h;
	uint32_t optt;
	struct Marker *m;
	SectorType sec;
	struct stat st;
	off_t insz;
	int ret;

	assert(sizeof h == SECTORSZ);	/* must be padded & packed! */
	assert(sizeof *m == SECTORSZ);	/* must be padded & packed! */

	randomfn = streamfn = vmdkfn = NULL;
	capacity = 0;
	opti = 0;
	optt = 0;
	zstrength = DEFLATE_STRENGTH;
	outspec = 0;

	/* make getopt() in Linux more like BSD */
	setenv("POSIXLY_CORRECT", "TRUE", 0);

	while ((ch = getopt(argc, argv, ":c:dir:s:t:Vv:z:")) != -1) {
		switch (ch) {
		case 'c':
			if (expand_number(optarg, &capacity)) {
				perror(optarg);
				return usage();
			}
			break;
		case 'd':
			diag++;
			break;
		case 'i':
			opti = 1;
			break;
		case 'r':
			randomfn = optarg;
			outspec |= 1;
			break;
		case 's':
			streamfn = optarg;
			outspec |= 2;
			break;
		case 't':
			optt = strtoul(optarg, &end, 0);
			if (!optt || *end)
				return usage();
			break;
		case 'V':
			printf("vmdktool version 1.4\n");
			return 0;
			break;
		case 'v':
			vmdkfn = optarg;
			outspec |= 4;
			break;
		case 'z':
			if (optarg[0] < '0' || optarg[0] > '9' || optarg[1])
				return usage();
			zstrength = optarg[0] - '0';
			break;
		default:
			fprintf(stderr, "Invalid option -%c\n", ch);
			return usage();
		}
	}

	if (argc - optind != 1)
		return usage();

	if ((capacity || zstrength != DEFLATE_STRENGTH) && !vmdkfn)
		return usage();

	switch (outspec) {
	case 4:
	case 2:
	case 1:
		break;
	case 0:
		if (opti)
			break;
		fprintf(stderr, "One of -i, -r, -s or -v must be used\n");
		return usage();
	default:
		fprintf(stderr, "Only one of -r, -s and -v may be used\n");
		return usage();
	}

	if ((ifd = open(argv[optind], O_RDONLY)) == -1) {
		perror(argv[optind]);
		return 2;
	}

	if (fstat(ifd, &st) == -1) {
		fprintf(stderr, "fstat: %s: %s\n", argv[optind],
		    strerror(errno));
		return 3;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFREG:
		insz = st.st_size;
		break;
	case S_IFCHR:
		if (vmdkfn) {
			insz = -1;
			break;
		}
		/* FALLTHRU */
	default:
		fprintf(stderr, "%s: File type not supported\n", argv[optind]);
		return 4;
	}

	if (randomfn || streamfn || opti || optt) {
		if (insz < (ssize_t)(sizeof h + SECTORSZ)) {
			fprintf(stderr, "%s: File too small "
			    "(must be at least %d bytes)\n", argv[optind],
			    (int)(sizeof h + SECTORSZ));
			return 5;
		}

		if (!vmdkinfo(argv[optind], ifd, &h, 1))
			return 6;		/* bad magic */
	} else if (vmdkfn) {
		if (insz >= 0 && insz < SECTORSZ) {
			fprintf(stderr, "%s: File too small "
			    "(must be at least %d bytes)\n", argv[optind],
			    SECTORSZ);
			return 7;
		}

		if (diag) {
			lseek(ifd, 0, SEEK_SET);
			aread(ifd, block, 512);
			if ((unsigned char)block[510] != 0x55 ||
			    (unsigned char)block[511] != 0xaa)
				fprintf(stderr, "Warning: %s: "
				    "Not a bootable filesystem\n",
				    argv[optind]);
		}
	}

	if (h.gdOffset + 1 == 0 && (randomfn || opti || optt)) {
		/* Take a crack at finding the footer */
		sec = (insz - sizeof h - SECTORSZ * 2) / SECTORSZ;
		lseek(ifd, sec * SECTORSZ, SEEK_SET);
		aread(ifd, block, SECTORSZ);
		m = (struct Marker *)block;
		if (m->size || m->u.type != MARKER_FOOTER) {
			fprintf(stderr, "%s: Cannot find FOOTER at "
			    "sector %llu\n", argv[optind],
			    (unsigned long long)sec);
			return 8;
		}
		ret = vmdkinfo(argv[optind], ifd, &h, 0);
		assert(ret != 0);
	}

	if (opti) {
		vmdkshow(&h);
		vmdkvrfy(&h, 1);
		dbuf = vmdkdesc(ifd, &h);
		vmdkdescshow(dbuf);
		free(dbuf);
		if (diag)
			vmdkshowtable(ifd, h.gdOffset, MARKER_GD, &h);
	}

	if (optt)
		vmdkshowtable(ifd, optt, MARKER_GT, &h);

	if (randomfn) {
		ofd = open(randomfn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (ofd == -1) {
			perror(randomfn);
			return 9;
		}
		allgrains2raw(ifd, &h, ofd);
		setsize(ofd, h.capacity);
		if (close(ofd) == -1)
			perror("close");
	}

	if (streamfn) {
		if (!h.streamoptimized) {
			fprintf(stderr, "This file is not stream-optimized\n");
			return 10;
		}
		ofd = -2;
		if (h.flags & FLAGBIT_COMPRESSED) {
			switch (h.compressAlgorithm) {
			default:
				fprintf(stderr, "Warning: Cannot decompress"
				    " using method %u", h.compressAlgorithm);
				ofd = -1;
			case COMPRESSION_NONE:
			case COMPRESSION_DEFLATE:
				break;
			}
		}
		if (diag)
			printf("\nParsing stream optimized file\n");
		if (ofd == -2) {
			ofd = open(streamfn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
			if (ofd == -1) {
				perror(streamfn);
				return 11;
			}
		}
		lseek(ifd, h.overHead * SECTORSZ, SEEK_SET);
		vmdkparsestream(ifd, &h, ofd);
		setsize(ofd, h.capacity);
		if (ofd != -1 && close(ofd) == -1)
			perror("close");
	}

	if (vmdkfn) {
		ofd = open(vmdkfn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (ofd == -1) {
			perror(vmdkfn);
			return 12;
		}
		writevmdk(ifd, ofd);
		if (close(ofd) == -1)
			perror("close");
	}

	return 0;
}
