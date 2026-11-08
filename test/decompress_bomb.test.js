"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// The checks above observe RSS, which the OS may not grow for a zero-filled
// mapping that is never touched. These checks record every Buffer.alloc made while
// the crafted entry is read and refuse any request above ALLOC_LIMIT before it can
// reserve memory, so an allocation driven by the declared size is caught directly,
// on every platform and Node version, for both the sync and the async read paths.
describe("decompression bomb (declared size) - CVE-2026-39244 - allocation bound", () => {
    const zlib = require("zlib");
    const DECLARED = 3 * 1024 * 1024 * 1024;
    // the crafted entries carry a single byte of payload
    const ALLOC_LIMIT = 1024 * 1024;
    const storedPayload = Buffer.from("A");
    // a valid deflate stream whose real output (one byte) is far below the declared size
    const deflatedPayload = zlib.deflateRawSync(Buffer.from("A"));

    function withAllocationGuard(fn) {
        const realAlloc = Buffer.alloc;
        const seen = { largest: 0, error: null };
        Buffer.alloc = function (size) {
            if (size > seen.largest) seen.largest = size;
            if (size > ALLOC_LIMIT) {
                throw new RangeError("test guard: refused Buffer.alloc(" + size + ")");
            }
            return realAlloc.apply(Buffer, arguments);
        };
        try {
            fn();
        } catch (err) {
            seen.error = err;
        } finally {
            Buffer.alloc = realAlloc;
        }
        return seen;
    }

    it("getData on a STORED entry allocates from the real data, not the declared size", () => {
        const entry = new Zip(craftBomb(DECLARED, 0 /* STORED */, storedPayload)).getEntries()[0];
        expect(entry.header.size).to.equal(DECLARED);

        const seen = withAllocationGuard(() => entry.getData());

        expect(seen.largest, "largest Buffer.alloc request").to.be.at.most(ALLOC_LIMIT);
        expect(seen.error).to.be.an("error");
        expect(seen.error.message).to.match(/CRC32/);
    });

    it("getData on a DEFLATED entry allocates from the real data, not the declared size", () => {
        const entry = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflatedPayload)).getEntries()[0];
        expect(entry.header.size).to.equal(DECLARED);

        const seen = withAllocationGuard(() => entry.getData());

        expect(seen.largest, "largest Buffer.alloc request").to.be.at.most(ALLOC_LIMIT);
        expect(seen.error).to.be.an("error");
        expect(seen.error.message).to.match(/CRC32/);
    });

    it("getDataAsync on a STORED entry allocates from the real data, not the declared size", () => {
        const entry = new Zip(craftBomb(DECLARED, 0 /* STORED */, storedPayload)).getEntries()[0];
        let cbData = null;
        let cbErr = null;

        const seen = withAllocationGuard(() =>
            entry.getDataAsync(function (data, err) {
                cbData = data;
                cbErr = err;
            })
        );

        expect(seen.largest, "largest Buffer.alloc request").to.be.at.most(ALLOC_LIMIT);
        expect(cbErr).to.be.an("error");
        expect(cbErr.message).to.match(/CRC32/);
        expect(cbData.length).to.equal(storedPayload.length);
    });

    it("getDataAsync on a DEFLATED entry allocates from the real data, not the declared size", function (done) {
        const entry = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflatedPayload)).getEntries()[0];
        let seen;
        try {
            seen = withAllocationGuard(() =>
                entry.getDataAsync(function (data, err) {
                    try {
                        expect(err).to.be.an("error");
                        expect(err.message).to.match(/CRC32/);
                        expect(data.length).to.equal(1);
                        done();
                    } catch (e) {
                        done(e);
                    }
                })
            );
            expect(seen.largest, "largest Buffer.alloc request").to.be.at.most(ALLOC_LIMIT);
            expect(seen.error).to.equal(null);
        } catch (e) {
            done(e);
        }
    });

    it("still reads a genuine STORED entry whose declared size matches its data", () => {
        const payload = Buffer.from("stored payload");
        const zip = new Zip();
        zip.addFile("plain.txt", payload);
        zip.getEntry("plain.txt").header.method = 0; // STORED
        const round = new Zip(zip.toBuffer());
        const entry = round.getEntry("plain.txt");

        expect(entry.header.method).to.equal(0);
        expect(entry.header.size).to.equal(payload.length);
        expect(round.readFile("plain.txt").equals(payload)).to.equal(true);
    });
});
