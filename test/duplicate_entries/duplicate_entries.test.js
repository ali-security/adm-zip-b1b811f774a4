"use strict";

// Regression test for GHSA-p634-w6r4-rjp2:
// A crafted archive can declare the same entry name twice. adm-zip kept every
// entry in its entry list (used by extractAllTo/getEntries) but only the last one
// in its name lookup table (used by getEntry/readFile), so getEntry() and
// extractAllTo() resolved the same name to different content: an application
// validating an entry via getEntry() before extracting the archive could approve
// one file while different bytes were written to disk under that name.
// Archives with duplicate entry names are now rejected.

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

function countOccurrences(buf, needle) {
    const n = Buffer.from(needle);
    let count = 0;
    let i = buf.indexOf(n);
    while (i !== -1) {
        count++;
        i = buf.indexOf(n, i + n.length);
    }
    return count;
}

// Returns a copy of `buf` where every occurrence of `from` is replaced by the
// same-length `to`, so all header offsets stay valid.
function replaceAll(buf, from, to) {
    const out = Buffer.from(buf);
    const f = Buffer.from(from);
    const t = Buffer.from(to);
    expect(t.length).to.equal(f.length);
    let i = out.indexOf(f);
    while (i !== -1) {
        t.copy(out, i);
        i = out.indexOf(f, i + f.length);
    }
    return out;
}

// Advisory PoC: store `placeholder` -> FIRST and `name` -> SECOND, then rename
// the placeholder in place, giving two entries both called `name`.
function craftDuplicate(name, placeholder) {
    const zip = new Zip({ noSort: true });
    zip.addFile(placeholder, Buffer.from("FIRST"));
    zip.addFile(name, Buffer.from("SECOND"));
    const buf = replaceAll(zip.toBuffer(), placeholder, name);
    // two local headers + two central directory headers carry the same name
    expect(countOccurrences(buf, name)).to.equal(4);
    expect(countOccurrences(buf, placeholder)).to.equal(0);
    return buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    const DUPLICATE = /Duplicate entry name/;
    let destination;

    beforeEach(() => {
        destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-dup-"));
    });

    afterEach(() => {
        rimraf.sync(destination);
    });

    it("getEntry() refuses to resolve a duplicated name", () => {
        const zip = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        expect(() => zip.getEntry("b.txt")).to.throw(DUPLICATE);
    });

    it("readFile() refuses to read a duplicated name", () => {
        const zip = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        expect(() => zip.readFile("b.txt")).to.throw(DUPLICATE);
    });

    it("getEntries() rejects an archive with duplicate names", () => {
        const zip = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        expect(() => zip.getEntries()).to.throw(DUPLICATE);
    });

    it("extractAllTo() rejects the archive and writes nothing", () => {
        const target = pth.join(destination, "b.txt");

        const zip = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        expect(() => zip.extractAllTo(destination, false)).to.throw(DUPLICATE);
        expect(fs.existsSync(target)).to.equal(false);

        const zipOverwrite = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        expect(() => zipOverwrite.extractAllTo(destination, true)).to.throw(DUPLICATE);
        expect(fs.existsSync(target)).to.equal(false);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate("b.txt", "a.txt"), { noSort: true });
        return zip.extractAllToAsync(destination, false).then(
            () => {
                throw new Error("extractAllToAsync should have rejected");
            },
            (err) => {
                expect(err.message).to.match(DUPLICATE);
                expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
            }
        );
    });

    it("rejects the archive at load time when readEntries is enabled", () => {
        const buf = craftDuplicate("b.txt", "a.txt");
        expect(() => new Zip(buf, { noSort: true, readEntries: true })).to.throw(DUPLICATE);
    });

    it("detects duplicates of names that shadow Object.prototype members", () => {
        const zip = new Zip(craftDuplicate("__proto__", "xxproto__"), { noSort: true });
        expect(() => zip.getEntry("__proto__")).to.throw(DUPLICATE);
        expect(({}).polluted).to.equal(undefined);
    });

    it("does not treat Object.prototype member names as duplicates", () => {
        const names = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, Buffer.from("content of " + name)));

        const reopened = new Zip(zip.toBuffer());
        expect(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort()
        ).to.deep.equal(names.slice().sort());
        names.forEach((name) => {
            expect(reopened.readFile(name).toString()).to.equal("content of " + name);
        });
    });

    it("getEntry() and extractAllTo() agree on the content of a well-formed archive", () => {
        const zip = new Zip({ noSort: true });
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));

        const reopened = new Zip(zip.toBuffer(), { noSort: true });
        const validated = reopened.getEntry("b.txt").getData().toString();
        reopened.extractAllTo(destination, false);

        expect(validated).to.equal("SECOND");
        expect(fs.readFileSync(pth.join(destination, "b.txt")).toString()).to.equal(validated);
        expect(fs.readFileSync(pth.join(destination, "a.txt")).toString()).to.equal("FIRST");
    });
});
