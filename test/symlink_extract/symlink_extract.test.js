"use strict";

// Regression test for CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9):
// sanitize() only checks the textual entry path against the extraction root, so
// a symlink that already exists inside the extraction directory (an intermediate
// directory or the destination file itself) was followed by mkdir()/open() and
// the entry was written outside the root. Extraction now refuses to write through
// any symlink located below the extraction root.

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const isWin = process.platform === "win32";
const IN_THE_WAY = /There is a file in the way/;

// Creates a symlink, returning false when the platform refuses (e.g. Windows
// without the symlink privilege) so the test can be skipped instead of failing.
// Directory links use junctions on Windows, which need no special privilege.
function trySymlink(target, linkPath, isDir) {
    const type = isDir ? (isWin ? "junction" : "dir") : "file";
    try {
        fs.symlinkSync(isDir && isWin ? pth.resolve(target) : target, linkPath, type);
        return true;
    } catch (e) {
        if (e && (e.code === "EPERM" || e.code === "EACCES" || e.code === "ENOSYS" || e.code === "UNKNOWN")) return false;
        throw e;
    }
}

function build(entries) {
    const zip = new Zip();
    entries.forEach(function (e) {
        zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1]));
    });
    return new Zip(zip.toBuffer());
}

function extractAsync(zip, target, overwrite) {
    return new Promise(function (resolve) {
        let settled = false;
        zip.extractAllToAsync(target, overwrite, false, function (err) {
            if (settled) return;
            settled = true;
            resolve(err);
        });
    });
}

describe("symlink extraction CVE-2026-76845", function () {
    let base;
    let root;
    let outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        root = pth.join(base, "root");
        outside = pth.join(base, "outside");
        fs.mkdirSync(root);
        fs.mkdirSync(outside);
    });

    afterEach(function () {
        rimraf.sync(base);
    });

    function linkDirInRoot(name) {
        return trySymlink(outside, pth.join(root, name), true);
    }

    function linkFileInRoot(name, outsideFile) {
        return trySymlink(outsideFile, pth.join(root, name), false);
    }

    describe("extractAllTo", function () {
        it("rejects a file written through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/pwned.txt", "PWNED"]]);

            expect(function () {
                zip.extractAllTo(root);
            }).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
        });

        it("rejects a directory created through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/newdir/", null]]);

            expect(function () {
                zip.extractAllTo(root);
            }).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "newdir"))).to.equal(false);
        });

        it("rejects overwriting a destination file that is a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "ORIGINAL");
            if (!linkFileInRoot("victim.txt", secret)) return this.skip();
            const zip = build([["victim.txt", "PWNED"]]);

            expect(function () {
                zip.extractAllTo(root, true);
            }).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("ORIGINAL");
        });

        it("still extracts into a root that is itself reached through a symlink", function () {
            const real = pth.join(base, "real");
            fs.mkdirSync(real);
            const rootLink = pth.join(base, "rootlink");
            if (!trySymlink(real, rootLink, true)) return this.skip();
            const zip = build([
                ["dir/", null],
                ["dir/file.txt", "content"],
                ["top.txt", "top"]
            ]);

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(real, "dir", "file.txt"), "utf8")).to.equal("content");
            expect(fs.readFileSync(pth.join(real, "top.txt"), "utf8")).to.equal("top");
        });

        it("still extracts into pre-existing regular directories", function () {
            fs.mkdirSync(pth.join(root, "sub"));
            const zip = build([["sub/file.txt", "content"]]);

            zip.extractAllTo(root, true);
            expect(fs.readFileSync(pth.join(root, "sub", "file.txt"), "utf8")).to.equal("content");
        });
    });

    describe("extractEntryTo", function () {
        it("rejects a single file written through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/pwned.txt", "PWNED"]]);

            expect(function () {
                zip.extractEntryTo("link/pwned.txt", root, true, true);
            }).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
        });

        it("rejects overwriting a destination file that is a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "ORIGINAL");
            if (!linkFileInRoot("victim.txt", secret)) return this.skip();
            const zip = build([["some/dir/victim.txt", "PWNED"]]);

            expect(function () {
                zip.extractEntryTo("some/dir/victim.txt", root, false, true);
            }).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("ORIGINAL");
        });

        it("rejects an outFileName that is a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "ORIGINAL");
            if (!linkFileInRoot("victim.txt", secret)) return this.skip();
            const zip = build([["a.txt", "PWNED"]]);

            expect(function () {
                zip.extractEntryTo("a.txt", root, false, true, false, "victim.txt");
            }).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("ORIGINAL");
        });

        it("rejects directory children written through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([
                ["link/", null],
                ["link/child.txt", "PWNED"]
            ]);

            expect(function () {
                zip.extractEntryTo("link/", root, true, true);
            }).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "child.txt"))).to.equal(false);
        });

        it("still extracts a regular entry", function () {
            const zip = build([["some/dir/file.txt", "content"]]);

            zip.extractEntryTo("some/dir/file.txt", root, true, true);
            expect(fs.readFileSync(pth.join(root, "some", "dir", "file.txt"), "utf8")).to.equal("content");
        });
    });

    describe("extractAllToAsync", function () {
        it("rejects a file written through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/pwned.txt", "PWNED"]]);

            return extractAsync(zip, root, false).then(function (err) {
                expect(err).to.be.an("error");
                expect(err.message).to.match(IN_THE_WAY);
                expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
            });
        });

        it("rejects a directory created through a symlinked directory", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/newdir/", null]]);

            return extractAsync(zip, root, false).then(function (err) {
                expect(err).to.be.an("error");
                expect(fs.existsSync(pth.join(outside, "newdir"))).to.equal(false);
            });
        });

        it("rejects overwriting a destination file that is a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "ORIGINAL");
            if (!linkFileInRoot("victim.txt", secret)) return this.skip();
            const zip = build([["victim.txt", "PWNED"]]);

            return extractAsync(zip, root, true).then(function (err) {
                expect(err).to.be.an("error");
                expect(err.message).to.match(IN_THE_WAY);
                expect(fs.readFileSync(secret, "utf8")).to.equal("ORIGINAL");
            });
        });

        it("rejects through the promise form as well", function () {
            if (!linkDirInRoot("link")) return this.skip();
            const zip = build([["link/pwned.txt", "PWNED"]]);

            return zip.extractAllToAsync(root, true, false).then(
                function () {
                    throw new Error("extraction through a symlink was not rejected");
                },
                function (err) {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
                }
            );
        });

        it("still extracts a regular archive", function () {
            const zip = build([
                ["dir/", null],
                ["dir/file.txt", "content"]
            ]);

            return extractAsync(zip, root, true).then(function (err) {
                expect(err).to.equal(undefined);
                expect(fs.readFileSync(pth.join(root, "dir", "file.txt"), "utf8")).to.equal("content");
            });
        });
    });
});
