"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods").Inflater;
const Utils = require("../../util");

describe("method - inflater", () => {
    const nodeMajor = +process.versions.node.split(".")[0];
    // 1 MiB of zeros deflates to roughly 1 KiB - a small decompression bomb
    const BOMB_SIZE = 1024 * 1024;
    const bomb = Buffer.alloc(BOMB_SIZE);
    const deflatedBomb = zlib.deflateRawSync(bomb);
    const MAX_OUTPUT_EXCEEDED = Utils.Errors.MAX_OUTPUT_EXCEEDED().message;

    // build a zip holding the bomb, then rewrite the declared uncompressed size
    // in both the local and the central header to lie about the real size
    function bombZip(declaredSize) {
        const zip = new Zip();
        zip.addFile("bomb.bin", bomb);
        const buf = zip.toBuffer();
        const Constants = Utils.Constants;
        // single entry, so its local header starts at offset 0
        expect(buf.readUInt32LE(0)).to.equal(Constants.LOCSIG);
        buf.writeUInt32LE(declaredSize, Constants.LOCLEN);
        // archive has no comment, so the END header is the last ENDHDR bytes
        const cenOffset = buf.readUInt32LE(buf.length - Constants.ENDHDR + Constants.ENDOFF);
        expect(buf.readUInt32LE(cenOffset)).to.equal(Constants.CENSIG);
        buf.writeUInt32LE(declaredSize, cenOffset + Constants.CENLEN);
        return new Zip(buf);
    }

    describe("inflateAsync", () => {
        it("stops a bomb that exceeds the declared size", (done) => {
            new Inflater(deflatedBomb, 1024).inflateAsync(function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("stops a bomb that declares an uncompressed size of 0", (done) => {
            new Inflater(deflatedBomb, 0).inflateAsync(function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("reports malformed deflate data through the callback", (done) => {
            // 0xff starts a final block of invalid type 3 -> Z_DATA_ERROR
            new Inflater(Buffer.from([0xff, 0xff, 0xff, 0xff]), 16).inflateAsync(function (data, err) {
                expect(err).to.be.an("error");
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("inflates data matching the declared size", (done) => {
            new Inflater(deflatedBomb, BOMB_SIZE).inflateAsync(function (data, err) {
                expect(err).to.be.undefined;
                expect(data).to.have.lengthOf(BOMB_SIZE);
                done();
            });
        });

        it("inflates a genuinely empty entry declaring size 0", (done) => {
            new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflateAsync(function (data, err) {
                expect(err).to.be.undefined;
                expect(data).to.have.lengthOf(0);
                done();
            });
        });
    });

    describe("inflate", () => {
        it("stops a bomb that declares an uncompressed size of 0", function () {
            // zlib only honours maxOutputLength from node 15 onwards
            if (nodeMajor < 15) this.skip();
            expect(() => new Inflater(deflatedBomb, 0).inflate()).to.throw(RangeError);
        });

        it("inflates data matching the declared size", () => {
            expect(new Inflater(deflatedBomb, BOMB_SIZE).inflate()).to.have.lengthOf(BOMB_SIZE);
        });

        it("inflates a genuinely empty entry declaring size 0", () => {
            expect(new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflate()).to.have.lengthOf(0);
        });
    });

    describe("zip entries lying about their size", () => {
        it("readFileAsync fails on an entry exceeding its declared size", (done) => {
            const zip = bombZip(1024);
            zip.readFileAsync("bomb.bin", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("readFileAsync fails on an entry declaring size 0", (done) => {
            const zip = bombZip(0);
            zip.readFileAsync("bomb.bin", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("readAsTextAsync fails on an entry declaring size 0", (done) => {
            const zip = bombZip(0);
            zip.readAsTextAsync("bomb.bin", function (data, err) {
                expect(err).to.be.an("error");
                expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                done();
            });
        });

        it("readFile refuses to inflate an entry declaring size 0", function () {
            // zlib only honours maxOutputLength from node 15 onwards
            if (nodeMajor < 15) this.skip();
            const zip = bombZip(0);
            // the bomb is capped by zlib before the CRC check is ever reached
            expect(() => zip.readFile("bomb.bin")).to.throw(RangeError);
        });
    });
});
