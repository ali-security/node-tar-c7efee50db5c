// Tests for path/linkpath sanitization CVEs.
// Adapted from upstream test/ghsa-8qq5-rm4j-mr97.ts for 2.2.1's API (tap 0.x + tar.Extract).
// Each CVE's patch adds its own tests to this file.

var tap = require("tap")
var tar = require("../tar.js")
var TarHeader = require("../lib/header.js")
var stripAbsolutePath = require("../lib/strip-absolute-path.js")
var fs = require("fs")
var path = require("path")
var rimraf = require("rimraf")
var mkdirp = require("mkdirp")

var target = path.resolve(__dirname, "tmp/ghsa-8qq5")
var tarFile = path.resolve(__dirname, "tmp/ghsa-8qq5.tar")

function makeHeader(props) {
  return TarHeader.encode({
    path: props.path, mode: props.mode || 0644, uid: 0, gid: 0,
    size: props.size || 0, mtime: 0, cksum: 0, type: props.type,
    linkpath: props.linkpath || '', ustar: 'ustar\0', ustarver: '00',
    uname: '', gname: '', devmaj: 0, devmin: 0, fill: ''
  })
}

// new Buffer(n) is not zero-filled on old node versions
function zeroes(n) {
  var b = new Buffer(n)
  b.fill(0)
  return b
}

// entries may carry a string `body`, padded out to whole 512-byte blocks
function buildTar(entries) {
  var chunks = []
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i]
    var body = typeof entry.body === "string" ? new Buffer(entry.body) : null
    if (body) entry.size = body.length
    chunks.push(makeHeader(entry))
    if (body && body.length) {
      var block = zeroes(Math.ceil(body.length / 512) * 512)
      body.copy(block)
      chunks.push(block)
    }
  }
  chunks.push(zeroes(1024))
  return Buffer.concat(chunks)
}

tap.test("preclean", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  mkdirp.sync(path.dirname(tarFile))
  t.pass("cleaned")
  t.end()
})

// CVE-2026-29786: drive-relative path c:../escape.txt is rejected
// The fix reorders: strip absolute root THEN check '..'.
// Before: c:../foo split to ['c:..', 'foo'] — no '..' match, not caught on Linux.
// After: strip 'c:' root → '../foo' → split → '..' detected → rejected.
tap.test("CVE-2026-29786: drive-relative path c:../escape.txt is rejected", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var escapeFile = path.resolve(target, "..", "cve29786-escape-" + process.pid + ".txt")

  var tarBuf = buildTar([
    { path: "c:../cve29786-escape-" + process.pid + ".txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var exists = false
      try { fs.lstatSync(escapeFile); exists = true } catch (e) {}
      t.equal(exists, false,
        "c:../escape file should not be created outside target")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-29786: absolute path with '..' is stripped before '..' check
// /../a/target: strip '/' → '../a/target' → '..' detected → rejected (for path).
tap.test("CVE-2026-29786: absolute path with embedded '..' is rejected after stripping", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var tarBuf = buildTar([
    { path: "/../a/target.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      // '../a/target.txt' should be rejected because '..' in path
      var exists = false
      try { fs.lstatSync(path.resolve(target, "../a/target.txt")); exists = true } catch (e) {}
      t.equal(exists, false,
        "/../a/target.txt should be rejected after stripping root")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: linkpaths of hard and symbolic links are sanitized like paths.
// A file outside of the extraction target that the links try to reach.
var secretFile = path.resolve(__dirname, "tmp/ghsa-8qq5-secret.txt")
// A sibling directory whose name has the extraction target as a prefix.
var evilDir = target + "-evil"

function exists(p) {
  try { fs.lstatSync(p); return true } catch (e) { return false }
}

function resetSecret() {
  rimraf.sync(secretFile)
  fs.writeFileSync(secretFile, "ORIGINAL DATA")
}

function extractEntries(t, entries, cb) {
  rimraf.sync(target)
  mkdirp.sync(target)
  fs.writeFileSync(tarFile, buildTar(entries))

  var done = false
  var extractor = tar.Extract({ path: target })
  extractor.on("error", function (er) {
    if (done) return
    done = true
    t.fail("extraction failed: " + (er && er.message))
    t.end()
  })
  extractor.on("end", function () {
    if (done) return
    done = true
    cb()
  })

  fs.createReadStream(tarFile).pipe(extractor)
}

tap.test("CVE-2026-23745: hardlink with absolute linkpath does not clobber its target", function (t) {
  resetSecret()
  t.ok(Buffer.byteLength(secretFile) <= 100, "absolute linkpath fits in the ustar header")
  // the in-tree location the absolute linkpath is confined to once its root is stripped
  var inTree = stripAbsolutePath(secretFile.replace(/\\/g, "/"))[1]

  extractEntries(t, [
    { path: inTree, type: "0", body: "IN TREE" },
    { path: "exploit_hard", type: "1", linkpath: secretFile }
  ], function () {
    fs.writeFileSync(path.resolve(target, "exploit_hard"), "OVERWRITTEN")
    t.equal(fs.readFileSync(secretFile, "utf8"), "ORIGINAL DATA",
      "file outside the extraction target is untouched")
    t.equal(fs.readFileSync(path.resolve(target, inTree), "utf8"), "OVERWRITTEN",
      "hardlink was confined to the extraction target")
    t.end()
  })
})

tap.test("CVE-2026-23745: hardlink with escaping '..' linkpath is not created", function (t) {
  resetSecret()

  extractEntries(t, [
    { path: "exploit_hard", type: "1", linkpath: "../" + path.basename(secretFile) },
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/exploit_hard", type: "1", linkpath: "a/../../" + path.basename(secretFile) }
  ], function () {
    t.notOk(exists(path.resolve(target, "exploit_hard")), "escaping hardlink not created")
    t.notOk(exists(path.resolve(target, "a/exploit_hard")), "nested escaping hardlink not created")
    t.equal(fs.readFileSync(secretFile, "utf8"), "ORIGINAL DATA",
      "file outside the extraction target is untouched")
    t.end()
  })
})

tap.test("CVE-2026-23745: symlink with absolute linkpath has its root stripped", function (t) {
  var targetSym = "/some/absolute/path"

  extractEntries(t, [
    { path: "exploit_sym", type: "2", linkpath: targetSym }
  ], function () {
    var lp = fs.readlinkSync(path.resolve(target, "exploit_sym"))
    t.notEqual(lp, targetSym, "symlink does not point at the absolute path")
    t.equal(lp, "some/absolute/path", "absolute root stripped from linkpath")
    t.end()
  })
})

tap.test("CVE-2026-23745: symlink escaping the extraction target is not created", function (t) {
  resetSecret()

  extractEntries(t, [
    { path: "secret.txt", type: "2", linkpath: "../" + path.basename(secretFile) }
  ], function () {
    t.notOk(exists(path.resolve(target, "secret.txt")), "escaping symlink not created")
    t.equal(fs.readFileSync(secretFile, "utf8"), "ORIGINAL DATA",
      "file outside the extraction target is untouched")
    t.end()
  })
})

tap.test("CVE-2026-23745: absolute symlink with '..' is normalized", function (t) {
  extractEntries(t, [
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/link", type: "2", linkpath: "/../a/target" }
  ], function () {
    t.equal(fs.readlinkSync(path.resolve(target, "a/link")), "../a/target",
      "symlink target should be normalized")
    t.end()
  })
})

tap.test("CVE-2026-23745: valid relative links with '..' are extracted", function (t) {
  extractEntries(t, [
    { path: "foo/", type: "5", mode: 0755 },
    { path: "foo/file.txt", type: "0", mode: 0644, body: "hello world" },
    { path: "bar/", type: "5", mode: 0755 },
    { path: "bar/link.txt", type: "2", linkpath: "../foo/file.txt" },
    { path: "bar/up", type: "2", linkpath: ".." },
    { path: "bar/hard.txt", type: "1", linkpath: "bar/../foo/file.txt" },
    { path: "bar/badlink.txt", type: "2", linkpath: "../../oh/no" }
  ], function () {
    t.ok(fs.lstatSync(path.resolve(target, "foo/file.txt")).isFile(), "regular file extracted")
    t.ok(fs.lstatSync(path.resolve(target, "bar/link.txt")).isSymbolicLink(),
      "relative symlink extracted")
    t.equal(fs.readlinkSync(path.resolve(target, "bar/link.txt")), "../foo/file.txt",
      "relative symlink target preserved")
    t.equal(fs.readFileSync(path.resolve(target, "bar/link.txt"), "utf8"), "hello world",
      "relative symlink resolves within the extraction target")
    t.equal(fs.readlinkSync(path.resolve(target, "bar/up")), "..",
      "symlink to the extraction root itself preserved")
    t.equal(fs.readFileSync(path.resolve(target, "bar/hard.txt"), "utf8"), "hello world",
      "in-tree hardlink with '..' extracted")
    t.notOk(exists(path.resolve(target, "bar/badlink.txt")), "escaping symlink not created")
    t.end()
  })
})

tap.test("CVE-2026-23745: symlink into a sibling dir sharing the target's name prefix is not created", function (t) {
  rimraf.sync(evilDir)
  mkdirp.sync(evilDir)
  fs.writeFileSync(path.resolve(evilDir, "pwn"), "EVIL")
  var evilName = path.basename(evilDir)

  extractEntries(t, [
    { path: "evil_sym", type: "2", linkpath: "../" + evilName + "/pwn" },
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/evil_sym", type: "2", linkpath: "../../" + evilName + "/pwn" }
  ], function () {
    t.notOk(exists(path.resolve(target, "evil_sym")), "sibling-prefix symlink not created")
    t.notOk(exists(path.resolve(target, "a/evil_sym")),
      "nested sibling-prefix symlink not created")
    rimraf.sync(evilDir)
    t.end()
  })
})

// CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve
tap.test("CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "c:foo/inner.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var expected = path.resolve(target, "foo/inner.txt")
      var exists = false
      try { fs.statSync(expected); exists = true } catch (e) {}
      t.equal(exists, true,
        "drive-prefix 'c:foo/inner.txt' should extract to target/foo/inner.txt after stripping")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// a dangling link must fail the assertions below, not crash the test file
function tryWrite(p, data) {
  try { fs.writeFileSync(p, data) } catch (e) {}
}

// CVE-2026-31802 (GHSA-9ppj-qmqm-q256): a drive-relative linkpath such as
// 'C:../../../x' must be checked for escapes AFTER its drive root is stripped,
// because the stripped value is what the link is actually created with.
tap.test("CVE-2026-31802: drive-relative symlink linkpath escaping the target is not created", function (t) {
  // where 'C:../../../<name>' from a/b/ (and 'c:../<name>' from the root) lands
  var victim = path.resolve(target, "..", "cve31802-target.txt")
  rimraf.sync(victim)
  fs.writeFileSync(victim, "ORIGINAL DATA")
  rimraf.sync(evilDir)
  mkdirp.sync(evilDir)
  fs.writeFileSync(path.resolve(evilDir, "pwn"), "EVIL")
  var evilName = path.basename(evilDir)

  extractEntries(t, [
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/l", type: "2", linkpath: "C:../../../" + path.basename(victim) },
    { path: "rootesc", type: "2", linkpath: "c:../" + path.basename(victim) },
    { path: "a/winrootdotsescapelink", type: "2", linkpath: "c:..\\..\\..\\..\\foo\\bar" },
    { path: "evil_drive_sym", type: "2", linkpath: "c:../" + evilName + "/pwn" }
  ], function () {
    t.notOk(exists(path.resolve(target, "a/b/l")),
      "drive-relative symlink climbing out of the target not created")
    t.notOk(exists(path.resolve(target, "rootesc")),
      "top-level drive-relative escaping symlink not created")
    t.notOk(exists(path.resolve(target, "a/winrootdotsescapelink")),
      "backslash drive-relative escaping symlink not created")
    t.notOk(exists(path.resolve(target, "evil_drive_sym")),
      "drive-relative symlink into a sibling-prefix dir not created")

    // writing where the links would have been must not reach outside the target
    tryWrite(path.resolve(target, "a/b/l"), "PWNED")
    tryWrite(path.resolve(target, "rootesc"), "PWNED")
    tryWrite(path.resolve(target, "evil_drive_sym"), "PWNED")
    t.equal(fs.readFileSync(victim, "utf8"), "ORIGINAL DATA",
      "file outside the extraction target is untouched")
    t.equal(fs.readFileSync(path.resolve(evilDir, "pwn"), "utf8"), "EVIL",
      "file in the sibling-prefix dir is untouched")
    rimraf.sync(victim)
    rimraf.sync(evilDir)
    t.end()
  })
})

tap.test("CVE-2026-31802: drive-relative hardlink linkpath escaping the target is not created", function (t) {
  resetSecret()
  var secretName = path.basename(secretFile)

  extractEntries(t, [
    // decoy at the in-tree spot an unchecked linkpath would be re-rooted to
    { path: secretName, type: "0", body: "DECOY" },
    { path: "exploit_hard", type: "1", linkpath: "c:../" + secretName }
  ], function () {
    t.notOk(exists(path.resolve(target, "exploit_hard")),
      "drive-relative escaping hardlink not created")
    t.equal(fs.readFileSync(secretFile, "utf8"), "ORIGINAL DATA",
      "file outside the extraction target is untouched")
    t.end()
  })
})

tap.test("CVE-2026-31802: in-tree drive-relative symlink linkpath keeps working", function (t) {
  extractEntries(t, [
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/ok/", type: "5", mode: 0755 },
    { path: "a/ok/target", type: "0", mode: 0644, body: "hello world" },
    { path: "a/b/ok_root", type: "2", linkpath: "c:../ok/target" }
  ], function () {
    t.equal(fs.readlinkSync(path.resolve(target, "a/b/ok_root")), "../ok/target",
      "drive root stripped, in-tree '..' preserved")
    t.equal(fs.readFileSync(path.resolve(target, "a/b/ok_root"), "utf8"), "hello world",
      "symlink resolves within the extraction target")
    t.end()
  })
})

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  rimraf.sync(secretFile)
  rimraf.sync(evilDir)
  t.pass("cleaned")
  t.end()
})
