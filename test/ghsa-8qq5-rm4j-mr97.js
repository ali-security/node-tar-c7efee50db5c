// Tests for path/linkpath sanitization CVEs.
// Adapted from upstream test/ghsa-8qq5-rm4j-mr97.ts for 2.2.1's API (tap 0.x + tar.Extract).
// Each CVE's patch adds its own tests to this file.

var tap = require("tap")
var tar = require("../tar.js")
var TarHeader = require("../lib/header.js")
var Entry = require("../lib/entry.js")
var ExtendedHeader = require("../lib/extended-header.js")
var ExtendedHeaderWriter = require("../lib/extended-header-writer.js")
var stripAbsolutePath = require("../lib/strip-absolute-path.js")
var SymlinkTracker = require("../lib/symlink-tracker.js")
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

function runChainExploitTest(t, linkType, typeName) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var exploitedName = "exploited-" + typeName + "-" + process.pid + ".txt"
  var exploitedFile = path.resolve(target, "..", exploitedName)
  fs.writeFileSync(exploitedFile, "original content")

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "up/.." },
    { path: "exploit", type: linkType, linkpath: "a/b/escape/" + exploitedName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    try { fs.writeFileSync(path.resolve(target, "exploit"), "pwned") } catch (e) {}
    t.equal(fs.readFileSync(exploitedFile, 'utf8'), "original content",
      "external exploited-file must NOT be modified via " + typeName + " chain")
    try { fs.unlinkSync(exploitedFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
}

tap.test("CVE-2026-26960: symlink chain exploit blocked (Link type)", function (t) {
  runChainExploitTest(t, "1", "Link")
})

tap.test("CVE-2026-26960: symlink chain exploit blocked (SymbolicLink type)", function (t) {
  runChainExploitTest(t, "2", "SymbolicLink")
})

// Variants of the GHSA-83g3-92jg-28cx chain. Each extracts the entries built
// by makeEntries(exploitedName), runs `check`, then writes "pwned" through
// `via` (relative to the target) and checks the file next to the target is
// untouched.
function runChainVariantTest(t, name, makeEntries, via, check) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var exploitedName = "exploited-" + name + "-" + process.pid + ".txt"
  var exploitedFile = path.resolve(target, "..", exploitedName)
  fs.writeFileSync(exploitedFile, "original content")
  fs.writeFileSync(tarFile, buildTar(makeEntries(exploitedName)))

  var done = false
  function finish() {
    if (done) return
    done = true
    if (check) check()
    if (via) tryWrite(path.resolve(target, via), "pwned")
    t.equal(fs.readFileSync(exploitedFile, "utf8"), "original content",
      "file outside the extraction target is untouched")
    rimraf.sync(exploitedFile)
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor)
}

tap.test("CVE-2026-26960: regular file through the symlink chain is not written outside", function (t) {
  runChainVariantTest(t, "file", function (name) {
    return [
      { path: "a/", type: "5", mode: 0755 },
      { path: "a/b/", type: "5", mode: 0755 },
      { path: "a/b/up", type: "2", linkpath: "../.." },
      { path: "a/b/escape", type: "2", linkpath: "up/.." },
      { path: "a/b/escape/" + name, type: "0", body: "pwned" },
      { path: "a/b/up/inner.txt", type: "0", body: "through a symlink" }
    ]
  }, null, function () {
    t.notOk(exists(path.resolve(target, "inner.txt")),
      "file not extracted through a symlink from the archive")
  })
})

tap.test("CVE-2026-26960: symlink target re-entering a symlinked dir via '..' is not created", function (t) {
  runChainVariantTest(t, "dotdot", function (name) {
    return [
      { path: "a/", type: "5", mode: 0755 },
      { path: "a/b/", type: "5", mode: 0755 },
      { path: "a/c/", type: "5", mode: 0755 },
      { path: "a/b/up", type: "2", linkpath: "../.." },
      // lexically a/b/<name>, but a/b/up/.. is the target's parent
      { path: "a/c/exploit", type: "2", linkpath: "../b/up/../" + name }
    ]
  }, "a/c/exploit", function () {
    t.notOk(exists(path.resolve(target, "a/c/exploit")), "escaping symlink not created")
  })
})

tap.test("CVE-2026-26960: differently spelled paths of the chain are recognized", function (t) {
  runChainVariantTest(t, "spelling", function (name) {
    return [
      { path: "./a/", type: "5", mode: 0755 },
      { path: "./a/b/", type: "5", mode: 0755 },
      { path: "./a/b/up", type: "2", linkpath: "../.." },
      { path: "a//b/escape", type: "2", linkpath: "up/.." },
      { path: "exploit", type: "2", linkpath: "./a/b/escape/" + name }
    ]
  }, "exploit", function () {
    t.notOk(exists(path.resolve(target, "a/b/escape")), "chained symlink not created")
  })
})

tap.test("CVE-2026-26960: hardlink to a symlink from the archive is not created", function (t) {
  // a/s points at <target>/<name>, but a hardlink to it in the target root is
  // the same relative symlink resolved from there: <target>/../<name>
  runChainVariantTest(t, "hardlink-to-symlink", function (name) {
    return [
      { path: "a/", type: "5", mode: 0755 },
      { path: "a/s", type: "2", linkpath: "../" + name },
      { path: "exploit", type: "1", linkpath: "a/s" }
    ]
  }, "exploit", function () {
    t.ok(fs.lstatSync(path.resolve(target, "a/s")).isSymbolicLink(), "in-tree symlink extracted")
  })
})

tap.test("CVE-2026-26960: symlink chain declared in the reverse order is not completed", function (t) {
  runChainVariantTest(t, "reverse", function (name) {
    return [
      { path: "a/", type: "5", mode: 0755 },
      { path: "a/b/", type: "5", mode: 0755 },
      { path: "exploit", type: "2", linkpath: "a/b/escape/" + name },
      { path: "a/b/escape", type: "2", linkpath: "up/.." },
      { path: "a/b/up", type: "2", linkpath: "../.." }
    ]
  }, "exploit", function () {
    t.notOk(exists(path.resolve(target, "a/b/escape")),
      "symlink redirecting an earlier symlink not created")
  })
})

tap.test("CVE-2026-26960: symlink with '..' in its path cannot extend the chain", function (t) {
  runChainVariantTest(t, "dotdot-path", function (name) {
    return [
      { path: "a/", type: "5", mode: 0755 },
      { path: "a/b/", type: "5", mode: 0755 },
      { path: "a/b/up", type: "2", linkpath: "../.." },
      { path: "a/b/x/../escape", type: "2", linkpath: "up/.." },
      { path: "exploit", type: "2", linkpath: "a/b/escape/" + name }
    ]
  }, "exploit", function () {
    t.notOk(exists(path.resolve(target, "a/b/escape")), "entry with '..' in its path not created")
  })
})

tap.test("CVE-2026-26960: in-archive symlinks to symlinks keep working", function (t) {
  extractEntries(t, [
    { path: "lib/", type: "5", mode: 0755 },
    { path: "lib/libz.so", type: "2", linkpath: "libz.so.1" },
    { path: "lib/libz.so.1", type: "2", linkpath: "libz.so.1.2.3" },
    { path: "lib/libz.so.1.2.3", type: "0", body: "zlib" },
    { path: "constructor/", type: "5", mode: 0755 },
    { path: "constructor/file.txt", type: "0", body: "proto" },
    { path: "lib/up", type: "2", linkpath: ".." }
  ], function () {
    t.equal(fs.readFileSync(path.resolve(target, "lib/libz.so"), "utf8"), "zlib",
      "versioned library symlink chain resolves")
    t.equal(fs.readlinkSync(path.resolve(target, "lib/libz.so.1")), "libz.so.1.2.3",
      "intermediate symlink extracted")
    t.equal(fs.readFileSync(path.resolve(target, "constructor/file.txt"), "utf8"), "proto",
      "directory named like an Object.prototype member extracted")
    t.equal(fs.readlinkSync(path.resolve(target, "lib/up")), "..",
      "symlink to the extraction root extracted")
    t.end()
  })
})

tap.test("CVE-2026-26960: symlink tracker matches paths case-insensitively when asked", function (t) {
  var ci = SymlinkTracker(target, true)
  ci.record("a/b/UP", "../..")
  t.equal(ci.findInHardlinkPath("A/b/up/x"), "A/b/up", "hardlink path, other case")
  t.equal(ci.findInSymlinkTarget("a/b/escape", "Up/.."), "a/b/Up", "symlink target, other case")
  t.ok(ci.findInDirChain("a/B/up/file"), "directory chain, other case")

  var cs = SymlinkTracker(target, false)
  cs.record("a/b/UP", "../..")
  t.equal(cs.findInHardlinkPath("a/b/up/x"), null, "distinct names on a case-sensitive filesystem")
  t.equal(cs.findInDirChain("constructor/file"), null, "no Object.prototype false positives")
  t.end()
})

// CVE-2026-59874: a negative `size`, from the ustar header or from a pax
// extended header, must never reach an entry. Its byte count could then never
// run down to zero, so the entry never ends and swallows the rest of the tar.

// A ustar header whose 12-byte size field holds -n in GNU base-256 form
// (0xFF marker, big-endian two's complement). Written by hand rather than
// through TarHeader.encode, since its base-256 writer mangles multi-byte values.
function negativeSizeHeader(props, n) {
  var block = makeHeader(props)
  var off = tar.fieldOffs[tar.fields.size]
  var end = tar.fieldEnds[tar.fields.size]
  // two's complement of n is the bitwise inverse of n - 1
  var m = n - 1
  for (var i = end - 1; i >= off; i--) {
    var b = m % 256
    block[i] = 0xFF - b
    m = (m - b) / 256
  }
  // checksum is taken with the cksum field read as spaces, then written
  // as 6 octal digits, a NUL and a space
  var sum = TarHeader.prototype.calcSum(block).toString(8)
  while (sum.length < 6) sum = "0" + sum
  var cOff = tar.fieldOffs[tar.fields.cksum]
  block.write(sum, cOff, 6, "ascii")
  block[cOff + 6] = 0
  block[cOff + 7] = 0x20
  return block
}

// feed a pax extended header body straight into an ExtendedHeader entry
function paxFields(body) {
  var buf = new Buffer(body)
  var eh = new ExtendedHeader({ path: "PaxHeader/x", type: "x", size: buf.length })
  eh.on("error", function () {})
  eh.write(buf)
  eh.end()
  return eh.fields
}

// Parse a tarball, writing it to the parser by hand: pipe() tears down on the
// first error, which would turn a desynchronized parser into a hang.
function parseTar(buf, cb) {
  var parser = tar.Parse()
  var entries = []
  var errors = []
  var done = false
  parser.on("entry", function (entry) {
    var rec = { path: entry.path, size: entry.props.size, body: "" }
    entries.push(rec)
    entry.on("data", function (c) { rec.body += c.toString() })
  })
  parser.on("error", function (er) { errors.push(er.message) })
  parser.on("end", function () {
    if (done) return
    done = true
    cb(entries, errors)
  })
  for (var i = 0; i < buf.length; i += 512) parser.write(buf.slice(i, i + 512))
  parser.end()
}

tap.test("CVE-2026-59874: no negative size from a ustar header", function (t) {
  var block = negativeSizeHeader({ path: "neg.txt", type: "0" }, 1000)
  var raw = block.slice(tar.fieldOffs[tar.fields.size], tar.fieldEnds[tar.fields.size])
  t.ok(TarHeader.parseNumeric(raw) < 0, "fixture size field holds a negative number")

  var h = new TarHeader(block)
  t.ok(h.cksumValid, "fixture checksum is valid")
  // stubbornly refuse
  t.equal(h.size, 0, "negative size is not honored")
  t.equal(h.path, "neg.txt", "rest of the header still decoded")
  t.end()
})

tap.test("CVE-2026-59874: no negative size from a pax extended header", function (t) {
  t.equivalent(paxFields("14 size=-1000\n"), {}, "negative pax size dropped")
  t.equivalent(paxFields("13 size=1000\n"), { size: 1000 }, "positive pax size kept")
  t.equivalent(paxFields("12 size=abc\n"), {}, "non-numeric pax size dropped")
  t.equivalent(paxFields("14 size=-1000\n10 uid=42\n"), { uid: 42 },
    "records after a dropped size are still parsed")
  t.end()
})

tap.test("CVE-2026-59874: an entry never takes a negative size", function (t) {
  var e = new Entry({ path: "neg.txt", type: "0", size: -1000 })
  t.equal(e.size, 0, "negative header size")
  t.equal(e.props.size, 0, "negative header size in props")
  t.equal(e._remaining, 0, "no negative byte count")

  e = new Entry({ path: "neg.txt", type: "0", size: 5 }, { size: -1000 })
  t.equal(e.size, 0, "negative extended header size")
  t.equal(e._remaining, 0, "no negative byte count from extended header")

  e = new Entry({ path: "neg.txt", type: "0", size: 5 }, null, { size: -1000 })
  t.equal(e.size, 0, "negative global extended header size")
  t.equal(e._remaining, 0, "no negative byte count from global extended header")

  e = new Entry({ path: "ok.txt", type: "0", size: 5 })
  t.equal(e.size, 5, "positive size kept")
  t.end()
})

tap.test("CVE-2026-59874: pax extended header is not written with a negative size", function (t) {
  var w = new ExtendedHeaderWriter({ path: "neg.txt", size: -1000, uid: 42 })
  w._encodeFields()
  var body = Buffer.concat(w.body).toString()
  t.equal(body.indexOf("size="), -1, "negative size not encoded")
  t.notEqual(body.indexOf(" uid=42\n"), -1, "other fields still encoded")

  w = new ExtendedHeaderWriter({ path: "ok.txt", size: 1000 })
  w._encodeFields()
  body = Buffer.concat(w.body).toString()
  t.notEqual(body.indexOf(" size=1000\n"), -1, "positive size encoded")
  t.end()
})

function expectParsedAfterNegativeSize(t, entries, errors, first) {
  t.equivalent(errors, [], "no parse errors")
  t.equal(entries.length, 2, "parser did not get stuck on the negative size")
  t.equivalent(entries[0], first, "entry with a negative size")
  t.equivalent(entries[1], { path: "after.txt", size: 5, body: "after" },
    "following entry is reached intact")
  t.end()
}

tap.test("CVE-2026-59874: negative ustar size does not swallow the rest of the tar", function (t) {
  var buf = Buffer.concat([
    negativeSizeHeader({ path: "neg.txt", type: "0" }, 1000),
    buildTar([{ path: "after.txt", type: "0", body: "after" }])
  ])
  parseTar(buf, function (entries, errors) {
    expectParsedAfterNegativeSize(t, entries, errors,
      { path: "neg.txt", size: 0, body: "" })
  })
})

tap.test("CVE-2026-59874: negative pax size does not swallow the rest of the tar", function (t) {
  var buf = buildTar([
    { path: "PaxHeader/a.txt", type: "x", body: "14 size=-1000\n" },
    { path: "a.txt", type: "0", body: "hello" },
    { path: "after.txt", type: "0", body: "after" }
  ])
  parseTar(buf, function (entries, errors) {
    expectParsedAfterNegativeSize(t, entries, errors,
      { path: "a.txt", size: 5, body: "hello" })
  })
})

tap.test("CVE-2026-59874: negative global pax size does not swallow the rest of the tar", function (t) {
  var buf = buildTar([
    { path: "GlobalHead", type: "g", body: "14 size=-1000\n" },
    { path: "a.txt", type: "0", body: "hello" },
    { path: "after.txt", type: "0", body: "after" }
  ])
  parseTar(buf, function (entries, errors) {
    expectParsedAfterNegativeSize(t, entries, errors,
      { path: "a.txt", size: 5, body: "hello" })
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
