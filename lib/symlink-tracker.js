// CVE-2026-26960 (GHSA-83g3-92jg-28cx) — analyst-authored module for tar 2.2.1.
// Tracks symlinks parsed from the tar stream so later entries cannot be extracted
// through them. Upstream's fix uses `lstatSync` against the filesystem; that does
// not work in 2.2.1 because fstream writes asynchronously, so a symlink declared
// earlier in the same tar may not be on disk when later entries are checked.
//
// Paths are compared in a normalized form ('\' and '/' both separate, '' and '.'
// are dropped, '..' pops), so that 'a/b', './a/b' and 'a//b' -- which fstream all
// writes to the same place -- are recognized as the same entry.

var path = require("path")

// keys are prefixed so that names like '__proto__' or 'constructor' never
// collide with the members of Object.prototype
var KEY_PREFIX = "k:"

var hasOwn = Object.prototype.hasOwnProperty

function SymlinkTracker (cwd, caseInsensitive) {
  if (!(this instanceof SymlinkTracker)) {
    return new SymlinkTracker(cwd, caseInsensitive)
  }
  this.cwd = path.resolve(cwd)
  // on case-insensitive filesystems (the default on win32 and darwin)
  // 'a/B' and 'A/b' name the same directory
  this.caseInsensitive = typeof caseInsensitive === "boolean"
    ? caseInsensitive
    : (process.platform === "win32" || process.platform === "darwin")
  // tar-relative paths of the symlinks extracted so far
  this.seen = {}
  // tar-relative paths that the targets of the symlinks extracted so far
  // walk through, mapped to the path of the (first) symlink that does
  this.traversed = {}
}

SymlinkTracker.prototype._key = function (parts) {
  var key = parts.join("/")
  return KEY_PREFIX + (this.caseInsensitive ? key.toLowerCase() : key)
}

SymlinkTracker.prototype._has = function (parts) {
  return parts.length > 0 && hasOwn.call(this.seen, this._key(parts))
}

// Splits a tar-relative path into its normalized components.
function split (p) {
  var raw = String(p || "").replace(/\\/g, "/").split("/")
  var parts = []
  for (var i = 0; i < raw.length; i++) {
    var part = raw[i]
    if (part === "" || part === ".") continue
    if (part === "..") parts.pop()
    else parts.push(part)
  }
  return parts
}

// Walks `linkpath` one component at a time starting from the directory `base`
// (a component list), resolving '..' as it goes -- the way the OS does when it
// follows the path. Calls `visit` with the components reached after each step
// and stops at the first one for which it returns true. The last component is
// only visited when `includeLast` is set. Returns the components the walk
// stopped at, or null.
function walk (base, linkpath, includeLast, visit) {
  var cur = base.slice()
  var raw = String(linkpath || "").replace(/\\/g, "/").split("/")
  var end = includeLast ? raw.length : raw.length - 1
  for (var i = 0; i < end; i++) {
    var part = raw[i]
    if (part === "" || part === ".") continue
    if (part === "..") {
      cur.pop()
      continue
    }
    cur.push(part)
    if (visit(cur)) return cur
  }
  return null
}

// Walks the directory chain from cwd to entry's parent. Returns the absolute
// directory whose tar-relative key is a recorded symlink, or null.
SymlinkTracker.prototype.findInDirChain = function (entryPath) {
  var parts = split(entryPath)
  for (var i = 1; i < parts.length; i++) {
    var dir = parts.slice(0, i)
    if (this._has(dir)) return path.resolve(this.cwd, dir.join("/"))
  }
  return null
}

// Walks the components of a hardlink linkpath (tar-relative), including the
// last one: a hardlink to a symlink is a copy of that symlink in another
// directory, where its relative target may point somewhere else entirely.
// Returns the prefix that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInHardlinkPath = function (linkpath) {
  var self = this
  var hit = walk([], linkpath, true, function (cur) {
    return self._has(cur)
  })
  return hit ? hit.join("/") : null
}

// Walks the resolved hardlink target path (absolute, inside cwd). Returns the
// absolute path that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInLinkTargetChain = function (linkTarget) {
  var self = this
  var rel = path.relative(this.cwd, linkTarget)
  if (!rel) return null
  var hit = walk([], rel, true, function (cur) {
    return self._has(cur)
  })
  return hit ? path.resolve(this.cwd, hit.join("/")) : null
}

// Walks a SymbolicLink's own target path components, starting from the
// directory that contains the link. The last component may itself be a
// symlink: it is resolved relative to its own location, not this one.
// Returns the candidate that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInSymlinkTarget = function (entryPath, linkpath) {
  var self = this
  var dir = split(entryPath).slice(0, -1)
  var hit = walk(dir, linkpath, false, function (cur) {
    return self._has(cur)
  })
  return hit ? hit.join("/") : null
}

// The same chain in the reverse order: a symlink created earlier in the archive
// walks through entryPath, so a symlink placed there now would redirect it.
// Returns the path of that earlier symlink, or null.
SymlinkTracker.prototype.findTraversedBy = function (entryPath) {
  var parts = split(entryPath)
  if (!parts.length) return null
  var key = this._key(parts)
  return hasOwn.call(this.traversed, key) ? this.traversed[key] : null
}

// Records a symlink declared at entryPath (tar-relative) pointing at linkpath.
SymlinkTracker.prototype.record = function (entryPath, linkpath) {
  var self = this
  var parts = split(entryPath)
  if (!parts.length) return
  this.seen[this._key(parts)] = true

  var by = parts.join("/")
  walk(parts.slice(0, -1), linkpath, false, function (cur) {
    var key = self._key(cur)
    if (!hasOwn.call(self.traversed, key)) self.traversed[key] = by
    return false
  })
}

module.exports = SymlinkTracker
