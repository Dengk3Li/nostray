import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fsyncDirectoryBestEffort, streamSha256File, writeDurableFileAtomic } from "./runtime-support.mjs";

// Caller supplies the bytes already hashed during the scan. Retain that exact snapshot
// on filesystems where reflink cloning is unavailable or the live file changed mid-copy.
export function persistSnapshotBlob(source, destination, capturedBytes, expectedHash) {
  const flags = fs.constants;
  if (capturedBytes.length >= 64 * 1024 && flags.COPYFILE_FICLONE_FORCE) {
    const parent = path.dirname(destination);
    fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
    const temp = path.join(parent, ".clone-" + randomUUID());
    let cloned = false;
    try {
      try {
        fs.copyFileSync(source, temp, flags.COPYFILE_FICLONE_FORCE | flags.COPYFILE_EXCL);
        cloned = true;
      } catch (error) {
        if (!["EXDEV", "ENOTSUP", "EOPNOTSUPP", "EINVAL", "ENOSYS", "ENOTTY", "EACCES", "EPERM", "ENOENT"].includes(error.code)) throw error;
      }
      if (cloned) fs.chmodSync(temp, 0o400);
      if (cloned && streamSha256File(temp).sha256 === expectedHash) {
        const fd = fs.openSync(temp, "r");
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        fs.renameSync(temp, destination);
        fsyncDirectoryBestEffort(parent);
        return "reflink";
      }
    } finally {
      fs.rmSync(temp, { force: true });
    }
  }
  writeDurableFileAtomic(destination, capturedBytes, 0o400);
  return "bytes";
}
