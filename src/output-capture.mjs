import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

/** Retains short output verbatim. Longer output uses a private file and bounded head/tail buffers. */
export function createBoundedOutputCapture({ directory = null, streamName = "stdout", maxMemoryBytes = 256 * 1024,
  previewBytes = 4096, maxFileBytes = 64 * 1024 * 1024 } = {}) {
  if (![maxMemoryBytes, previewBytes, maxFileBytes].every((value) => Number.isSafeInteger(value) && value > 0) ||
      !/^[a-z][a-z0-9-]*$/.test(streamName)) throw new Error("Output limits must be positive integers and streamName must be a simple name.");
  let chunks = [];
  let byteCount = 0;
  let writtenBytes = 0;
  let head = Buffer.alloc(0);
  let tail = Buffer.alloc(0);
  let descriptor = null;
  let outputPath = null;
  let writeError = null;
  let finished = null;
  const halfPreview = Math.max(128, Math.floor(previewBytes / 2));

  function appendFile(bytes) {
    if (descriptor === null || writeError) return;
    const remaining = Math.max(0, maxFileBytes - writtenBytes);
    const part = bytes.subarray(0, remaining);
    try {
      let offset = 0;
      while (offset < part.length) offset += fs.writeSync(descriptor, part, offset);
      writtenBytes += part.length;
    } catch (error) { writeError = error.code || error.message; }
  }

  function append(bytes) {
    if (finished) throw new Error("Output capture is already closed.");
    const chunk = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    byteCount += chunk.length;
    if (head.length < halfPreview) head = Buffer.concat([head, chunk.subarray(0, halfPreview - head.length)]);
    tail = chunk.length >= halfPreview ? Buffer.from(chunk.subarray(chunk.length - halfPreview))
      : Buffer.concat([tail, chunk]).subarray(-halfPreview);
    if (!outputPath && !writeError && byteCount <= maxMemoryBytes) { chunks.push(chunk); return; }
    if (!outputPath && !writeError) {
      try {
        const destination = directory || fs.mkdtempSync(path.join(os.tmpdir(), "bg-output-"));
        fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
        const directoryStat = fs.lstatSync(destination);
        if (!directoryStat.isDirectory() || (directoryStat.mode & 0o077) !== 0) throw new Error("Output directory must be private (0700).");
        outputPath = path.join(destination, `${streamName}-${process.pid}-${randomBytes(8).toString("hex")}.log`);
        descriptor = fs.openSync(outputPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
        for (const retained of chunks) appendFile(retained);
      } catch (error) { writeError = error.code || error.message; }
      chunks = [];
    }
    appendFile(chunk);
  }

  function finish() {
    if (finished) return finished;
    if (descriptor !== null) {
      try { fs.fsyncSync(descriptor); } catch (error) { writeError ||= error.code || error.message; }
      try { fs.closeSync(descriptor); } catch (error) { writeError ||= error.code || error.message; }
      descriptor = null;
    }
    if (!outputPath && !writeError) return finished = { text: Buffer.concat(chunks).toString("utf8"), artifact: null };
    const reference = outputPath ? `输出文件 ${outputPath}` : "输出文件创建失败";
    const suffix = writeError ? `，保存失败 ${writeError}` : byteCount > writtenBytes ? `，仅保存前 ${writtenBytes} 字节（达到文件上限）` : "";
    return finished = {
      text: `${head.toString("utf8")}\n[BlastGuard 长输出预览，${byteCount} 字节；${reference}${suffix}]\n${tail.toString("utf8")}`,
      artifact: { path: outputPath, totalBytes: byteCount, savedBytes: writtenBytes,
        truncated: writtenBytes < byteCount, writeError },
    };
  }
  return { append, finish };
}
