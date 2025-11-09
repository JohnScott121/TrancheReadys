// lib/zip.js (ESM, Node 18–22 compatible)
import archiver from 'archiver';
import { PassThrough } from 'stream';

/**
 * Zip an object of { filename: Buffer } into a single Buffer
 * @param {Record<string, Buffer>} named
 * @returns {Promise<Buffer>}
 */
export async function zipNamedBuffers(named) {
  return new Promise((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });

    // Collect the zip bytes into memory
    const out = new PassThrough();
    const chunks = [];

    out.on('data', (c) => chunks.push(c));
    out.on('finish', () => resolve(Buffer.concat(chunks)));
    out.on('error', reject);

    // Handle archiver warnings/errors
    archive.on('warning', (err) => {
      // ENOENT is usually harmless (missing file on disk); we don't use disk entries here
      if (err.code !== 'ENOENT') reject(err);
    });
    archive.on('error', reject);

    archive.pipe(out);

    // Append each in-memory file
    for (const [name, buf] of Object.entries(named)) {
      archive.append(buf, { name });
    }

    // Finalize (flush) the archive
    archive.finalize().catch(reject);
  });
}

// Optional default export for flexibility (won’t hurt)
export default { zipNamedBuffers };
