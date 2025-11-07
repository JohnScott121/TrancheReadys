import archiver from 'archiver';
import { PassThrough } from 'stream';

export async function zipNamedBuffers(named) {
  const archive = archiver('zip', { zlib: { level: 9 } });
  const out = new PassThrough();
  const chunks = [];
  out.on('data', (c) => chunks.push(c));
  const done = new Promise((resolve, reject) => {
    out.on('end', () => resolve(Buffer.concat(chunks)));
    out.on('error', reject);
  });

  archive.pipe(out);
  for (const [name, buf] of Object.entries(named)) {
    archive.append(buf, { name });
  }
  await archive.finalize();
  return done;
}
