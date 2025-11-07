import crypto from 'crypto';

export function buildManifest(namedFiles, rulesMeta) {
  const files = Object.entries(namedFiles).map(([name, buf]) => ({
    name,
    bytes: buf.length,
    sha256: sha256Hex(buf)
  }));
  return {
    created_utc: new Date().toISOString(),
    hash_algo: 'SHA-256',
    ruleset_id: rulesMeta.ruleset_id,
    files
  };
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
