import { createHash } from 'node:crypto';

// Owner key stored in secret_notes.owner_id (uuid). A student token owns its Auth user id.
// A judge token carries two identities (a, b) next to its subject, so the key mixes both;
// two judge identities can then never share one owner even if they share a subject.
export function ownerKeyOf(verified) {
  if (!verified || typeof verified.userId !== 'string' || verified.userId.length === 0) return null;
  if (verified.kind !== 'judge') return verified.userId;
  const hex = createHash('sha256')
    .update(`${verified.userId.toLowerCase()}:${verified.identity}`)
    .digest('hex')
    .slice(0, 32)
    .split('');
  hex[12] = '4';
  hex[16] = '89ab'[Number.parseInt(hex[16], 16) % 4];
  const text = hex.join('');
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20, 32)}`;
}
