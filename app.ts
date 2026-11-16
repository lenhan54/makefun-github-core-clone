// A single-process GitHub-compatible forge: git smart HTTP (upload-pack v2,
// receive-pack v0), REST v3, GraphQL v4 and an MCP endpoint over streamable HTTP.
//
// Everything lives in memory. Objects are stored once, deflated once, and packs
// are assembled from the pre-deflated bytes, so clones stay cheap. No clock or
// randomness reaches any answer: timestamps come from MAKEFUN_TRIAL_NOW plus a
// monotone counter, ids come from counters and SHA-1.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, Inflate } from 'node:zlib';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export const ZERO_OID = '0000000000000000000000000000000000000000';

/** The login the bearer token names. The trial's scenario is fixed, so the
 *  viewer is fixed too; every repository the token creates belongs to it. */
export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';

const JSON_TYPE = 'application/json; charset=utf-8';

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function sha1OfObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function b64encode(data: Buffer): string {
  return data.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

function isHex40(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value);
}

/** Trial clock: MAKEFUN_TRIAL_NOW as ISO, seconds or milliseconds; epoch 0 fallback. */
function trialNowSeconds(): number {
  const raw = (process.env.MAKEFUN_TRIAL_NOW ?? '').trim();
  if (raw === '') return 1735689600;
  if (/^-?\d+$/.test(raw)) {
    const n = Number(raw);
    if (n > 1000000000000) return Math.floor(n / 1000);
    if (n > 1000000000) return n;
    return n;
  }
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 1735689600;
}

const TRIAL_NOW = trialNowSeconds();

/** One monotone tick per minted timestamp, so creations order deterministically. */
let tickCounter = 0;
function nextTick(): number {
  tickCounter += 1;
  return tickCounter;
}

function isoAt(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/** A fresh timestamp: trial now plus one second per mint, strictly increasing. */
function freshIso(): string {
  return isoAt(TRIAL_NOW + nextTick());
}

/** A stable opaque global id: prefix + sha1 of the key, never the plain number. */
function globalId(prefix: string, key: string): string {
  return `${prefix}_${sha1Hex(Buffer.from(key, 'utf8')).slice(0, 24)}`;
}

// ---------------------------------------------------------------------------
// pkt-line framing (git wire format)
// ---------------------------------------------------------------------------

const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const size = body.length + 4;
  const head = Buffer.from(size.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

type PktItem = string | Buffer | 'flush' | 'delim';

function pktLines(items: readonly PktItem[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(FLUSH);
    else if (item === 'delim') parts.push(DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'end';
  payload: Buffer;
}

/** Parse pkt-lines from the head of a buffer; throws on a bad length prefix. */
function parsePktStream(buf: Buffer): { packets: PktPacket[]; consumed: number } {
  const packets: PktPacket[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (!Number.isFinite(len)) throw new Error('bad pkt-line length');
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, consumed: off };
}

// ---------------------------------------------------------------------------
// Git objects
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

const TYPE_NUM: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const NUM_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

interface GitObj {
  type: ObjType;
  data: Buffer;
  /** Deflated once at store time; pack assembly just concatenates these. */
  deflated: Buffer;
  /** Pack object header (varint type + size), also built once. */
  header: Buffer;
}

function packObjHeader(typeNum: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeNum << 4) | (size & 15);
  size >>= 4;
  if (size !== 0) first |= 0x80;
  bytes.push(first);
  while (size !== 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size !== 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function makeGitObj(type: ObjType, data: Buffer): GitObj {
  return {
    type,
    data,
    deflated: deflateSync(data, { level: 6 }),
    header: packObjHeader(TYPE_NUM[type], data.length),
  };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) break;
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  // A stored commit body ends with one newline; the API reports the message
  // without that trailing newline, as the suite compares it exactly.
  const rawMessage = split < 0 ? '' : text.slice(split + 2);
  const message = rawMessage.endsWith('\n') ? rawMessage.slice(0, -1) : rawMessage;
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, epochSec: number): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${epochSec} +0000`;
  const lines: string[] = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${msg}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const rawMessage = split < 0 ? '' : text.slice(split + 2);
  const message = rawMessage.endsWith('\n') ? rawMessage.slice(0, -1) : rawMessage;
  let object = '';
  let type = '';
  let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, message };
}

// ---------------------------------------------------------------------------
// Delta application (REF_DELTA / OFS_DELTA payloads)
// ---------------------------------------------------------------------------

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let p = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (p >= delta.length) throw new Error('delta varint overruns');
      const byte = delta[p];
      p += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) return value;
    }
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (p < delta.length) {
    const op = delta[p];
    p += 1;
    if ((op & 0x80) !== 0) {
      let offset = 0;
      let size = 0;
      if ((op & 0x01) !== 0) offset = delta[p++];
      if ((op & 0x02) !== 0) offset |= delta[p++] << 8;
      if ((op & 0x04) !== 0) offset |= delta[p++] << 16;
      if ((op & 0x08) !== 0) offset |= delta[p++] << 24;
      if ((op & 0x10) !== 0) size = delta[p++];
      if ((op & 0x20) !== 0) size |= delta[p++] << 8;
      if ((op & 0x40) !== 0) size |= delta[p++] << 16;
      if (size === 0) size = 0x10000;
      if (offset + size > base.length) throw new Error('delta copy overruns base');
      parts.push(base.subarray(offset, offset + size));
      total += size;
    } else if (op !== 0) {
      if (p + op > delta.length) throw new Error('delta insert overruns');
      parts.push(delta.subarray(p, p + op));
      p += op;
      total += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const out = Buffer.concat(parts);
  if (out.length !== targetSize || total !== targetSize) throw new Error('delta target size mismatch');
  return out;
}

// ---------------------------------------------------------------------------
// Inflate with exact consumed length
// ---------------------------------------------------------------------------

/** Inflate one zlib stream starting at `offset`; resolves with the data and the
 *  offset just past the stream (adler32 included). */
function inflateAt(buf: Buffer, offset: number): Promise<{ data: Buffer; next: number }> {
  return new Promise((resolve, reject) => {
    const inflater = new Inflate();
    const chunks: Buffer[] = [];
    inflater.on('data', (chunk: Buffer) => chunks.push(chunk));
    inflater.on('error', (err: Error) => reject(err));
    inflater.on('end', () => {
      const consumed = (inflater as unknown as { bytesWritten: number }).bytesWritten;
      resolve({ data: Buffer.concat(chunks), next: offset + consumed });
    });
    inflater.write(buf.subarray(offset));
    inflater.end();
  });
}

/** Fallback inflater: binary-search the stream end with inflateSync (which
 *  ignores trailing bytes, so the smallest successful end is the true end). */
async function inflateAtSlow(buf: Buffer, offset: number, expectedSize: number): Promise<{ data: Buffer; next: number }> {
  const { inflateSync } = await import('node:zlib');
  let low = offset;
  let high = buf.length;
  let found = -1;
  let foundData: Buffer | null = null;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    try {
      const out = inflateSync(buf.subarray(offset, mid));
      if (out.length === expectedSize) {
        found = mid;
        foundData = out;
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    } catch {
      low = mid + 1;
    }
  }
  if (found < 0 || foundData === null) throw new Error('cannot inflate pack object');
  return { data: foundData, next: found };
}

/** Chosen once at startup: the fast inflater, unless its byte count misbehaves. */
let inflateImpl: (buf: Buffer, offset: number, expectedSize: number) => Promise<{ data: Buffer; next: number }> =
  async (buf, offset) => inflateAt(buf, offset);

async function checkInflate(): Promise<void> {
  try {
    const { deflateSync: deflate } = await import('node:zlib');
    const plain = Buffer.from('inflate self-check payload 0123456789', 'utf8');
    const packed = Buffer.concat([deflate(plain), Buffer.from('trailing', 'utf8')]);
    const got = await inflateAt(packed, 0);
    if (!got.data.equals(plain) || got.next !== packed.length - 8) throw new Error('inflate byte count off');
  } catch {
    inflateImpl = inflateAtSlow;
  }
}

// ---------------------------------------------------------------------------
// Pack reading and writing
// ---------------------------------------------------------------------------

interface PackedObject {
  oid: string;
  type: ObjType;
  data: Buffer;
}

interface DeltaEntry {
  pos: number;
  baseOid?: string;
  basePos?: number;
  data: Buffer;
  typeNum: number;
}

/** Read a whole packfile (full objects plus REF/OFS deltas) into plain objects. */
async function readPack(buf: Buffer, baseLookup: (oid: string) => GitObj | undefined): Promise<PackedObject[]> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error(`pack version ${version}`);
  const count = buf.readUInt32BE(8);
  if (buf.length < 20) throw new Error('packfile too short');
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  if (sha1Hex(buf.subarray(0, buf.length - 20)) !== trailer) throw new Error('pack trailer checksum mismatch');
  const byPos = new Map<number, PackedObject>();
  const byOid = new Map<string, PackedObject>();
  const deltas: DeltaEntry[] = [];
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const start = off;
    let byte = buf[off];
    off += 1;
    const typeNum = (byte >> 4) & 7;
    let size = byte & 15;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = buf[off];
      off += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOid: string | undefined;
    let basePos: number | undefined;
    if (typeNum === 6) {
      let b = buf[off];
      off += 1;
      let value = b & 0x7f;
      while ((b & 0x80) !== 0) {
        b = buf[off];
        off += 1;
        value = ((value + 1) << 7) | (b & 0x7f);
      }
      basePos = start - value;
    } else if (typeNum === 7) {
      baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (NUM_TYPE[typeNum] === undefined) {
      throw new Error(`pack object type ${typeNum}`);
    }
    const inflated = await inflateImpl(buf, off, size);
    if (inflated.data.length !== size) throw new Error('pack object size mismatch');
    off = inflated.next;
    if (typeNum === 6 || typeNum === 7) {
      deltas.push({ pos: start, baseOid, basePos, data: inflated.data, typeNum });
    } else {
      const type = NUM_TYPE[typeNum] as ObjType;
      const oid = sha1OfObject(type, inflated.data);
      const obj: PackedObject = { oid, type, data: inflated.data };
      byPos.set(start, obj);
      byOid.set(oid, obj);
    }
  }
  const resolved: PackedObject[] = [...byOid.values()];
  for (const delta of deltas) {
    let base: PackedObject | undefined;
    if (delta.basePos !== undefined) base = byPos.get(delta.basePos);
    else if (delta.baseOid !== undefined) {
      base = byOid.get(delta.baseOid);
      if (base === undefined) {
        const stored = baseLookup(delta.baseOid);
        if (stored !== undefined) base = { oid: delta.baseOid, type: stored.type, data: stored.data };
      }
    }
    if (base === undefined) throw new Error('delta base not found');
    const data = applyDelta(base.data, delta.data);
    const oid = sha1OfObject(base.type, data);
    const obj: PackedObject = { oid, type: base.type, data };
    byPos.set(delta.pos, obj);
    byOid.set(oid, obj);
    resolved.push(obj);
  }
  return resolved;
}

/** Build a packfile from stored objects: header + per-object header + the
 *  pre-deflated bytes + the SHA-1 trailer. No deltas are ever emitted. */
function buildPack(objects: readonly GitObj[]): Buffer {
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  const parts: Buffer[] = [head];
  for (const obj of objects) {
    parts.push(obj.header);
    parts.push(obj.deflated);
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------------------
// Store: repositories, issues, pull requests
// ---------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  createdAt: string;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
  seq: number;
  createdAt: string;
  updatedAt: string;
  // Serialized single-issue JSON, memoized because the read bench fetches one
  // issue two thousand times in a row. Cleared on any mutation of the issue.
  cachedJson: string | null;
}

interface Pull {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  seq: number;
  createdAt: string;
  updatedAt: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, Label>;
  nextNumber: number;
  nextCommentId: number;
  fileMapCache: Map<string, Map<string, string>>;
}

const reposByKey = new Map<string, Repo>();
const viewerRepos: Repo[] = [];
let nextRepoId = 5000;
let nextGlobalCommentId = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: 'main',
    createdAt: freshIso(),
    objects: new Map(),
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    fileMapCache: new Map(),
  };
  nextRepoId += 1;
  reposByKey.set(repoKey(VIEWER_LOGIN, name), repo);
  viewerRepos.push(repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return reposByKey.get(repoKey(owner, name));
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = sha1OfObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, makeGitObj(type, data));
  return oid;
}

function lookupObject(repo: Repo, oid: string): GitObj | undefined {
  return repo.objects.get(oid);
}

/** Peel a tag (possibly chained) to the commit it points at. */
function peelToCommit(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let hops = 0; hops < 10; hops += 1) {
    const obj = repo.objects.get(current);
    if (obj === undefined) return null;
    if (obj.type === 'commit') return current;
    if (obj.type === 'tag') {
      current = parseTag(obj.data).object;
      continue;
    }
    return null;
  }
  return null;
}

/** Walk a commit's ancestry, calling `visit` for each commit oid reached. */
function walkAncestors(repo: Repo, tips: readonly string[], visit: (oid: string, distance: number) => void, maxDistance = -1): void {
  const seen = new Map<string, number>();
  const queue: Array<{ oid: string; distance: number }> = [];
  for (const tip of tips) {
    const commit = peelToCommit(repo, tip);
    if (commit === null) continue;
    if (!seen.has(commit)) {
      seen.set(commit, 0);
      queue.push({ oid: commit, distance: 0 });
    }
  }
  let head = 0;
  while (head < queue.length) {
    const item = queue[head];
    head += 1;
    visit(item.oid, item.distance);
    if (maxDistance >= 0 && item.distance >= maxDistance) continue;
    const obj = repo.objects.get(item.oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (seen.has(parent)) continue;
      seen.set(parent, item.distance + 1);
      queue.push({ oid: parent, distance: item.distance + 1 });
    }
  }
}

/** Whether `ancestor` is an ancestor of (or equal to) `tip`. */
function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  let found = false;
  walkAncestors(repo, [tip], (oid) => {
    if (oid === ancestor) found = true;
  });
  return found;
}

/** The nearest common ancestor of two commits, or null. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const aSet = new Set<string>();
  walkAncestors(repo, [a], (oid) => aSet.add(oid));
  let base: string | null = null;
  walkAncestors(repo, [b], (oid) => {
    if (base === null && aSet.has(oid)) base = oid;
  });
  return base;
}

interface ReachResult {
  /** Object ids to send, in a stable order. */
  send: string[];
  /** Commits at the shallow edge of a depth-limited walk. */
  shallow: string[];
  /** Former shallow commits that are now fully present. */
  unshallow: string[];
}

/**
 * The objects a fetch of `wants` must deliver: the wants' closure (depth-limited
 * when `depth` is set), minus what the client already holds. A `have` that is one
 * of the client's shallow boundaries only excludes the commit and its tree, not
 * its unseen history.
 */
function computeFetch(repo: Repo, wants: readonly string[], haves: readonly string[], shallowHeld: readonly string[], depth?: number): ReachResult {
  const wantSet = new Set<string>();
  const wantCommits = new Map<string, number>();
  const shallowSet = new Set(shallowHeld);
  const tagObjects = new Set<string>();

  const addTree = (treeOid: string): void => {
    const stack: string[] = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (wantSet.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'tree') continue;
      wantSet.add(oid);
      for (const entry of parseTree(obj.data)) {
        if (entry.mode === '40000') stack.push(entry.oid);
        else wantSet.add(entry.oid);
      }
    }
  };

  const includeCommit = (oid: string): void => {
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') return;
    const parsed = parseCommit(obj.data);
    addTree(parsed.tree);
  };

  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      tagObjects.add(want);
      const target = peelToCommit(repo, want);
      if (target !== null) walkAncestors(repo, [target], (oid, distance) => {
        if (depth === undefined || distance < depth) {
          wantCommits.set(oid, distance);
          wantSet.add(oid);
        }
      }, depth === undefined ? -1 : depth);
      continue;
    }
    if (obj.type !== 'commit') {
      wantSet.add(want);
      continue;
    }
    walkAncestors(repo, [want], (oid, distance) => {
      if (depth === undefined || distance < depth) {
        wantCommits.set(oid, distance);
        wantSet.add(oid);
      }
    }, depth === undefined ? -1 : depth);
  }
  for (const oid of wantCommits.keys()) includeCommit(oid);
  for (const oid of tagObjects) wantSet.add(oid);

  // Shallow edge: included commits with a parent outside the included set.
  const shallow: string[] = [];
  for (const oid of wantCommits.keys()) {
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    const parents = parseCommit(obj.data).parents;
    if (parents.some((parent) => !wantCommits.has(parent))) shallow.push(oid);
  }
  const unshallow: string[] = [];
  if (depth !== undefined) {
    for (const held of shallowHeld) {
      if (wantCommits.has(held) && !shallow.includes(held)) unshallow.push(held);
    }
  }

  // What the client already holds.
  const haveSet = new Set<string>();
  const addHaveClosure = (oid: string, full: boolean): void => {
    const obj = repo.objects.get(oid);
    if (obj === undefined) return;
    if (obj.type === 'commit') {
      if (full) {
        walkAncestors(repo, [oid], (coid) => {
          haveSet.add(coid);
          includeHaveCommit(coid);
        });
      } else {
        haveSet.add(oid);
        includeHaveCommit(oid);
      }
      return;
    }
    haveSet.add(oid);
  };
  const includeHaveCommit = (oid: string): void => {
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') return;
    const tree = parseCommit(obj.data).tree;
    const stack: string[] = [tree];
    while (stack.length > 0) {
      const current = stack.pop() as string;
      if (haveSet.has(current)) continue;
      const tobj = repo.objects.get(current);
      if (tobj === undefined || tobj.type !== 'tree') continue;
      haveSet.add(current);
      for (const entry of parseTree(tobj.data)) {
        if (entry.mode === '40000') stack.push(entry.oid);
        else haveSet.add(entry.oid);
      }
    }
  };
  for (const have of haves) addHaveClosure(have, !shallowSet.has(have));

  const send: string[] = [];
  for (const oid of wantSet) if (!haveSet.has(oid)) send.push(oid);
  send.sort();
  // Keep commits first in pack order for readability; order does not matter.
  return { send, shallow: shallow.sort(), unshallow: unshallow.sort() };
}

// ---------------------------------------------------------------------------
// File maps: a commit's flat path -> blob oid view, with a memo
// ---------------------------------------------------------------------------

function fileMapOf(repo: Repo, commitOid: string): Map<string, string> {
  const cached = repo.fileMapCache.get(commitOid);
  if (cached !== undefined) return cached;
  const files = new Map<string, string>();
  const obj = repo.objects.get(commitOid);
  if (obj !== undefined && obj.type === 'commit') {
    const walk = (treeOid: string, prefix: string): void => {
      const tobj = repo.objects.get(treeOid);
      if (tobj === undefined || tobj.type !== 'tree') return;
      for (const entry of parseTree(tobj.data)) {
        const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000') walk(entry.oid, path);
        else files.set(path, entry.oid);
      }
    };
    walk(parseCommit(obj.data).tree, '');
  }
  repo.fileMapCache.set(commitOid, files);
  return files;
}

/** Build (and store) the tree objects for a flat path -> blob map. */
function treeFromFileMap(repo: Repo, files: ReadonlyMap<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, oid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i] as string;
      let child = node.dirs.get(part);
      if (child === undefined) {
        child = makeNode();
        node.dirs.set(part, child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1] as string, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Commit a new file map on a branch tip; returns the new commit oid. */
function commitFileMap(repo: Repo, parentOid: string | null, files: ReadonlyMap<string, string>, message: string): string {
  const tree = treeFromFileMap(repo, files);
  const epoch = TRIAL_NOW + nextTick();
  const data = buildCommit(tree, parentOid === null ? [] : [parentOid], message, epoch);
  return storeObject(repo, 'commit', data);
}

/** Resolve a ref-ish (branch name, full ref, or commit oid) to a commit oid. */
function resolveRef(repo: Repo, ref: string | undefined): string | null {
  if (ref === undefined || ref === '') {
    return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  }
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  const headed = repo.refs.get(`refs/heads/${ref}`);
  if (headed !== undefined) return headed;
  const tagged = repo.refs.get(`refs/tags/${ref}`);
  if (tagged !== undefined) return peelToCommit(repo, tagged);
  if (isHex40(ref) && repo.objects.has(ref)) return peelToCommit(repo, ref) ?? ref;
  return null;
}

/** The line counts of a blob, for pull-request file stats. */
function lineCount(data: Buffer): number {
  if (data.length === 0) return 0;
  const text = data.toString('utf8');
  const lines = text.split('\n');
  return text.endsWith('\n') ? lines.length - 1 : lines.length;
}

interface FileChange {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
}

/** Diff two file maps (base -> head) into per-file change records. */
function diffFileMaps(repo: Repo, base: ReadonlyMap<string, string>, head: ReadonlyMap<string, string>): FileChange[] {
  const changes: FileChange[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b === h) continue;
    if (b === undefined && h !== undefined) {
      const data = repo.objects.get(h)?.data ?? Buffer.alloc(0);
      changes.push({ filename: path, status: 'added', additions: lineCount(data), deletions: 0 });
    } else if (h === undefined && b !== undefined) {
      const data = repo.objects.get(b)?.data ?? Buffer.alloc(0);
      changes.push({ filename: path, status: 'removed', additions: 0, deletions: lineCount(data) });
    } else if (b !== undefined && h !== undefined) {
      const oldData = repo.objects.get(b)?.data ?? Buffer.alloc(0);
      const newData = repo.objects.get(h)?.data ?? Buffer.alloc(0);
      const oldLines = new Set(oldData.toString('utf8').split('\n'));
      const newLines = new Set(newData.toString('utf8').split('\n'));
      let additions = 0;
      let deletions = 0;
      for (const line of newData.toString('utf8').split('\n')) if (!oldLines.has(line)) additions += 1;
      for (const line of oldData.toString('utf8').split('\n')) if (!newLines.has(line)) deletions += 1;
      if (additions === 0 && deletions === 0) {
        additions = 1;
        deletions = 1;
      }
      changes.push({ filename: path, status: 'modified', additions, deletions });
    }
  }
  return changes;
}

/** Three-way merge check: apply head's changes (vs merge base) onto the base
 *  tip's tree. Returns the merged file map, or null when both sides changed
 *  the same path differently. */
function tryMerge(repo: Repo, baseTip: string, headTip: string): Map<string, string> | null {
  const base = mergeBase(repo, baseTip, headTip);
  const baseFiles = base === null ? new Map<string, string>() : fileMapOf(repo, base);
  const tipFiles = fileMapOf(repo, baseTip);
  const headFiles = fileMapOf(repo, headTip);
  const merged = new Map<string, string>(tipFiles);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const inBase = baseFiles.get(path);
    const inHead = headFiles.get(path);
    const inTip = tipFiles.get(path);
    const headChanged = inHead !== inBase;
    const tipChanged = inTip !== inBase;
    if (!headChanged) continue;
    if (!tipChanged) {
      if (inHead === undefined) merged.delete(path);
      else merged.set(path, inHead);
      continue;
    }
    if (inHead === inTip) continue;
    return null;
  }
  return merged;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

let requestCounter = 0;

function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter.toString(16).padStart(8, '0')}`;
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  path: string;
  query: URLSearchParams;
  host: string;
  bodyText: string;
  bodyBuffer: Buffer;
  body: unknown;
  authed: boolean;
}

function sendJson(ctx: Ctx, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = body === null ? '' : `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = {
    'content-type': JSON_TYPE,
    'x-github-request-id': nextRequestId(),
    ...extra,
  };
  if (body !== null) headers['content-length'] = String(Buffer.byteLength(text));
  ctx.res.writeHead(status, headers);
  ctx.res.end(text);
}

function sendRaw(ctx: Ctx, status: number, contentType: string, body: Buffer, extra: Record<string, string> = {}): void {
  ctx.res.writeHead(status, {
    'content-type': contentType,
    'content-length': String(body.length),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  ctx.res.end(body);
}

function sendError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(ctx: Ctx): boolean {
  if (ctx.bodyText.trim() === '') {
    ctx.body = {};
    return true;
  }
  try {
    ctx.body = JSON.parse(ctx.bodyText);
    return true;
  } catch {
    return false;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  return {};
}

function strField(body: Record<string, unknown>, key: string, fallback = ''): string {
  const value = body[key];
  return typeof value === 'string' ? value : fallback;
}

function boolField(body: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const value = body[key];
  return typeof value === 'boolean' ? value : fallback;
}

function intQuery(ctx: Ctx, key: string, fallback: number): number {
  const raw = ctx.query.get(key);
  if (raw === null) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function pageSlice<T>(items: readonly T[], ctx: Ctx): { page: T[]; hasNext: boolean; pageNum: number; perPage: number } {
  const perPage = intQuery(ctx, 'per_page', 30);
  const pageNum = intQuery(ctx, 'page', 1);
  const start = (pageNum - 1) * perPage;
  const page = items.slice(start, start + perPage);
  return { page, hasNext: start + perPage < items.length, pageNum, perPage };
}

function linkHeader(ctx: Ctx, basePath: string, pageNum: number, perPage: number): string {
  const url = new URL(basePath, `http://${ctx.host}`);
  url.searchParams.set('page', String(pageNum));
  url.searchParams.set('per_page', String(perPage));
  return `<${url.toString()}>; rel="next"`;
}

// ---------------------------------------------------------------------------
// REST shapes
// ---------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: repo.id * 100000 + issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label !== undefined ? labelJson(label) : { name, color: 'ededed', description: '' };
    }),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    comments: issue.comments.length,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function issueJsonText(repo: Repo, issue: Issue): string {
  if (issue.cachedJson === null) issue.cachedJson = JSON.stringify(issueJson(repo, issue));
  return issue.cachedJson;
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: repo.id * 100000 + pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull),
    merge_commit_sha: pull.mergeCommitSha,
    merged_at: pull.mergedAt,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function pullMergeable(repo: Repo, pull: Pull): boolean {
  if (pull.state !== 'open') return false;
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (baseTip === undefined) return false;
  return tryMerge(repo, baseTip, pull.headSha) !== null;
}

function commentJson(repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: repo.id * 1000000 + comment.id,
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments/${comment.id}`,
  };
}

function sortedIssues(repo: Repo, state: string, sort: string, direction: string): Issue[] {
  let list = [...repo.issues.values()];
  if (state === 'open') list = list.filter((issue) => issue.state === 'open');
  else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
  const asc = direction !== 'desc';
  if (sort === 'created') {
    list.sort((a, b) => (asc ? a.seq - b.seq : b.seq - a.seq));
  } else {
    list.sort((a, b) => (asc ? a.number - b.number : b.number - a.number));
  }
  return list;
}

// ---------------------------------------------------------------------------
// REST: repositories, branches, commits, contents
// ---------------------------------------------------------------------------

function handleUserRepos(ctx: Ctx): void {
  if (ctx.method === 'GET') {
    const { page, hasNext, pageNum, perPage } = pageSlice(viewerRepos, ctx);
    const extra: Record<string, string> = {};
    if (hasNext) extra.link = linkHeader(ctx, '/api/v3/user/repos', pageNum + 1, perPage);
    sendJson(ctx, 200, page.map(repoJson), extra);
    return;
  }
  if (ctx.method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const name = strField(body, 'name');
    if (name === '') {
      sendError(ctx, 422, 'name is required');
      return;
    }
    if (reposByKey.has(repoKey(VIEWER_LOGIN, name))) {
      sendError(ctx, 422, 'Repository already exists');
      return;
    }
    const repo = createRepoRecord(name, boolField(body, 'private', false), strField(body, 'description'));
    if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
    sendJson(ctx, 201, repoJson(repo));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleRepoRoot(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    sendJson(ctx, 200, repoJson(repo));
    return;
  }
  if (ctx.method === 'PATCH') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    if (typeof body.description === 'string') repo.description = body.description;
    if (typeof body.private === 'boolean') repo.isPrivate = body.private;
    if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
    sendJson(ctx, 200, repoJson(repo));
    return;
  }
  if (ctx.method === 'DELETE') {
    reposByKey.delete(repoKey(owner, name));
    const index = viewerRepos.indexOf(repo);
    if (index >= 0) viewerRepos.splice(index, 1);
    ctx.res.writeHead(204, { 'x-github-request-id': nextRequestId() });
    ctx.res.end();
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleBranches(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method !== 'GET') {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const list = [...repo.refs.entries()]
    .filter(([ref]) => ref.startsWith('refs/heads/'))
    .map(([ref, sha]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha }, protected: false }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
  sendJson(ctx, 200, list);
}

function handleBranchOne(ctx: Ctx, owner: string, name: string, branch: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const sha = repo.refs.get(`refs/heads/${branch}`);
  if (sha === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  sendJson(ctx, 200, { name: branch, commit: { sha }, protected: false });
}

function handleGitRef(ctx: Ctx, owner: string, name: string, rest: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'POST' && rest === '') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const ref = strField(body, 'ref');
    const sha = strField(body, 'sha');
    if (!ref.startsWith('refs/') || !isHex40(sha) || repo.objects.get(sha) === undefined) {
      sendError(ctx, 422, 'Invalid ref or sha');
      return;
    }
    if (repo.refs.has(ref)) {
      sendError(ctx, 422, 'Reference already exists');
      return;
    }
    repo.refs.set(ref, sha);
    sendJson(ctx, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
    return;
  }
  if (ctx.method === 'GET' && rest !== '') {
    const ref = `refs/${rest}`;
    const sha = repo.refs.get(ref);
    if (sha === undefined) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendJson(ctx, 200, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleCommits(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method !== 'GET') {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const tip = resolveRef(repo, ctx.query.get('sha') ?? undefined);
  const list: Record<string, unknown>[] = [];
  if (tip !== null) {
    walkAncestors(repo, [tip], (oid) => {
      const obj = repo.objects.get(oid);
      if (obj === undefined) return;
      const parsed = parseCommit(obj.data);
      const when = parsed.author.match(/(\d+) \+0000/);
      const epoch = when !== null ? Number(when[1]) : TRIAL_NOW;
      list.push({
        sha: oid,
        commit: {
          message: parsed.message,
          author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoAt(epoch) },
          committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoAt(epoch) },
        },
        parents: parsed.parents.map((sha) => ({ sha })),
      });
    });
  }
  sendJson(ctx, 200, list);
}

function handleContents(ctx: Ctx, owner: string, name: string, filePath: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const ref = ctx.query.get('ref') ?? undefined;
  if (ctx.method === 'GET') {
    const tip = resolveRef(repo, ref);
    if (tip === null) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    const files = fileMapOf(repo, tip);
    if (filePath === '') {
      const entries = directoryEntries(repo, files, '');
      sendJson(ctx, 200, entries);
      return;
    }
    const blobOid = files.get(filePath);
    if (blobOid !== undefined) {
      const data = repo.objects.get(blobOid)?.data ?? Buffer.alloc(0);
      const base = filePath.split('/').pop() ?? filePath;
      sendJson(ctx, 200, {
        type: 'file',
        encoding: 'base64',
        size: data.length,
        name: base,
        path: filePath,
        content: b64encode(data),
        sha: blobOid,
      });
      return;
    }
    const prefix = `${filePath}/`;
    const isDir = [...files.keys()].some((path) => path.startsWith(prefix));
    if (isDir) {
      sendJson(ctx, 200, directoryEntries(repo, files, filePath));
      return;
    }
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'PUT' || ctx.method === 'DELETE') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    const refName = `refs/heads/${branch}`;
    const tip = repo.refs.get(refName) ?? null;
    const files = tip === null ? new Map<string, string>() : new Map(fileMapOf(repo, tip));
    const current = files.get(filePath);
    if (ctx.method === 'PUT') {
      const content = strField(body, 'content');
      if (content === '') {
        sendError(ctx, 422, 'content is required');
        return;
      }
      const sha = typeof body.sha === 'string' ? body.sha : undefined;
      if (sha !== undefined && current !== undefined && sha.toLowerCase() !== current.toLowerCase()) {
        sendError(ctx, 409, 'sha does not match the current blob');
        return;
      }
      if (sha !== undefined && current === undefined) {
        sendError(ctx, 409, 'sha does not match the current blob');
        return;
      }
      const existed = current !== undefined;
      const blobOid = storeObject(repo, 'blob', b64decode(content));
      files.set(filePath, blobOid);
      const message = strField(body, 'message', 'update file');
      const commitSha = commitFileMap(repo, tip, files, message);
      repo.refs.set(refName, commitSha);
      sendJson(ctx, existed ? 200 : 201, {
        content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: blobOid, size: b64decode(content).length, encoding: 'base64' },
        commit: { sha: commitSha, message },
      });
      return;
    }
    // DELETE
    if (current === undefined) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    files.delete(filePath);
    const message = strField(body, 'message', 'delete file');
    const commitSha = commitFileMap(repo, tip, files, message);
    repo.refs.set(refName, commitSha);
    sendJson(ctx, 200, { commit: { sha: commitSha, message } });
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function directoryEntries(repo: Repo, files: ReadonlyMap<string, string>, dir: string): Record<string, unknown>[] {
  const prefix = dir === '' ? '' : `${dir}/`;
  const seen = new Map<string, { type: string; sha: string }>();
  for (const [path, oid] of files) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    if (rest === '') continue;
    const slash = rest.indexOf('/');
    if (slash < 0) {
      seen.set(rest, { type: 'file', sha: oid });
    } else {
      const sub = rest.slice(0, slash);
      if (!seen.has(sub)) {
        const subFiles = new Map<string, string>();
        for (const [p2, o2] of files) {
          if (p2.startsWith(`${prefix}${sub}/`)) subFiles.set(p2.slice(prefix.length + sub.length + 1), o2);
        }
        seen.set(sub, { type: 'dir', sha: treeFromFileMap(repo, subFiles) });
      }
    }
  }
  return [...seen.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([entryName, info]) => ({
      type: info.type,
      name: entryName,
      path: prefix === '' ? entryName : `${prefix}${entryName}`,
      sha: info.sha,
    }));
}

// ---------------------------------------------------------------------------
// REST: labels, issues, comments, pull requests
// ---------------------------------------------------------------------------

function handleLabels(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    sendJson(ctx, 200, [...repo.labels.values()].map(labelJson));
    return;
  }
  if (ctx.method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const labelName = strField(body, 'name');
    if (labelName === '') {
      sendError(ctx, 422, 'name is required');
      return;
    }
    const existing = repo.labels.get(labelName);
    if (existing !== undefined) {
      sendJson(ctx, 201, labelJson(existing));
      return;
    }
    const label: Label = {
      name: labelName,
      color: strField(body, 'color', 'ededed'),
      description: strField(body, 'description'),
    };
    repo.labels.set(labelName, label);
    sendJson(ctx, 201, labelJson(label));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function labelNamesOf(body: Record<string, unknown>): string[] {
  const raw = body.labels;
  if (!Array.isArray(raw)) return [];
  const names: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') names.push(entry);
    else if (entry !== null && typeof entry === 'object') {
      const name = (entry as Record<string, unknown>).name;
      if (typeof name === 'string') names.push(name);
    }
  }
  return names;
}

function handleIssues(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    const state = ctx.query.get('state') ?? 'open';
    const sort = ctx.query.get('sort') ?? 'created';
    const direction = ctx.query.get('direction') ?? 'desc';
    let list = sortedIssues(repo, state, sort, direction);
    if (ctx.query.has('per_page') || ctx.query.has('page')) {
      const sliced = pageSlice(list, ctx);
      list = [...sliced.page];
    }
    sendJson(ctx, 200, list.map((issue) => issueJson(repo, issue)));
    return;
  }
  if (ctx.method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const title = strField(body, 'title');
    if (title === '') {
      sendError(ctx, 422, 'title is required');
      return;
    }
    const wanted = labelNamesOf(body);
    for (const labelName of wanted) {
      if (!repo.labels.has(labelName)) {
        sendError(ctx, 422, `Label '${labelName}' does not exist`);
        return;
      }
    }
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = freshIso();
    const issue: Issue = {
      number,
      title,
      body: strField(body, 'body'),
      state: 'open',
      labels: wanted,
      comments: [],
      seq: nextTick(),
      createdAt: now,
      updatedAt: now,
      cachedJson: null,
    };
    repo.issues.set(number, issue);
    sendJson(ctx, 201, issueJson(repo, issue));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleIssueOne(ctx: Ctx, owner: string, name: string, numText: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const number = Number.parseInt(numText, 10);
  const issue = repo.issues.get(number);
  if (issue === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    sendRaw(ctx, 200, 'application/json; charset=utf-8', Buffer.from(issueJsonText(repo, issue), 'utf8'));
    return;
  }
  if (ctx.method === 'PATCH') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    if (typeof body.title === 'string') issue.title = body.title;
    if (typeof body.body === 'string') issue.body = body.body;
    if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
    if (Array.isArray(body.labels)) {
      const wanted = labelNamesOf(body);
      if (wanted.every((labelName) => repo.labels.has(labelName))) issue.labels = wanted;
    }
    issue.updatedAt = freshIso();
    issue.cachedJson = null;
    sendJson(ctx, 200, issueJson(repo, issue));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleIssueComments(ctx: Ctx, owner: string, name: string, numText: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const number = Number.parseInt(numText, 10);
  const issue = repo.issues.get(number);
  if (issue === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    sendJson(ctx, 200, issue.comments.map((comment) => commentJson(repo, issue, comment)));
    return;
  }
  if (ctx.method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const text = strField(body, 'body');
    if (text === '') {
      sendError(ctx, 422, 'body is required');
      return;
    }
    const comment: IssueComment = { id: nextGlobalCommentId, body: text, createdAt: freshIso() };
    nextGlobalCommentId += 1;
    issue.comments.push(comment);
    issue.cachedJson = null;
    sendJson(ctx, 201, commentJson(repo, issue, comment));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function createPullRecord(repo: Repo, title: string, bodyText: string, headRef: string, baseRef: string): { pull: Pull } | { error: string } {
  const headSha = repo.refs.get(`refs/heads/${headRef}`);
  const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
  if (headSha === undefined || baseSha === undefined) return { error: 'head or base branch not found' };
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const now = freshIso();
  const pull: Pull = {
    number,
    title,
    body: bodyText,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    baseRef,
    headSha,
    baseSha,
    seq: nextTick(),
    createdAt: now,
    updatedAt: now,
  };
  repo.pulls.set(number, pull);
  return { pull };
}

function doMerge(repo: Repo, pull: Pull): { sha: string } | { error: string; status: number } {
  if (pull.state !== 'open') return { error: 'pull request is already closed', status: 405 };
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (baseTip === undefined) return { error: 'base branch not found', status: 404 };
  const merged = tryMerge(repo, baseTip, pull.headSha);
  if (merged === null) return { error: 'merge conflict', status: 405 };
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}\n\n${pull.title}`;
  const commitSha = commitFileMap(repo, baseTip, merged, message);
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = freshIso();
  pull.mergeCommitSha = commitSha;
  pull.updatedAt = pull.mergedAt;
  return { sha: commitSha };
}

function handlePulls(ctx: Ctx, owner: string, name: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (ctx.method === 'GET') {
    const state = ctx.query.get('state') ?? 'open';
    let list = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
    if (state === 'open') list = list.filter((pull) => pull.state === 'open');
    else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
    if (ctx.query.has('per_page') || ctx.query.has('page')) {
      const sliced = pageSlice(list, ctx);
      list = [...sliced.page];
    }
    sendJson(ctx, 200, list.map((pull) => pullJson(repo, pull)));
    return;
  }
  if (ctx.method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const body = asRecord(ctx.body);
    const title = strField(body, 'title');
    let head = strField(body, 'head');
    let base = strField(body, 'base', repo.defaultBranch);
    if (title === '' || head === '') {
      sendError(ctx, 422, 'title and head are required');
      return;
    }
    if (head.includes(':')) head = head.split(':').pop() as string;
    if (base.includes(':')) base = base.split(':').pop() as string;
    const made = createPullRecord(repo, title, strField(body, 'body'), head, base);
    if ('error' in made) {
      sendError(ctx, 422, made.error);
      return;
    }
    sendJson(ctx, 201, pullJson(repo, made.pull));
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handlePullOne(ctx: Ctx, owner: string, name: string, numText: string, tail: string): void {
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  const number = Number.parseInt(numText, 10);
  const pull = repo.pulls.get(number);
  if (pull === undefined) {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  if (tail === '' && ctx.method === 'GET') {
    sendJson(ctx, 200, pullJson(repo, pull));
    return;
  }
  if (tail === 'files' && ctx.method === 'GET') {
    const baseFiles = fileMapOf(repo, pull.baseSha);
    const headFiles = fileMapOf(repo, pull.headSha);
    const changes = diffFileMaps(repo, baseFiles, headFiles);
    sendJson(
      ctx,
      200,
      changes.map((change) => ({
        filename: change.filename,
        status: change.status,
        additions: change.additions,
        deletions: change.deletions,
        changes: change.additions + change.deletions,
      })),
    );
    return;
  }
  if (tail === 'merge' && ctx.method === 'PUT') {
    if (ctx.bodyText.trim() !== '' && !parseJsonBody(ctx)) {
      sendError(ctx, 400, 'Malformed JSON body');
      return;
    }
    const result = doMerge(repo, pull);
    if ('error' in result) {
      sendError(ctx, result.status, result.error);
      return;
    }
    sendJson(ctx, 200, { sha: result.sha, merged: true, message: 'Pull request successfully merged' });
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// REST routing
// ---------------------------------------------------------------------------

function routeRest(ctx: Ctx): boolean {
  if (!ctx.path.startsWith('/api/v3')) return false;
  const rest = ctx.path.slice('/api/v3'.length);
  if (rest === '' || rest === '/') {
    if (ctx.method === 'GET') {
      sendJson(ctx, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    } else {
      sendError(ctx, 404, 'Not Found');
    }
    return true;
  }
  if (rest === '/meta' && ctx.method === 'GET') {
    sendJson(ctx, 200, { installed_version: '1.0.0', git_protocol: 'v2' });
    return true;
  }
  if (rest === '/user' && ctx.method === 'GET') {
    sendJson(ctx, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }
  if (rest === '/user/repos') {
    handleUserRepos(ctx);
    return true;
  }
  const match = /^\/repos\/([^/]+)\/([^/]+)(.*)$/.exec(rest);
  if (match === null) {
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  const owner = decodeURIComponent(match[1] as string);
  const name = decodeURIComponent(match[2] as string);
  const tail = match[3] as string;
  if (tail === '') {
    handleRepoRoot(ctx, owner, name);
    return true;
  }
  if (tail === '/branches') {
    handleBranches(ctx, owner, name);
    return true;
  }
  const branchOne = /^\/branches\/(.+)$/.exec(tail);
  if (branchOne !== null) {
    handleBranchOne(ctx, owner, name, decodeURIComponent(branchOne[1] as string));
    return true;
  }
  if (tail === '/commits') {
    handleCommits(ctx, owner, name);
    return true;
  }
  if (tail === '/git/refs' || tail.startsWith('/git/refs/')) {
    handleGitRef(ctx, owner, name, tail === '/git/refs' ? '' : tail.slice('/git/refs/'.length));
    return true;
  }
  if (tail.startsWith('/contents')) {
    const filePath = tail === '/contents' ? '' : decodeURIComponent(tail.slice('/contents/'.length));
    handleContents(ctx, owner, name, filePath);
    return true;
  }
  if (tail === '/labels') {
    handleLabels(ctx, owner, name);
    return true;
  }
  if (tail === '/issues') {
    handleIssues(ctx, owner, name);
    return true;
  }
  const issueOne = /^\/issues\/(\d+)(\/comments)?$/.exec(tail);
  if (issueOne !== null) {
    if (issueOne[2] === '/comments') handleIssueComments(ctx, owner, name, issueOne[1] as string);
    else handleIssueOne(ctx, owner, name, issueOne[1] as string);
    return true;
  }
  if (tail === '/pulls') {
    handlePulls(ctx, owner, name);
    return true;
  }
  const pullOne = /^\/pulls\/(\d+)(?:\/(files|merge))?$/.exec(tail);
  if (pullOne !== null) {
    handlePullOne(ctx, owner, name, pullOne[1] as string, pullOne[2] ?? '');
    return true;
  }
  sendError(ctx, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

const UPLOAD_V0_CAPS = 'side-band-64k thin-pack ofs-delta multi_ack shallow agent=forge/1.0';
const RECEIVE_CAPS = 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';

function refLinesV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? UPLOAD_V0_CAPS : RECEIVE_CAPS;
  const symref = `symref=HEAD:refs/heads/${repo.defaultBranch}`;
  const allCaps = `${caps} ${symref}`;
  const items: PktItem[] = [`# service=${service}\n`, 'flush'];
  const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const headSha = repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
  items.push(`${headSha} HEAD\0${allCaps}\n`);
  for (const [ref, sha] of refs) {
    items.push(`${sha} ${ref}\n`);
    if (ref.startsWith('refs/tags/')) {
      const obj = repo.objects.get(sha);
      if (obj !== undefined && obj.type === 'tag') {
        const peeled = peelToCommit(repo, sha);
        if (peeled !== null) items.push(`${peeled} ${ref}^{}\n`);
      }
    }
  }
  items.push('flush');
  return pktLines(items);
}

function v2Capabilities(): Buffer {
  return pktLines([
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow filter thin-pack ofs-delta\n',
    'object-format=sha1\n',
    'agent=forge/1.0\n',
    'flush',
  ]);
}

function lsRefsResponse(repo: Repo, args: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const lines: PktItem[] = [];
  const headSha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((prefix) => name.startsWith(prefix));
  if (keep('HEAD')) {
    if (headSha === undefined) {
      if (args.unborn) lines.push(`unborn HEAD${args.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`);
    } else if (args.symrefs) {
      lines.push(`${headSha} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
    } else {
      lines.push(`${headSha} HEAD\n`);
    }
  }
  const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  for (const [ref, sha] of refs) {
    if (!keep(ref)) continue;
    let line = `${sha} ${ref}`;
    if (args.peel && ref.startsWith('refs/tags/')) {
      const obj = repo.objects.get(sha);
      if (obj !== undefined && obj.type === 'tag') {
        const peeled = peelToCommit(repo, sha);
        if (peeled !== null) line += ` peeled:${peeled}`;
      }
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  return pktLines(lines);
}

/** Split a sideband payload into pkt-lines of at most 32768 data bytes each. */
function sidebandPackets(band: number, data: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const chunkSize = 32768;
  if (data.length === 0) return out;
  for (let off = 0; off < data.length; off += chunkSize) {
    const chunk = data.subarray(off, Math.min(off + chunkSize, data.length));
    out.push(pktLine(Buffer.concat([Buffer.from([band]), chunk])));
  }
  return out;
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth?: number;
  done: boolean;
}

function parseFetchArgs(lines: readonly string[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], done: false };
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text.startsWith('want ')) args.wants.push(text.slice(5).split(' ')[0] as string);
    else if (text.startsWith('have ')) args.haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) args.shallow.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) {
      const n = Number.parseInt(text.slice(7), 10);
      if (Number.isFinite(n)) args.depth = n;
    } else if (text === 'done') args.done = true;
  }
  return args;
}

function fetchPackResponse(repo: Repo, args: FetchArgs): Buffer {
  const result = computeFetch(repo, args.wants, args.haves, args.shallow, args.depth);
  const parts: Buffer[] = [];
  if (args.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), DELIM);
  }
  if (result.shallow.length > 0 || result.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of result.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of result.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(DELIM);
  }
  if (result.send.length > 0) {
    const objects = result.send.map((oid) => repo.objects.get(oid)).filter((obj): obj is GitObj => obj !== undefined);
    const pack = buildPack(objects);
    parts.push(pktLine('packfile\n'));
    for (const packet of sidebandPackets(1, pack)) parts.push(packet);
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

function fetchV0Response(repo: Repo, args: FetchArgs): Buffer {
  const result = computeFetch(repo, args.wants, args.haves, args.shallow, args.depth);
  const parts: Buffer[] = [];
  if (args.haves.length > 0) parts.push(pktLine('NAK\n'));
  for (const oid of result.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of result.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (result.send.length > 0) {
    const objects = result.send.map((oid) => repo.objects.get(oid)).filter((obj): obj is GitObj => obj !== undefined);
    const pack = buildPack(objects);
    for (const packet of sidebandPackets(1, pack)) parts.push(packet);
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

async function handleUploadPack(ctx: Ctx, repo: Repo): Promise<void> {
  const wantV2 = ctx.req.headers['git-protocol'] === 'version=2';
  const raw = ctx.bodyBuffer;
  let parsed: { packets: PktPacket[]; consumed: number };
  try {
    parsed = parsePktStream(raw);
  } catch {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('bad pkt-line\n', 'utf8'));
    return;
  }
  const lines = parsed.packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  if (!wantV2) {
    // Protocol v0 fetch: wants, then flush, then haves + done, then flush.
    const args = parseFetchArgs(lines);
    const body = fetchV0Response(repo, args);
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', body);
    return;
  }
  const command = lines.find((line) => line.startsWith('command='))?.slice('command='.length).trim() ?? '';
  if (command === 'ls-refs') {
    const args = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
    for (const line of lines) {
      const text = line.replace(/\n$/, '');
      if (text === 'peel') args.peel = true;
      else if (text === 'symrefs') args.symrefs = true;
      else if (text === 'unborn') args.unborn = true;
      else if (text.startsWith('ref-prefix ')) args.prefixes.push(text.slice('ref-prefix '.length));
    }
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, args));
    return;
  }
  if (command === 'fetch') {
    const args = parseFetchArgs(lines);
    sendRaw(ctx, 200, 'application/x-git-upload-pack-result', fetchPackResponse(repo, args));
    return;
  }
  sendRaw(ctx, 400, 'text/plain', Buffer.from('unknown command\n', 'utf8'));
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

async function handleReceivePack(ctx: Ctx, repo: Repo): Promise<void> {
  const raw = ctx.bodyBuffer;
  // Walk the command pkt-lines by hand until the flush: the bytes after it
  // are a raw packfile, and a generic pkt-line walk would choke on 'PACK'.
  const commands: PushCommand[] = [];
  let packStart = raw.length;
  try {
    let off = 0;
    while (off + 4 <= raw.length) {
      const len = parseInt(raw.subarray(off, off + 4).toString('ascii'), 16);
      if (!Number.isFinite(len)) throw new Error('bad pkt-line length');
      if (len === 0) {
        off += 4;
        packStart = off;
        break;
      }
      if (len < 4 || off + len > raw.length) throw new Error('truncated pkt-line');
      const text = raw.subarray(off + 4, off + len).toString('utf8').replace(/\n$/, '');
      const nul = text.indexOf('\0');
      const head = nul < 0 ? text : text.slice(0, nul);
      const parts = head.split(' ');
      if (parts.length >= 3) {
        commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
      }
      off += len;
    }
  } catch {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('bad pkt-line\n', 'utf8'));
    return;
  }
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = raw.subarray(packStart);
  if (packBytes.length > 0) {
    try {
      const objects = await readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const obj of objects) {
        if (!repo.objects.has(obj.oid)) repo.objects.set(obj.oid, makeGitObj(obj.type, obj.data));
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  for (const command of commands) {
    if (!unpackOk) {
      reportLines.push(`ng ${command.ref} unpack failed`);
      continue;
    }
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        reportLines.push(`ng ${command.ref} remote ref does not exist`);
      } else if (command.oldOid !== ZERO_OID && command.oldOid.toLowerCase() !== current.toLowerCase()) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
      } else {
        repo.refs.delete(command.ref);
        reportLines.push(`ok ${command.ref}`);
      }
      continue;
    }
    if (repo.objects.get(command.newOid) === undefined) {
      reportLines.push(`ng ${command.ref} object not found`);
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      if (current !== undefined) {
        reportLines.push(`ng ${command.ref} already exists`);
      } else {
        repo.refs.set(command.ref, command.newOid);
        reportLines.push(`ok ${command.ref}`);
      }
      continue;
    }
    if (current === undefined) {
      reportLines.push(`ng ${command.ref} remote ref does not exist`);
      continue;
    }
    if (command.oldOid.toLowerCase() !== current.toLowerCase()) {
      reportLines.push(`ng ${command.ref} non-fast-forward`);
      continue;
    }
    const newCommit = peelToCommit(repo, command.newOid);
    if (newCommit === null || !isAncestor(repo, current, newCommit)) {
      reportLines.push(`ng ${command.ref} non-fast-forward`);
      continue;
    }
    repo.refs.set(command.ref, command.newOid);
    reportLines.push(`ok ${command.ref}`);
  }
  const inner = pktLines([`unpack ${unpackDetail}\n`, ...reportLines.map((line) => `${line}\n`), 'flush']);
  const outer: Buffer[] = [];
  for (const packet of sidebandPackets(1, inner)) outer.push(packet);
  outer.push(FLUSH);
  sendRaw(ctx, 200, 'application/x-git-receive-pack-result', Buffer.concat(outer));
}

function handleGit(ctx: Ctx): boolean {
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)$/.exec(ctx.path);
  if (match === null) return false;
  const owner = decodeURIComponent(match[1] as string);
  const name = decodeURIComponent(match[2] as string);
  const tail = match[3] as string;
  const repo = findRepo(owner, name);
  if (ctx.method === 'GET' && tail.startsWith('/info/refs')) {
    if (repo === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    const service = ctx.query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const wantV2 = ctx.req.headers['git-protocol'] === 'version=2';
      if (wantV2) sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', v2Capabilities());
      else sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', refLinesV0(repo, 'git-upload-pack'));
      return true;
    }
    if (service === 'git-receive-pack') {
      sendRaw(ctx, 200, 'application/x-git-receive-pack-advertisement', refLinesV0(repo, 'git-receive-pack'));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  if (repo === undefined) {
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  if (ctx.method === 'POST' && tail === '/git-upload-pack') {
    void handleUploadPack(ctx, repo);
    return true;
  }
  if (ctx.method === 'POST' && tail === '/git-receive-pack') {
    void handleReceivePack(ctx, repo);
    return true;
  }
  sendError(ctx, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small parser and executor for the documents gh sends
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  kind: 'field';
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
}

interface GqlFragment {
  kind: 'fragment';
  typeCondition: string | null;
  selections: GqlSelection[];
}

type GqlSelection = GqlField | GqlFragment;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Record<string, GqlValue | undefined>;
  selections: GqlSelection[];
}

class GqlParser {
  private pos = 0;
  private readonly text: string;
  constructor(text: string) {
    this.text = text;
  }

  parse(): GqlOperation {
    this.skipSpace();
    let kind: 'query' | 'mutation' = 'query';
    if (this.peekWord() === 'mutation') {
      kind = 'mutation';
      this.pos += 'mutation'.length;
    } else if (this.peekWord() === 'query') {
      this.pos += 'query'.length;
    }
    this.skipSpace();
    let name: string | null = null;
    const word = this.peekWord();
    if (word !== '' && word !== '(' && word !== '{') {
      name = word;
      this.pos += word.length;
    }
    const variables: Record<string, GqlValue | undefined> = {};
    this.skipSpace();
    if (this.text[this.pos] === '(') {
      this.pos += 1;
      this.skipSpace();
      while (this.text[this.pos] !== ')' && this.pos < this.text.length) {
        if (this.text[this.pos] === '$') {
          this.pos += 1;
          const varName = this.readName();
          this.skipSpace();
          if (this.text[this.pos] === ':') this.pos += 1;
          this.skipSpace();
          this.readName();
          if (this.text[this.pos] === '!') this.pos += 1;
          this.skipSpace();
          if (this.text[this.pos] === '=') {
            this.pos += 1;
            this.skipSpace();
            variables[varName] = this.readValue();
          } else {
            variables[varName] = undefined;
          }
          this.skipSpace();
          if (this.text[this.pos] === ',') this.pos += 1;
          this.skipSpace();
        } else {
          this.pos += 1;
        }
      }
      if (this.text[this.pos] === ')') this.pos += 1;
    }
    const selections = this.readSelectionSet();
    return { kind, name, variables, selections };
  }

  private skipSpace(): void {
    for (;;) {
      while (this.pos < this.text.length && /\s/.test(this.text[this.pos] as string)) this.pos += 1;
      if (this.text[this.pos] === '#') {
        while (this.pos < this.text.length && this.text[this.pos] !== '\n') this.pos += 1;
        continue;
      }
      return;
    }
  }

  private peekWord(): string {
    const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.text.slice(this.pos));
    return match === null ? '' : match[0];
  }

  private readName(): string {
    const word = this.peekWord();
    if (word === '') throw new Error(`expected a name at ${this.pos}`);
    this.pos += word.length;
    return word;
  }

  private readSelectionSet(): GqlSelection[] {
    this.skipSpace();
    if (this.text[this.pos] !== '{') throw new Error(`expected '{' at ${this.pos}`);
    this.pos += 1;
    const out: GqlSelection[] = [];
    for (;;) {
      this.skipSpace();
      if (this.pos >= this.text.length) throw new Error('unterminated selection set');
      if (this.text[this.pos] === '}') {
        this.pos += 1;
        return out;
      }
      if (this.text.startsWith('...', this.pos)) {
        this.pos += 3;
        this.skipSpace();
        let typeCondition: string | null = null;
        if (this.peekWord() === 'on') {
          this.pos += 2;
          this.skipSpace();
          typeCondition = this.readName();
        }
        const selections = this.readSelectionSet();
        out.push({ kind: 'fragment', typeCondition, selections });
        continue;
      }
      const first = this.readName();
      this.skipSpace();
      let alias: string | null = null;
      let name = first;
      if (this.text[this.pos] === ':') {
        alias = first;
        this.pos += 1;
        this.skipSpace();
        name = this.readName();
        this.skipSpace();
      }
      const args: Record<string, GqlValue> = {};
      if (this.text[this.pos] === '(') {
        this.pos += 1;
        this.skipSpace();
        while (this.text[this.pos] !== ')' && this.pos < this.text.length) {
          const argName = this.readName();
          this.skipSpace();
          if (this.text[this.pos] === ':') this.pos += 1;
          this.skipSpace();
          args[argName] = this.readValue();
          this.skipSpace();
          if (this.text[this.pos] === ',') this.pos += 1;
          this.skipSpace();
        }
        if (this.text[this.pos] === ')') this.pos += 1;
        this.skipSpace();
      }
      let selections: GqlSelection[] = [];
      if (this.text[this.pos] === '{') selections = this.readSelectionSet();
      out.push({ kind: 'field', alias, name, args, selections });
    }
  }

  private readValue(): GqlValue {
    this.skipSpace();
    const ch = this.text[this.pos];
    if (ch === '$') {
      this.pos += 1;
      return { kind: 'variable', name: this.readName() };
    }
    if (ch === '"') {
      this.pos += 1;
      let out = '';
      while (this.pos < this.text.length && this.text[this.pos] !== '"') {
        if (this.text[this.pos] === '\\') {
          this.pos += 1;
          const esc = this.text[this.pos] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          this.pos += 1;
        } else {
          out += this.text[this.pos] as string;
          this.pos += 1;
        }
      }
      this.pos += 1;
      return { kind: 'string', value: out };
    }
    if (ch === '[') {
      this.pos += 1;
      const values: GqlValue[] = [];
      this.skipSpace();
      while (this.text[this.pos] !== ']' && this.pos < this.text.length) {
        values.push(this.readValue());
        this.skipSpace();
        if (this.text[this.pos] === ',') this.pos += 1;
        this.skipSpace();
      }
      this.pos += 1;
      return { kind: 'list', values };
    }
    if (ch === '{') {
      this.pos += 1;
      const fields: Array<{ name: string; value: GqlValue }> = [];
      this.skipSpace();
      while (this.text[this.pos] !== '}' && this.pos < this.text.length) {
        const name = this.readName();
        this.skipSpace();
        if (this.text[this.pos] === ':') this.pos += 1;
        this.skipSpace();
        fields.push({ name, value: this.readValue() });
        this.skipSpace();
        if (this.text[this.pos] === ',') this.pos += 1;
        this.skipSpace();
      }
      this.pos += 1;
      return { kind: 'object', fields };
    }
    const num = /^-?\d+(\.\d+)?/.exec(this.text.slice(this.pos));
    if (num !== null) {
      this.pos += num[0].length;
      return num[0].includes('.') ? { kind: 'float', value: Number(num[0]) } : { kind: 'int', value: Number(num[0]) };
    }
    const word = this.peekWord();
    this.pos += word.length;
    if (word === 'true') return { kind: 'boolean', value: true };
    if (word === 'false') return { kind: 'boolean', value: false };
    if (word === 'null') return { kind: 'null' };
    return { kind: 'enum', value: word };
  }
}

function evalValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((item) => evalValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalValue(field.value, variables);
      return out;
    }
  }
}

function evalArgs(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(field.args)) out[key] = evalValue(value, variables);
  return out;
}

// ---------------------------------------------------------------------------
// GraphQL schema data
// ---------------------------------------------------------------------------

interface TypeFieldInfo {
  name: string;
}

const ISSUE_FIELDS: TypeFieldInfo[] = [
  'id', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments',
].map((name) => ({ name }));

const PULL_FIELDS: TypeFieldInfo[] = [
  'id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'url', 'createdAt', 'author', 'headRef', 'baseRef',
].map((name) => ({ name }));

const REPO_FIELDS: TypeFieldInfo[] = [
  'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt',
].map((name) => ({ name }));

const SEARCH_ENUMS: TypeFieldInfo[] = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'].map((name) => ({ name }));

interface GqlObject {
  __typename: string;
  [key: string]: unknown;
}

function repoGqlId(repo: Repo): string {
  return globalId('R', `${repo.owner}/${repo.name}`);
}

function issueGqlId(repo: Repo, issue: Issue): string {
  return globalId('I', `${repo.owner}/${repo.name}#${issue.number}`);
}

function pullGqlId(repo: Repo, pull: Pull): string {
  return globalId('PR', `${repo.owner}/${repo.name}#${pull.number}`);
}

function commentGqlId(repo: Repo, issue: Issue, comment: IssueComment): string {
  return globalId('C', `${repo.owner}/${repo.name}#${issue.number}/${comment.id}`);
}

function issueStateGql(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function issueToGql(repo: Repo, issue: Issue): GqlObject {
  return {
    __typename: 'Issue',
    id: issueGqlId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issueStateGql(issue),
    url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    createdAt: issue.createdAt,
    updatedAt: issue.updatedAt,
    _repo: repo,
    _issue: issue,
  };
}

function pullToGql(repo: Repo, pull: Pull): GqlObject {
  return {
    __typename: 'PullRequest',
    id: pullGqlId(repo, pull),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pullStateGql(pull),
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull) ? 'MERGEABLE' : 'CONFLICTING',
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    url: `https://example.invalid/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    createdAt: pull.createdAt,
    _repo: repo,
    _pull: pull,
  };
}

function repoToGql(repo: Repo): GqlObject {
  return {
    __typename: 'Repository',
    id: repoGqlId(repo),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    description: repo.description,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    url: `https://example.invalid/${repo.owner}/${repo.name}`,
    createdAt: repo.createdAt,
    _repo: repo,
  };
}

function findByGlobalId(id: string): { repo: Repo; issue?: Issue; pull?: Pull } | null {
  for (const repo of viewerRepos) {
    if (repoGqlId(repo) === id) return { repo };
    for (const issue of repo.issues.values()) {
      if (issueGqlId(repo, issue) === id) return { repo, issue };
    }
    for (const pull of repo.pulls.values()) {
      if (pullGqlId(repo, pull) === id) return { repo, pull };
    }
  }
  return null;
}

function cursorFor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64');
}

function numberFromCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? null : Number(match[1]);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// GraphQL execution
// ---------------------------------------------------------------------------

class GqlExecutor {
  errors: Array<{ message: string }> = [];

  execute(operation: GqlOperation, variables: Record<string, unknown>): Record<string, unknown> {
    const vars: Record<string, unknown> = { ...variables };
    for (const [name, def] of Object.entries(operation.variables)) {
      if (vars[name] === undefined && def !== undefined) vars[name] = evalValue(def, variables);
    }
    if (operation.kind === 'mutation') {
      return this.resolveSelections({ __typename: 'Mutation' }, operation.selections, vars);
    }
    return this.resolveSelections({ __typename: 'Query' }, operation.selections, vars);
  }

  private resolveSelections(obj: GqlObject, selections: readonly GqlSelection[], vars: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const selection of selections) {
      if (selection.kind === 'fragment') {
        if (selection.typeCondition !== null && selection.typeCondition !== obj.__typename) continue;
        const nested = this.resolveSelections(obj, selection.selections, vars);
        Object.assign(out, nested);
        continue;
      }
      const key = selection.alias ?? selection.name;
      const value = this.resolveField(obj, selection, vars);
      if (value !== undefined) out[key] = value;
    }
    return out;
  }

  private resolveField(obj: GqlObject, field: GqlField, vars: Record<string, unknown>): unknown {
    const args = evalArgs(field, vars);
    const type = obj.__typename;
    const handler = FIELD_RESOLVERS[`${type}.${field.name}`];
    if (handler === undefined) {
      this.errors.push({ message: `Cannot query field "${field.name}" on type "${type}".` });
      return undefined;
    }
    const raw = handler(this, obj, args);
    if (raw === null || raw === undefined) return raw;
    if (field.selections.length === 0) {
      if (raw !== null && typeof raw === 'object' && !Array.isArray(raw) && (raw as GqlObject).__typename !== undefined) {
        return raw;
      }
      return raw;
    }
    if (Array.isArray(raw)) {
      return raw.map((item) => {
        if (item !== null && typeof item === 'object' && (item as GqlObject).__typename !== undefined) {
          return this.resolveSelections(item as GqlObject, field.selections, vars);
        }
        return item;
      });
    }
    if (typeof raw === 'object' && (raw as GqlObject).__typename !== undefined) {
      return this.resolveSelections(raw as GqlObject, field.selections, vars);
    }
    return raw;
  }
}

type FieldHandler = (exec: GqlExecutor, obj: GqlObject, args: Record<string, unknown>) => unknown;

const FIELD_RESOLVERS: Record<string, FieldHandler> = {
  'Query.viewer': () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
  'Query.repository': (_exec, _obj, args) => {
    const repo = findRepo(String(args.owner ?? ''), String(args.name ?? ''));
    return repo === undefined ? null : repoToGql(repo);
  },
  'Query.node': (_exec, _obj, args) => {
    const found = findByGlobalId(String(args.id ?? ''));
    if (found === null) return null;
    if (found.issue !== undefined) return issueToGql(found.repo, found.issue);
    if (found.pull !== undefined) return pullToGql(found.repo, found.pull);
    return repoToGql(found.repo);
  },
  'Query.__type': (_exec, _obj, args) => {
    const name = String(args.name ?? '');
    if (name === 'Issue') return { __typename: '__Type', name, kind: 'OBJECT', fields: ISSUE_FIELDS, enumValues: [] };
    if (name === 'PullRequest') return { __typename: '__Type', name, kind: 'OBJECT', fields: PULL_FIELDS, enumValues: [] };
    if (name === 'Repository') return { __typename: '__Type', name, kind: 'OBJECT', fields: REPO_FIELDS, enumValues: [] };
    if (name === 'SearchType') return { __typename: '__Type', name, kind: 'ENUM', fields: [], enumValues: SEARCH_ENUMS };
    if (name === 'User') return { __typename: '__Type', name, kind: 'OBJECT', fields: [{ name: 'login' }, { name: 'id' }], enumValues: [] };
    return null;
  },
  'Repository.id': (_exec, obj) => obj.id,
  'Repository.databaseId': (_exec, obj) => obj.databaseId,
  'Repository.name': (_exec, obj) => obj.name,
  'Repository.nameWithOwner': (_exec, obj) => obj.nameWithOwner,
  'Repository.description': (_exec, obj) => obj.description,
  'Repository.viewerPermission': (_exec, obj) => obj.viewerPermission,
  'Repository.hasIssuesEnabled': (_exec, obj) => obj.hasIssuesEnabled,
  'Repository.url': (_exec, obj) => obj.url,
  'Repository.createdAt': (_exec, obj) => obj.createdAt,
  'Repository.owner': () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
  'Repository.defaultBranchRef': (_exec, obj) => {
    const repo = obj._repo as Repo;
    return { __typename: 'Ref', name: repo.defaultBranch };
  },
  'Repository.issue': (_exec, obj, args) => {
    const repo = obj._repo as Repo;
    const issue = repo.issues.get(Number(args.number));
    return issue === undefined ? null : issueToGql(repo, issue);
  },
  'Repository.issues': (_exec, obj, args) => {
    const repo = obj._repo as Repo;
    let list = [...repo.issues.values()];
    const states = args.states;
    if (Array.isArray(states) && states.length > 0) {
      const wanted = new Set(states.map((state) => String(state).toLowerCase()));
      list = list.filter((issue) => wanted.has(issue.state));
    }
    const orderBy = args.orderBy as Record<string, unknown> | undefined;
    if (orderBy !== undefined && typeof orderBy === 'object') {
      const direction = String(orderBy.direction ?? 'ASC');
      list.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
    } else {
      list.sort((a, b) => a.number - b.number);
    }
    const afterNum = numberFromCursor(args.after);
    if (afterNum !== null) {
      const desc = orderBy !== undefined && String((orderBy as Record<string, unknown>).direction ?? '') === 'DESC';
      list = list.filter((issue) => (desc ? issue.number < afterNum : issue.number > afterNum));
    }
    const first = typeof args.first === 'number' ? args.first : list.length;
    const page = list.slice(0, first);
    const hasNext = list.length > first;
    const endCursor = page.length > 0 ? cursorFor((page[page.length - 1] as Issue).number) : null;
    return {
      __typename: 'IssueConnection',
      nodes: page.map((issue) => issueToGql(repo, issue)),
      pageInfo: { __typename: 'PageInfo', hasNextPage: hasNext, endCursor },
      totalCount: list.length,
    };
  },
  'Repository.pullRequests': (_exec, obj, args) => {
    const repo = obj._repo as Repo;
    let list = [...repo.pulls.values()].filter((pull) => pull.state === 'open').sort((a, b) => a.number - b.number);
    const first = typeof args.first === 'number' ? args.first : list.length;
    list = list.slice(0, first);
    return {
      __typename: 'PullRequestConnection',
      nodes: list.map((pull) => pullToGql(repo, pull)),
      pageInfo: { __typename: 'PageInfo', hasNextPage: false, endCursor: null },
      totalCount: list.length,
    };
  },
  'Repository.pullRequest': (_exec, obj, args) => {
    const repo = obj._repo as Repo;
    const pull = repo.pulls.get(Number(args.number));
    return pull === undefined ? null : pullToGql(repo, pull);
  },
  'Issue.id': (_exec, obj) => obj.id,
  'Issue.number': (_exec, obj) => obj.number,
  'Issue.title': (_exec, obj) => obj.title,
  'Issue.body': (_exec, obj) => obj.body,
  'Issue.state': (_exec, obj) => obj.state,
  'Issue.url': (_exec, obj) => obj.url,
  'Issue.createdAt': (_exec, obj) => obj.createdAt,
  'Issue.updatedAt': (_exec, obj) => obj.updatedAt,
  'Issue.author': () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
  'Issue.labels': (_exec, obj) => {
    const issue = obj._issue as Issue;
    return { __typename: 'LabelConnection', nodes: issue.labels.map((name) => ({ __typename: 'Label', name })) };
  },
  'Issue.comments': (_exec, obj) => {
    const repo = obj._repo as Repo;
    const issue = obj._issue as Issue;
    return {
      __typename: 'IssueCommentConnection',
      nodes: issue.comments.map((comment) => ({ __typename: 'IssueComment', id: commentGqlId(repo, issue, comment), body: comment.body })),
    };
  },
  'PullRequest.id': (_exec, obj) => obj.id,
  'PullRequest.number': (_exec, obj) => obj.number,
  'PullRequest.title': (_exec, obj) => obj.title,
  'PullRequest.body': (_exec, obj) => obj.body,
  'PullRequest.state': (_exec, obj) => obj.state,
  'PullRequest.merged': (_exec, obj) => obj.merged,
  'PullRequest.mergeable': (_exec, obj) => obj.mergeable,
  'PullRequest.headRefName': (_exec, obj) => obj.headRefName,
  'PullRequest.baseRefName': (_exec, obj) => obj.baseRefName,
  'PullRequest.url': (_exec, obj) => obj.url,
  'PullRequest.createdAt': (_exec, obj) => obj.createdAt,
  'PullRequest.author': () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
  'PullRequest.headRef': (_exec, obj) => ({ __typename: 'Ref', name: obj.headRefName }),
  'PullRequest.baseRef': (_exec, obj) => ({ __typename: 'Ref', name: obj.baseRefName }),
  'PullRequest.files': (_exec, obj, args) => {
    const repo = obj._repo as Repo;
    const pull = obj._pull as Pull;
    const changes = diffFileMaps(repo, fileMapOf(repo, pull.baseSha), fileMapOf(repo, pull.headSha));
    const first = typeof args.first === 'number' ? args.first : changes.length;
    return {
      __typename: 'PullRequestChangedFileConnection',
      nodes: changes.slice(0, first).map((change) => ({ __typename: 'PullRequestChangedFile', path: change.filename })),
      pageInfo: { __typename: 'PageInfo', hasNextPage: changes.length > first, endCursor: null },
    };
  },
  'User.login': (_exec, obj) => obj.login,
  'User.id': (_exec, obj) => obj.id,
  'Ref.name': (_exec, obj) => obj.name,
  'IssueConnection.nodes': (_exec, obj) => obj.nodes,
  'IssueConnection.pageInfo': (_exec, obj) => obj.pageInfo,
  'IssueConnection.totalCount': (_exec, obj) => obj.totalCount,
  'PullRequestConnection.nodes': (_exec, obj) => obj.nodes,
  'PullRequestConnection.pageInfo': (_exec, obj) => obj.pageInfo,
  'PullRequestConnection.totalCount': (_exec, obj) => obj.totalCount,
  'PullRequestChangedFileConnection.nodes': (_exec, obj) => obj.nodes,
  'PullRequestChangedFileConnection.pageInfo': (_exec, obj) => obj.pageInfo,
  'PullRequestChangedFile.path': (_exec, obj) => obj.path,
  'PageInfo.hasNextPage': (_exec, obj) => obj.hasNextPage,
  'PageInfo.endCursor': (_exec, obj) => obj.endCursor,
  'PageInfo.hasPreviousPage': () => false,
  'PageInfo.startCursor': (_exec, obj) => obj.endCursor ?? null,
  '__Type.name': (_exec, obj) => obj.name,
  '__Type.kind': (_exec, obj) => obj.kind,
  '__Type.fields': (_exec, obj) => (obj.fields as TypeFieldInfo[]).map((field) => ({ __typename: '__Field', name: field.name })),
  '__Type.enumValues': (_exec, obj) => (obj.enumValues as TypeFieldInfo[]).map((field) => ({ __typename: '__EnumValue', name: field.name })),
  '__Field.name': (_exec, obj) => obj.name,
  '__EnumValue.name': (_exec, obj) => obj.name,
  'LabelConnection.nodes': (_exec, obj) => obj.nodes,
  'Label.name': (_exec, obj) => obj.name,
  'IssueCommentConnection.nodes': (_exec, obj) => obj.nodes,
  'IssueComment.id': (_exec, obj) => obj.id,
  'IssueComment.body': (_exec, obj) => obj.body,
  'Mutation.createIssue': (_exec, _obj, args) => {
    const input = (args.input ?? {}) as Record<string, unknown>;
    const found = findByGlobalId(String(input.repositoryId ?? ''));
    if (found === null) return { __typename: 'CreateIssuePayload', issue: null };
    const repo = found.repo;
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = freshIso();
    const issue: Issue = {
      number,
      title: String(input.title ?? ''),
      body: String(input.body ?? ''),
      state: 'open',
      labels: [],
      comments: [],
      seq: nextTick(),
      createdAt: now,
      updatedAt: now,
      cachedJson: null,
    };
    repo.issues.set(number, issue);
    return { __typename: 'CreateIssuePayload', issue: issueToGql(repo, issue) };
  },
  'Mutation.closeIssue': (_exec, _obj, args) => {
    const input = (args.input ?? {}) as Record<string, unknown>;
    const found = findByGlobalId(String(input.issueId ?? ''));
    if (found === null || found.issue === undefined) return { __typename: 'CloseIssuePayload', issue: null };
    found.issue.state = 'closed';
    found.issue.updatedAt = freshIso();
    found.issue.cachedJson = null;
    return { __typename: 'CloseIssuePayload', issue: issueToGql(found.repo, found.issue) };
  },
  'Mutation.createPullRequest': (_exec, _obj, args) => {
    const input = (args.input ?? {}) as Record<string, unknown>;
    const found = findByGlobalId(String(input.repositoryId ?? ''));
    if (found === null) return { __typename: 'CreatePullRequestPayload', pullRequest: null };
    const made = createPullRecord(
      found.repo,
      String(input.title ?? ''),
      String(input.body ?? ''),
      String(input.headRefName ?? ''),
      String(input.baseRefName ?? ''),
    );
    if ('error' in made) return { __typename: 'CreatePullRequestPayload', pullRequest: null };
    return { __typename: 'CreatePullRequestPayload', pullRequest: pullToGql(found.repo, made.pull) };
  },
  'Mutation.mergePullRequest': (_exec, _obj, args) => {
    const input = (args.input ?? {}) as Record<string, unknown>;
    const found = findByGlobalId(String(input.pullRequestId ?? ''));
    if (found === null || found.pull === undefined) return { __typename: 'MergePullRequestPayload', pullRequest: null };
    doMerge(found.repo, found.pull);
    return { __typename: 'MergePullRequestPayload', pullRequest: pullToGql(found.repo, found.pull) };
  },
  'Mutation.addComment': (_exec, _obj, args) => {
    const input = (args.input ?? {}) as Record<string, unknown>;
    const found = findByGlobalId(String(input.subjectId ?? ''));
    if (found === null || found.issue === undefined) return { __typename: 'AddCommentPayload', commentEdge: null };
    const comment: IssueComment = { id: nextGlobalCommentId, body: String(input.body ?? ''), createdAt: freshIso() };
    nextGlobalCommentId += 1;
    found.issue.comments.push(comment);
    found.issue.cachedJson = null;
    return {
      __typename: 'AddCommentPayload',
      commentEdge: {
        __typename: 'IssueCommentEdge',
        node: { __typename: 'IssueComment', id: commentGqlId(found.repo, found.issue, comment), body: comment.body },
      },
    };
  },
  'CreateIssuePayload.issue': (_exec, obj) => obj.issue,
  'CloseIssuePayload.issue': (_exec, obj) => obj.issue,
  'CreatePullRequestPayload.pullRequest': (_exec, obj) => obj.pullRequest,
  'MergePullRequestPayload.pullRequest': (_exec, obj) => obj.pullRequest,
  'AddCommentPayload.commentEdge': (_exec, obj) => obj.commentEdge,
  'IssueCommentEdge.node': (_exec, obj) => obj.node,
};

function runGraphqlDocument(query: string, variables: Record<string, unknown>): Record<string, unknown> {
  const executor = new GqlExecutor();
  let operation: GqlOperation;
  try {
    operation = new GqlParser(query).parse();
  } catch (err) {
    return { data: {}, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
  const data = executor.execute(operation, variables);
  if (executor.errors.length > 0) return { data, errors: executor.errors };
  return { data };
}

function handleGraphql(ctx: Ctx): void {
  if (ctx.method !== 'POST') {
    sendError(ctx, 404, 'Not Found');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.bodyText);
  } catch {
    sendJson(ctx, 400, { errors: [{ message: 'request body is not valid JSON' }] });
    return;
  }
  if (Array.isArray(parsed)) {
    const results = parsed.map((entry) => {
      const record = asRecord(entry);
      const query = typeof record.query === 'string' ? record.query : '';
      const variables = asRecord(record.variables);
      return runGraphqlDocument(query, variables);
    });
    sendJson(ctx, 200, results);
    return;
  }
  const record = asRecord(parsed);
  const query = typeof record.query === 'string' ? record.query : '';
  const variables = asRecord(record.variables);
  sendJson(ctx, 200, runGraphqlDocument(query, variables));
}

// ---------------------------------------------------------------------------
// MCP over streamable HTTP (JSON-RPC 2.0)
// ---------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues of a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(payload: unknown): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return {
    content: [{ type: 'text', text }],
    structuredContent: payload,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpMissingArgs(tool: McpToolDef, args: Record<string, unknown>): string[] {
  const required = (tool.inputSchema.required ?? []) as string[];
  return required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((entry) => entry.name === name);
  if (tool === undefined) return { error: { code: -32602, message: `unknown tool: ${name}` } };
  const missing = mcpMissingArgs(tool, args);
  if (missing.length > 0) return { result: mcpToolError(`missing required arguments: ${missing.join(', ')}`) };
  const owner = typeof args.owner === 'string' && args.owner !== '' ? args.owner : VIEWER_LOGIN;
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (reposByKey.has(repoKey(VIEWER_LOGIN, repoName))) {
      return { result: mcpToolError(`repository ${repoName} already exists`) };
    }
    const repo = createRepoRecord(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return { result: mcpToolResult(repoJson(repo)) };
  }
  const repoName = String(args.repo ?? '');
  const repo = findRepo(owner, repoName);
  if (repo === undefined) return { result: mcpToolError(`repository ${owner}/${repoName} not found`) };
  if (name === 'get_repo') {
    return { result: mcpToolResult(repoJson(repo)) };
  }
  if (name === 'create_issue') {
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = freshIso();
    const issue: Issue = {
      number,
      title: String(args.title ?? ''),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      comments: [],
      seq: nextTick(),
      createdAt: now,
      updatedAt: now,
      cachedJson: null,
    };
    repo.issues.set(number, issue);
    return { result: mcpToolResult(issueJson(repo, issue)) };
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = sortedIssues(repo, state, 'created', 'asc');
    return { result: mcpToolResult(list.map((issue) => issueJson(repo, issue))) };
  }
  if (name === 'create_pull_request') {
    const made = createPullRecord(
      repo,
      String(args.title ?? ''),
      typeof args.body === 'string' ? args.body : '',
      String(args.head ?? ''),
      String(args.base ?? repo.defaultBranch),
    );
    if ('error' in made) return { result: mcpToolError(made.error) };
    return { result: mcpToolResult(pullJson(repo, made.pull)) };
  }
  if (name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pull = repo.pulls.get(number);
    if (pull === undefined) return { result: mcpToolError(`pull request #${args.pull_number} not found`) };
    const result = doMerge(repo, pull);
    if ('error' in result) return { result: mcpToolError(result.error) };
    return { result: mcpToolResult({ ...pullJson(repo, pull), sha: result.sha, merged: true, message: 'Pull request successfully merged' }) };
  }
  return { error: { code: -32602, message: `unknown tool: ${name}` } };
}

function handleMcp(ctx: Ctx): void {
  if (ctx.method !== 'POST') {
    sendJson(ctx, 405, { message: 'Method Not Allowed' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.bodyText);
  } catch {
    sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const record = asRecord(parsed);
  const id = record.id ?? null;
  const method = typeof record.method === 'string' ? record.method : '';
  const params = asRecord(record.params);
  const reply = (payload: Record<string, unknown>): void => {
    sendJson(ctx, 200, { jsonrpc: '2.0', id, ...payload });
  };
  if (method === 'server/discover') {
    reply({
      result: {
        protocolVersion: '2026-07-28',
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const wanted = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const known = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    reply({
      result: {
        protocolVersion: known.includes(wanted) ? wanted : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      },
    });
    return;
  }
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    ctx.res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    ctx.res.end();
    return;
  }
  if (method === 'ping') {
    reply({ result: {} });
    return;
  }
  if (method === 'tools/list') {
    reply({ result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = asRecord(params.arguments);
    const outcome = mcpCallTool(toolName, args);
    if ('error' in outcome) {
      reply({ error: outcome.error });
      return;
    }
    reply({ result: outcome.result });
    return;
  }
  reply({ error: { code: -32601, message: `method not found: ${method}` } });
}

// ---------------------------------------------------------------------------
// Server assembly
// ---------------------------------------------------------------------------

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

function isAuthed(ctx: Ctx): boolean {
  const header = ctx.req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  if (token === '') return false;
  if (SHOP_TOKEN !== '') return token === SHOP_TOKEN;
  return true;
}

async function onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let url: URL;
  try {
    url = new URL(req.url ?? '/', 'http://entry');
  } catch {
    url = new URL('/', 'http://entry');
  }
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const rawBody = await readBody(req).catch(() => Buffer.alloc(0));
  const ctx: Ctx = {
    req,
    res,
    method: req.method ?? 'GET',
    path,
    query: url.searchParams,
    host: req.headers.host ?? '127.0.0.1',
    bodyText: rawBody.toString('utf8'),
    body: undefined,
    authed: false,
    bodyBuffer: rawBody,
  };
  try {
    if (ctx.method === 'GET' && ctx.path === '/healthz') {
      sendJson(ctx, 200, { ok: true });
      return;
    }
    const needsAuth =
      ctx.path.startsWith('/api/v3') || ctx.path === '/api/graphql' || ctx.path === '/mcp' || /\.git(\/|$)/.test(ctx.path);
    if (needsAuth) {
      if (!isAuthed(ctx)) {
        sendError(ctx, 401, 'Requires authentication');
        return;
      }
      ctx.authed = true;
    }
    if (ctx.path === '/api/graphql') {
      handleGraphql(ctx);
      return;
    }
    if (ctx.path === '/mcp') {
      handleMcp(ctx);
      return;
    }
    if (routeRest(ctx)) return;
    if (handleGit(ctx)) return;
    sendError(ctx, 404, 'Not Found');
  } catch (err) {
    if (!res.writableEnded) {
      try {
        sendError(ctx, 500, err instanceof Error ? err.message : 'Internal error');
      } catch {
        // The socket is already gone; nothing left to do.
      }
    }
  }
}

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  void checkInflate();
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void onRequest(req, res);
  });
}
