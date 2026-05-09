#!/usr/bin/env node
//
// JSON-over-stdin adapter for the `@atproto/*` TypeScript SDK.
//
// Protocol: line-delimited JSON. Each input line is
//
//     { "op": "<opname>", "input": <any> }
//
// and each output line is
//
//     { "ok": true, "value": <any> }
// or
//     { "ok": false, "error": "<kind>", "message": "<display>" }
//
// The Rust harness spawns this process with `stdio: 'piped'`, writes
// N requests, and reads N responses. One process per test run keeps
// overhead low (~70ms Node startup vs per-fixture invocation).
//
// Op catalog (grouped by TS package):
//
//   @atproto/syntax
//     - normalize_handle      : string → string
//     - is_valid_handle       : string → bool
//     - nsid_is_valid         : string → bool
//     - aturi_components      : string → { authority, collection, rkey, fragment }
//
//   @atproto/common-web
//     - tid_from_time         : { timestamp_us, clockid } → string
//     - tid_from_str          : string → bool (valid)
//     - s32_encode            : number → string
//     - s32_decode            : string → number
//     - grapheme_len          : string → number
//     - get_pds_endpoint      : DidDocument → string|null
//
//   @atproto/crypto
//     - did_key_parse         : string → { jwtAlg, key_hex }
//     - multibase_encode      : { encoding, bytes_hex } → string
//     - multibase_decode      : string → bytes_hex
//
//   @atproto/lexicon
//     - lexicon_validate_record : { lexicons, record_type, record } → { valid, error?, message? }
//
//   @atproto/common (dag-cbor parity — added for #10)
//     - cbor_encode_lexvalue  : LexValueJson → { hex } (raw dag-cbor bytes)
//     - cid_for_lexvalue      : LexValueJson → { cid } (canonical multibase string)
//
//   @atproto/repo (MST parity — added for #26)
//     - mst_root_cid          : { entries: [[key, cid_str], ...] } → { cid }
//                                Builds an MST in TS with the given (key, cid) pairs
//                                inserted in input order, returns the root CID. The
//                                MST is content-addressed so insertion order MUST NOT
//                                affect the result — that property is checked Rust-side.
//
//   @atproto/repo (CAR layout parity — added for #27)
//     - car_write_blocks      : { root: cid_str|null, blocks: [[cid_str, hex_payload], ...] } → { hex }
//                                Writes a CAR file in input block order using TS
//                                `writeCarStream`. Bypasses BlockMap so the test
//                                controls block order exactly — required for
//                                byte-equivalent comparison against Rust's
//                                `blocks_to_car`, since BlockMap iteration order is
//                                an implementation detail and would otherwise
//                                drift between impls.
//
//   @atproto/repo (signed commit parity — added for #28)
//     - commit_signing_bytes  : { did, data: cid_str, rev, prev: cid_str|null } → { hex }
//                                DAG-CBOR encoding of the unsigned commit (the
//                                signing input). Determinism guarantee: this MUST
//                                be byte-equivalent across impls or signatures
//                                produced by one side won't verify on the other.
//     - commit_signed_cid     : { did, data, rev, prev, sig_hex } → { cid }
//                                CID of the full signed commit, with a caller-
//                                supplied signature. ECDSA signatures are
//                                non-deterministic, so this op accepts a fixed
//                                sig from Rust to make CID comparison stable.
//     - commit_verify_sig     : { did, data, rev, prev: cid_str|null, sig_hex, did_key } → { valid }
//                                Cross-impl: Rust signs, TS verifies (or vice
//                                versa). End-to-end check that signing input is
//                                truly identical across impls.
//
//     LexValueJson is a tagged-enum wire format both sides build IPLD
//     from. Avoids coupling the cbor-parity test to the lex-json
//     codec's own correctness. Shape:
//       { t: "null" }
//       { t: "bool", v: true|false }
//       { t: "int", v: <i64-as-number> }    // Range-checked to JS-safe ints upstream
//       { t: "str", v: "..." }
//       { t: "bytes", hex: "deadbeef" }
//       { t: "cid", s: "bafyrei..." }       // multibase
//       { t: "arr", v: [ <LexValueJson>... ] }
//       { t: "map", v: [ [k, <LexValueJson>], ... ] }   // insertion-order entries

import {
  normalizeHandle,
  ensureValidHandle,
  ensureValidNsid,
  AtUri,
} from '@atproto/syntax'
import {
  TID,
  s32encode,
  s32decode,
  graphemeLen,
  getPdsEndpoint,
} from '@atproto/common-web'
import {
  parseDidKey,
  bytesToMultibase,
  multibaseToBytes,
} from '@atproto/crypto'
import { Lexicons } from '@atproto/lexicon'
import { cborEncode, cidForCbor } from '@atproto/common'
import {
  MST,
  MemoryBlockstore,
  writeCarStream,
  verifyCommitSig,
  cidForRecord,
} from '@atproto/repo'
import { CID } from 'multiformats/cid'
import readline from 'node:readline'

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
})

for await (const line of rl) {
  const trimmed = line.trim()
  if (!trimmed) continue
  let req
  try {
    req = JSON.parse(trimmed)
  } catch (e) {
    writeError('ParseRequest', e)
    continue
  }

  try {
    const value = await dispatch(req.op, req.input)
    process.stdout.write(JSON.stringify({ ok: true, value }) + '\n')
  } catch (e) {
    writeError(e?.constructor?.name ?? 'Error', e)
  }
}

async function dispatch(op, input) {
  switch (op) {
    // ── @atproto/syntax ────────────────────────────────────────────
    case 'normalize_handle':
      return normalizeHandle(input)

    case 'is_valid_handle': {
      try {
        ensureValidHandle(input)
        return true
      } catch {
        return false
      }
    }

    case 'nsid_is_valid': {
      try {
        ensureValidNsid(input)
        return true
      } catch {
        return false
      }
    }

    case 'aturi_components': {
      const uri = new AtUri(input)
      return {
        authority: uri.hostname,
        collection: uri.collection || null,
        rkey: uri.rkey || null,
        fragment: uri.hash || null,
      }
    }

    // ── @atproto/common-web ────────────────────────────────────────
    case 'tid_from_time': {
      // The TS `TID.fromTime` takes `timestamp` (microseconds) and a
      // `clockid` (0..=1023). Return the string form.
      const tid = TID.fromTime(input.timestamp_us, input.clockid)
      return tid.toString()
    }

    case 'tid_from_str':
      // `TID.is` for a pure accept/reject; `fromStr` would throw.
      return TID.is(input)

    case 's32_encode':
      // `s32encode` takes a number, returns a base-32 sortable string.
      return s32encode(input)

    case 's32_decode':
      return s32decode(input)

    case 'grapheme_len':
      return graphemeLen(input)

    case 'get_pds_endpoint': {
      // getPdsEndpoint throws on non-DidDocument-shaped input; catch
      // so the Rust side can diff the reject path too.
      return getPdsEndpoint(input) ?? null
    }

    // ── @atproto/crypto ────────────────────────────────────────────
    case 'did_key_parse': {
      // parseDidKey returns `{ jwtAlg, keyBytes }`; return
      // keyBytes as hex so JSON can carry it.
      const parsed = parseDidKey(input)
      return {
        jwtAlg: parsed.jwtAlg,
        key_hex: Buffer.from(parsed.keyBytes).toString('hex'),
      }
    }

    case 'multibase_encode': {
      const bytes = Buffer.from(input.bytes_hex, 'hex')
      return bytesToMultibase(bytes, input.encoding)
    }

    case 'multibase_decode': {
      const bytes = multibaseToBytes(input)
      return Buffer.from(bytes).toString('hex')
    }

    // ── @atproto/lexicon ───────────────────────────────────────────
    case 'lexicon_validate_record': {
      const lex = new Lexicons(input.lexicons)
      try {
        lex.assertValidRecord(input.record_type, input.record)
        return { valid: true }
      } catch (e) {
        return {
          valid: false,
          error: e?.constructor?.name ?? 'Error',
          message: e?.message ?? String(e),
        }
      }
    }

    // ── @atproto/common — dag-cbor parity ──────────────────────────
    case 'cbor_encode_lexvalue': {
      const ipld = lexValueJsonToIpld(input)
      const bytes = cborEncode(ipld)
      return { hex: Buffer.from(bytes).toString('hex') }
    }

    case 'cid_for_lexvalue': {
      const ipld = lexValueJsonToIpld(input)
      const cid = await cidForCbor(ipld)
      return { cid: cid.toString() }
    }

    // ── @atproto/repo — signed commit parity (#28) ───────────────
    case 'commit_signing_bytes': {
      const unsigned = unsignedCommitFromInput(input)
      // Same call signCommit() makes internally before signing —
      // cborEncode returns the canonical DAG-CBOR signing bytes.
      const bytes = cborEncode(unsigned)
      return { hex: Buffer.from(bytes).toString('hex') }
    }

    case 'commit_signed_cid': {
      const unsigned = unsignedCommitFromInput(input)
      if (typeof input?.sig_hex !== 'string') {
        throw new Error(`commit_signed_cid: input.sig_hex must be a hex string`)
      }
      const sig = Buffer.from(input.sig_hex, 'hex')
      const signed = { ...unsigned, sig }
      const cid = await cidForRecord(signed)
      return { cid: cid.toString() }
    }

    case 'commit_verify_sig': {
      const unsigned = unsignedCommitFromInput(input)
      if (typeof input?.sig_hex !== 'string') {
        throw new Error(`commit_verify_sig: input.sig_hex must be a hex string`)
      }
      if (typeof input?.did_key !== 'string') {
        throw new Error(`commit_verify_sig: input.did_key must be a string`)
      }
      const sig = Buffer.from(input.sig_hex, 'hex')
      const valid = await verifyCommitSig({ ...unsigned, sig }, input.did_key)
      return { valid }
    }

    // ── @atproto/repo — CAR layout parity (#27) ──────────────────
    case 'car_write_blocks': {
      const root = input?.root == null ? null : CID.parse(input.root)
      const blocks = input?.blocks
      if (!Array.isArray(blocks)) {
        throw new Error(`car_write_blocks: input.blocks must be an array of [cid, hex] pairs`)
      }
      // Synthesize an async iterable of CarBlocks in input order, so
      // the test (Rust side) controls block order exactly. We bypass
      // BlockMap entirely to keep order under explicit control.
      async function* iter() {
        for (const block of blocks) {
          if (
            !Array.isArray(block) ||
            block.length !== 2 ||
            typeof block[0] !== 'string' ||
            typeof block[1] !== 'string'
          ) {
            throw new Error(`car_write_blocks: each block must be [cid_str, hex_payload]`)
          }
          yield {
            cid: CID.parse(block[0]),
            bytes: Buffer.from(block[1], 'hex'),
          }
        }
      }
      const chunks = []
      for await (const chunk of writeCarStream(root, iter())) {
        chunks.push(chunk)
      }
      const total = chunks.reduce((n, c) => n + c.byteLength, 0)
      const out = new Uint8Array(total)
      let offset = 0
      for (const chunk of chunks) {
        out.set(chunk, offset)
        offset += chunk.byteLength
      }
      return { hex: Buffer.from(out).toString('hex') }
    }

    // ── @atproto/repo — MST parity (#26) ─────────────────────────
    case 'mst_root_cid': {
      const entries = input?.entries
      if (!Array.isArray(entries)) {
        throw new Error(`mst_root_cid: input.entries must be an array of [key, cid] pairs`)
      }
      const blockstore = new MemoryBlockstore()
      let mst = await MST.create(blockstore)
      for (const entry of entries) {
        if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || typeof entry[1] !== 'string') {
          throw new Error(`mst_root_cid: each entry must be [string-key, string-cid]`)
        }
        mst = await mst.add(entry[0], CID.parse(entry[1]))
      }
      const root = await mst.getPointer()
      return { cid: root.toString() }
    }

    default:
      throw new Error(`Unknown op: ${op}`)
  }
}

/// Build a native IPLD value from a LexValueJson record. Fails loudly
/// on unknown shapes — silent coercion would hide test bugs.
function lexValueJsonToIpld(node) {
  if (node === null || typeof node !== 'object' || typeof node.t !== 'string') {
    throw new Error(`LexValueJson: expected tagged object, got ${JSON.stringify(node)}`)
  }
  switch (node.t) {
    case 'null':
      return null
    case 'bool':
      if (typeof node.v !== 'boolean') {
        throw new Error(`LexValueJson bool: v must be boolean, got ${typeof node.v}`)
      }
      return node.v
    case 'int':
      if (typeof node.v !== 'number' || !Number.isInteger(node.v)) {
        throw new Error(`LexValueJson int: v must be integer, got ${node.v}`)
      }
      return node.v
    case 'str':
      if (typeof node.v !== 'string') {
        throw new Error(`LexValueJson str: v must be string`)
      }
      return node.v
    case 'bytes':
      if (typeof node.hex !== 'string') {
        throw new Error(`LexValueJson bytes: hex must be a string`)
      }
      return Buffer.from(node.hex, 'hex')
    case 'cid':
      if (typeof node.s !== 'string') {
        throw new Error(`LexValueJson cid: s must be a multibase string`)
      }
      return CID.parse(node.s)
    case 'arr':
      if (!Array.isArray(node.v)) {
        throw new Error(`LexValueJson arr: v must be an array`)
      }
      return node.v.map(lexValueJsonToIpld)
    case 'map': {
      // dag-cbor maps are JS objects; @atproto/common's cborEncode
      // sorts keys per the dag-cbor spec.
      if (!Array.isArray(node.v)) {
        throw new Error(`LexValueJson map: v must be an array of [k, v] entries`)
      }
      const obj = {}
      for (const entry of node.v) {
        if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') {
          throw new Error(`LexValueJson map entry: must be [string, LexValueJson]`)
        }
        if (Object.prototype.hasOwnProperty.call(obj, entry[0])) {
          throw new Error(`LexValueJson map: duplicate key ${entry[0]}`)
        }
        obj[entry[0]] = lexValueJsonToIpld(entry[1])
      }
      return obj
    }
    default:
      throw new Error(`LexValueJson: unknown tag ${node.t}`)
  }
}

/// Validate and lift a commit input { did, data, rev, prev } into a
/// shape suitable for cborEncode / cidForRecord / verifyCommitSig.
/// Strict — fails loudly on missing/wrong-typed fields.
function unsignedCommitFromInput(input) {
  if (input === null || typeof input !== 'object') {
    throw new Error(`commit input: expected object, got ${typeof input}`)
  }
  const { did, data, rev, prev } = input
  if (typeof did !== 'string') {
    throw new Error(`commit input: did must be a string`)
  }
  if (typeof data !== 'string') {
    throw new Error(`commit input: data must be a CID string`)
  }
  if (typeof rev !== 'string') {
    throw new Error(`commit input: rev must be a TID string`)
  }
  if (prev !== null && typeof prev !== 'string') {
    throw new Error(`commit input: prev must be a CID string or null`)
  }
  return {
    did,
    version: 3,
    data: CID.parse(data),
    rev,
    prev: prev === null ? null : CID.parse(prev),
  }
}

function writeError(kind, e) {
  const message = e instanceof Error ? e.message : String(e)
  process.stdout.write(
    JSON.stringify({ ok: false, error: kind, message }) + '\n',
  )
}
