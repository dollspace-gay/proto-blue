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

function writeError(kind, e) {
  const message = e instanceof Error ? e.message : String(e)
  process.stdout.write(
    JSON.stringify({ ok: false, error: kind, message }) + '\n',
  )
}
