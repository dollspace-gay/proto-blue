#!/usr/bin/env node
//
// JSON-over-stdin adapter for @atproto/syntax.
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
// overhead low (~50ms Node startup vs per-fixture invocation).
//
// Ops:
// - `normalize_handle`: returns the normalized handle string without
//   running validation. Pure transform.
// - `is_valid_handle`: runs ensureValidHandle and returns a boolean.
// - `nsid_is_valid`: runs ensureValidNsid; returns boolean.
// - `aturi_components`: parses an AT-URI string into
//   `{authority, collection, rkey, fragment}`.

import {
  normalizeHandle,
  ensureValidHandle,
  ensureValidNsid,
  AtUri,
} from '@atproto/syntax'
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
    const value = dispatch(req.op, req.input)
    process.stdout.write(JSON.stringify({ ok: true, value }) + '\n')
  } catch (e) {
    writeError(e?.constructor?.name ?? 'Error', e)
  }
}

function dispatch(op, input) {
  switch (op) {
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
      // Parsing may throw on malformed input; surface that as
      // `{ok: false}` so the Rust side can compare accept/reject
      // decisions symmetrically with its own parser.
      const uri = new AtUri(input)
      return {
        authority: uri.hostname,
        collection: uri.collection || null,
        rkey: uri.rkey || null,
        fragment: uri.hash || null,
      }
    }

    default:
      throw new Error(`Unknown op: ${op}`)
  }
}

function writeError(kind, e) {
  const message = e instanceof Error ? e.message : String(e)
  process.stdout.write(
    JSON.stringify({ ok: false, error: kind, message }) + '\n',
  )
}
