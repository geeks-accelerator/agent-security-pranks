// The audit's one HTTP request, on node:http(s). Internal: the package exports only audit.mjs.
//
// Not fetch(): fetch decodes a Brotli body even when the request didn't ask for one, so a
// hostile site could hand any body to the Brotli decoder. node:http decodes nothing; this
// decodes gzip and deflate and refuses the rest. Every body is capped, before and after
// decoding, so a probe answered with a zip bomb or an endless stream can't exhaust memory (X1).

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { gunzipSync, inflateSync, inflateRawSync } from 'node:zlib';

export const TIMEOUT_MS = 10000;
export const MAX_BYTES = 256 * 1024;

/**
 * One request, no redirects followed. Headers default to `accept: *\/*` and
 * `accept-encoding: gzip, deflate`.
 * Resolves, never rejects: { status, headers (a Headers object), text, ms, error?, tooBig?, slow? }.
 * status is 0 when nothing answered. tooBig: the body passed maxBytes (raw or decoded) and
 * reading stopped. slow: the headers came but the body didn't finish within timeoutMs.
 */
export function request(url, { method = 'GET', headers = {}, body, userAgent, timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  const target = new URL(url);
  const send = target.protocol === 'http:' ? httpRequest : httpsRequest;
  const all = { 'user-agent': userAgent, accept: '*/*', 'accept-encoding': 'gzip, deflate', ...headers };
  if (body !== undefined) all['content-length'] = Buffer.byteLength(body);
  const sent = Object.fromEntries(Object.entries(all).filter(([, v]) => v !== null && v !== undefined));
  const started = Date.now();
  const none = (error) => ({ status: 0, headers: new Headers(), text: '', ms: Date.now() - started, error });
  return new Promise((resolve) => {
    let answered = null; // the response, once headers arrive
    let settled = false;
    const done = (out) => { if (!settled) { settled = true; clearTimeout(timer); resolve(out); } };
    const headersOf = (res) => new Headers(Object.entries(res.headers).flatMap(([k, v]) => [].concat(v).map((x) => [k, String(x)])));
    const req = send(target, { method, headers: sent }, (res) => {
      answered = res;
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) {
          done({ status: res.statusCode, headers: headersOf(res), text: '', ms: Date.now() - started, tooBig: true, error: `body over ${Math.round(maxBytes / 1024)} KB` });
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('error', (e) => done(none(e.message)));
      res.on('end', () => {
        const hdrs = headersOf(res);
        const raw = Buffer.concat(chunks);
        const encoding = (hdrs.get('content-encoding') ?? 'identity').trim().toLowerCase();
        const out = { status: res.statusCode, headers: hdrs, text: '', ms: Date.now() - started };
        const opts = { maxOutputLength: maxBytes };
        try {
          if (encoding === 'identity' || encoding === '') out.text = raw.toString('utf8');
          else if (encoding === 'gzip' || encoding === 'x-gzip') out.text = gunzipSync(raw, opts).toString('utf8');
          else if (encoding === 'deflate') { try { out.text = inflateSync(raw, opts).toString('utf8'); } catch (e) { if (e.code === 'ERR_BUFFER_TOO_LARGE') throw e; out.text = inflateRawSync(raw, opts).toString('utf8'); } } // zlib-wrapped, or raw as some servers send it
          else out.error = `refused: ${encoding} body`;
        } catch (e) {
          if (e.code === 'ERR_BUFFER_TOO_LARGE' || /larger than/i.test(e.message)) { out.tooBig = true; out.error = `${encoding} body decodes to over ${Math.round(maxBytes / 1024)} KB`; }
          else out.error = `undecodable ${encoding} body: ${e.message}`;
        }
        done(out);
      });
    });
    const timer = setTimeout(() => {
      if (answered) done({ status: answered.statusCode, headers: headersOf(answered), text: '', ms: Date.now() - started, slow: true, error: `body still arriving after ${timeoutMs / 1000} seconds` });
      else done(none(`no answer in ${timeoutMs / 1000} seconds`));
      req.destroy();
    }, timeoutMs);
    req.on('error', (e) => done(none(e.message)));
    req.end(body);
  });
}
