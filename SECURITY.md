# Security

The scorecard probes the site you name the way secret-hunting scanners do: GET requests for paths like `/.env`, a HEAD, and an empty POST and PUT to `/` that create nothing. If you find a way it could change, harm or leak data from a site it audits, or from the machine that runs it, please report it privately to privacy@geeksinthewoods.com rather than opening a public issue. We'll reply within a week.

What it does to protect the machine that runs it:
- It requests only the domain you name and its www or bare twin, and never follows a redirect anywhere else. `--base` sends those requests to the address you chose instead.
- Every request goes through one function (`request()` in `src/http.mjs`) on `node:http(s)`. It asks for gzip or deflate and decodes those itself; a body in any other encoding, such as Brotli, is refused, so a site can't reach a decoder bug. `fetch` isn't used: it decodes Brotli even when the request didn't ask for it.
- Every body is capped at 256 KB, before and after decoding, and every request at 10 seconds, so a probe answered with a zip bomb, an endless stream or a tarpit can't exhaust memory or hang the run.
- It needs Node 26.12.1 or later, and you should run the current security release: TLS hostname checks and the decoders are Node's.

What it does to protect the sites it audits: about 20 requests plus up to 10 sitemap pages, at most four in flight, with a user agent that names the tool and this repo.

Run the scorecard only against sites you own or have permission to test. Its requests look like an attack to a firewall.
