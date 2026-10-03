# Protocol and format contract

The original URI is retained in SQLite aliases and in raw subscriptions. Identity v2 uses structured fields, normalized host/port, all query parameters, and VMess metadata. Presentation remarks do not affect identity. Xray short custom IDs map to UUIDv5 with the nil namespace, matching the pinned core. Unknown connection parameters are retained and cause an explicit capability omission instead of being silently dropped.

| Protocol | Validation adapter | Clash/mihomo | sing-box 1.14 profile |
|---|---|---|---|
| VLESS, VMess, Trojan | Xray; sing-box fallback | Yes, supported transports | Yes, supported transports |
| Shadowsocks, SOCKS, HTTP/HTTPS | Xray; sing-box fallback | Yes | Yes |
| Hysteria, Hysteria2/hy2, TUIC | sing-box | Yes | Yes |
| SSR | mihomo | Yes | Explicit omission |
| WireGuard/wg | sing-box endpoint | Yes | Endpoint |
| Juicity | No verified client adapter available | Explicit omission | Explicit omission |

Xray supports raw/TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP in the new renderer. Formats that lack a matching transport omit that connection and identify its stable hash and reason in `output/conversion_report.json`. Reality, TLS, passwords, gRPC services, WebSocket paths/queries and supported plugin settings are preserved. ECH, fragmentation, unknown future parameters and unsupported fingerprint profiles are reported rather than approximated.

`allowInsecure` is removed in the pinned Xray release. The supervisor selects sing-box for connections that request it; it does not silently enable verification or downgrade TLS. The controlled Xray server fixture allows only its ephemeral loopback target port through `finalRules`; production workers have no direct fallback route.

Portable client defaults use loopback mixed listeners. TUN remains available in the source templates and is opt-in with `OPENRAY_CLIENT_TUN=1`; enabling automatic system routing needs an appropriate platform and privileges. Raw subscriptions retain the existing names/paths and all parseable legacy connections until validation applies the health policy. Malformed concatenated URIs, broken encodings and invalid authentication fields are quarantined at import, with counts in the migration report.

Client exports are schema checked with the pinned actual clients before automatic pipeline installation/publication. A schema-valid export is not proof that a remote proxy is currently reachable. Controlled end-to-end tests cover VLESS/VMess/Trojan, SS/SOCKS/HTTP/HTTPS, WebSocket including path queries, gRPC, Reality, both Hysteria versions, TUIC and userspace WireGuard. Actual client schema tests also cover SSR and dual-stack WireGuard with reserved bytes. SSR still needs a representative controlled server for end-to-end acceptance; schema validity alone does not prove interoperability.
