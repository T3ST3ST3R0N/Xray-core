# SS2022 UDP session and return-path guarantees

This change ports the relevant guarantees from earlier downstream
`sing-shadowsocks v0.2.7` lifecycle and rebinding repairs to the native SS2022
implementation. It does not restore the removed dependency.

## Why a native port is needed

The native implementation already moves replies to a client's changed UDP
connection after successful packet decoding. However, an authenticated delayed
packet arriving on the previous connection can move replies back again. Packet
arrival order is not necessarily packet-ID order. Concurrent packets can also
race during cipher initialization and between the separate replay check and
insertion operations.

The receive path must satisfy all of these rules:

- Initialize and use the session receive cipher under synchronization.
- Authenticate and validate a packet before accepting its replay ID. Concurrent
  copies of one packet must produce at most one successful acceptance.
- Move the reply connection only when a completely validated packet has a higher
  packet ID than the connection's current high-water mark. A valid reordered
  lower-ID packet can still carry data without redirecting replies.
- Retain the authenticated session object through dispatch and reply encoding.
  A reused numeric session ID must not join two session generations, and a late
  timeout from an old object must not delete its replacement.
- Release receive-validation locks before routing or writing packet payloads.

These guarantees cover single-user AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305,
and multi-user AES-128-GCM and AES-256-GCM. A relay cannot authenticate the inner
payload and retains its existing connection-update policy; it shares the session
lifetime protections.

## Existing fixes that are not duplicated

The native implementation supersedes the old sing-based paths removed by
[upstream #6831](https://github.com/XTLS/Xray-core/pull/6831) and refined by
[#6866](https://github.com/XTLS/Xray-core/pull/6866). The old invalid-destination
backport of [#6162](https://github.com/XTLS/Xray-core/pull/6162) therefore is not
reapplied. The Linux inbound custom-socket-option correction from
[#6568](https://github.com/XTLS/Xray-core/pull/6568) is already in the history.

Supervisor stderr forwarding and configuration-only receive-buffer tuning
belong to the embedding application, not Xray-core. They are outside this port.
This is a correctness change, with no claimed WAN performance improvement.

## Separate lifetime concern

Source review also found that `EnsureLink` derives its routing context from the
first source-tuple worker. That worker can cancel its context when its tuple
expires, even if the authenticated return path subsequently moved. This coupling
exists in the base implementation and is unchanged here. Its end-to-end effect
has not been reproduced in this port's tests; it needs a separate worker-lifetime
regression before changing cancellation semantics. This port must not be described
as proving that every possible reconnect or NAT-lifetime failure is resolved.

## Maintaining the fix

Keep future Xray-core changes in `T3ST3ST3R0N/Xray-core`, targeting `dev`, and
check existing branches and PRs before introducing another patch. The regression
tests live beside the native implementation and run under the race detector in
the normal test workflow and the scheduled upstream-merge check.

Run locally with the Go version selected by `go.mod`:

```sh
go test ./proxy/shadowsocks_2022
go test -race -count=10 -timeout 10m ./proxy/shadowsocks_2022
go run ./infra/vformat/main.go -mode check -pwd ./
go build ./...
```

An embedding application must explicitly select and validate a release containing
this change. Opening or merging this PR does not replace a deployed runtime or
retarget an existing pinned build profile.

## Validation of the port

Compared with `dev` commit `a9e521b22ee7b3300b2f5e45ca6535d199b767c3`, using
Linux amd64 and Go 1.27.0:

| Check | Unmodified base | Native port |
| --- | --- | --- |
| Authenticated move followed by delayed lower-ID packet | Replies move back to old connection in all five cipher/user-mode cases | Replies stay on new connection |
| Concurrent copies of the first packet | Race detector reports cipher/user access; duplicate AES packets sometimes accepted 2–3 times | One acceptance; race detector passes |
| Repeated AES payload decode | Second decode succeeds | Replay rejected |
| Old session cleanup and late response after ID reuse | New regressions added for this port | Replacement retained; response uses original cryptographic generation |
| Closing while routing is blocked | New regression added for this port | Returned link interrupted; session not resurrected |
| Return-path update allocations | Not measured | Zero allocations in regression test |

The before/after controls ran the source-compatible rebinding, concurrent receive
and direct AES replay tests against an untouched archive of the base commit;
the base failures are runtime assertions and race reports, not compile failures.
The full package passes `go test -race -count=10`. Related inbound-worker, UDP
transport and activity-timer package tests, `go build ./...`, and the project
formatter also pass. Tests use real packet encryption/decoding with synthetic
connections and dispatchers; they do not measure a production or WAN path.
