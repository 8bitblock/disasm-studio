# Address Inspector Core model

`Core/AddressInspector` projects one explicit static VA into the identities used
by the investigation UI. Each numeric coordinate carries its own validity bit,
so VA/RVA/file offset/runtime address zero is never treated as “missing.”

The helper consumes immutable `BinaryFile`, project, xref, classification, and
optional live-module snapshots. It reports file offset, RVA, verified ASLR
translation, FILE/LIVE identity confidence and evidence, incoming xref kinds,
derived versus authoritative analyst classification, function/type overrides,
names/comments, and every overlapping patch in application order with the
later-wins byte marked explicitly.

It is deliberately side-effect free: there are no debugger reads, filesystem
accesses, decoder calls, or implicit content hashing. Callers that already know
the pristine file hash may supply it for high-confidence live identity; path or
filename matches are visibly lower-confidence and mismatches fail closed.
