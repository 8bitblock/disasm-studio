# Multi-document workspace ownership

`Core/DocumentContext` establishes the lifetime boundary needed for static
multi-document analysis. Each context owns one `BinaryFile`, `ProjectState`,
engine/architecture selection, UI decoder, `AnalysisService`, `CodeExportService`,
immutable-result cache, Java/runtime/firmware evidence, and address/view
navigation history. Address validity and FILE/LIVE identity are explicit, so a
current or historical location at VA zero is preserved without conflating file
and runtime address spaces.

The normal `AnalysisService` constructor retains its automatic one-to-eight
worker policy. A document deliberately requests one worker, so eight open
documents create at most eight document-analysis workers rather than eight full
pools (up to sixty-four threads). Each document still owns its service and can
cancel/join it independently.

`DocumentManager` keeps insertion order, assigns non-reused monotone IDs, selects
new documents, and caps the collection at eight. Closing the active document
selects its successor, or its predecessor when the last item closes. Closing an
inactive document leaves selection unchanged. Its production `openStaged` path
compares pristine content hashes before adding a context; reopening an already
open image activates the existing owner rather than admitting two writers for
the same hash-keyed sidecar.

Image loading is staged. The caller can install a prepared `BinaryFile`, exact
`ProjectState`, engine/architecture, and runtime metadata in one transaction.
Decoder rejection (including a throwing factory) leaves the current image,
project, decoder, metadata, and workers untouched. Successful replacement, patch
mutation, clear, close, manager removal, and manager clear all pass through
blocking cancellation barriers for both per-document services before
`BinaryFile` storage can be changed or freed. The focused regression deliberately
parks an analysis decoder on image bytes and verifies that manager removal waits
while those bytes remain alive.

Persistence is injected through `DocumentSaveCallback`, keeping this ownership
layer independent of the Project filesystem implementation. A revision-bearing
dirty document is stamped into an immutable save snapshot (including an explicit
raw entry at VA zero) before the callback runs. Failed or throwing saves leave the
document open, dirty, and fully intact. Replacement, activation, close, and clear
therefore cannot silently discard analyst state. `DocumentManager` also accepts a
prepare-transition callback so the future UI host can mirror tab-owned edits
before the durable flush; rejection leaves `activeId` and the collection
unchanged. Application shutdown must call `clear` and surface failure before the
manager destructor; forced destruction can guarantee memory safety but cannot
keep an application alive to retry a failed external store.

`AppContext` constructs one active scratch document in a private
`DocumentManager`; its static binary, project, decoder, analysis, export,
engine/architecture, and runtime-metadata accessors forward to the active owner.
There is no duplicate singleton ownership. File, raw, and live-module opens stage
the complete image/project/metadata transaction and queue the topology change.
The queue is committed only after every tab and modal has returned for the frame,
so no render call can observe `activeId` changing underneath a borrowed reference.
A second topology request in the same frame is visibly rejected. Save rejection
leaves the outgoing document active and intact.

The fixed single-window UI exposes the managed collection as a top document strip.
`BinaryViewHostTab` retains one `BinaryViewTab` per stable `DocumentId`; only the
active child renders or advances its bounded investigation snapshot. Child ImGui
state is scoped by document ID and image generation, navigation/view/cache state is
retained while inactive, and host-level investigation generations cannot collide
across documents. Deactivation mirrors analyst state before the exact save ticket is
flushed. Close joins both Core workers and the child symbol worker before releasing
binary storage. Closing the last document atomically creates a replacement scratch,
and the initial scratch is retired after the first successful open.

Static result owners in Sig Scanner, Binary Tech, Cortex, semantic transfer, and
Binary View handoffs include document ID, image generation, pristine hash, and image
revision. A mismatched result is cleared or rejected before navigation. The global
module analyzer owns a separate service and routes results by debugger epoch/module
base; changing documents cannot cancel it or make it borrow document storage. An
app-level debugger session-generation gate retires module images even if every
retained Binary View missed the detach edge.

Image writes and decoder changes still use document gateways, so workers are
quiesced before mutation. Debounced Project saves acknowledge the exact originating
document/revision ticket, and a synchronous transition waits for any older async
snapshot before committing. The Win32 debugger, JDWP client, Prism collector,
live-memory scanner, and live-module registry intentionally remain app-global and
are not detached by static document switches.
