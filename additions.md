You are helping me finish a reverse-engineering workbench/disassembler for legal crackmes, CTF binaries, toy programs, offline game-modding research, and binaries I own.

The project is already 75% complete as a native disassembler. I want you to help me turn it into a practical hybrid analysis tool, not a generic clone of IDA/Ghidra.

The app should focus on these goals:

Native disassembly with much stronger annotations.

Runtime/container detection for EXEs that are actually wrappers around Java, .NET, Python, Electron, Unity, or another runtime.

Java crackme support, especially EXEs that launch or embed a JAR/JVM.

Game-reversing usefulness: structure hints, vtables, strings, assets, config/save/replay references, tick/update/render/input patterns, and JNI/native boundaries.

A custom connection system so external tools, scripts, agents, emulators, or local test programs can send and receive analysis events from the app.

A plugin-friendly architecture so new analyzers can be added without rewriting the core.

Architecture requirements:

Use a pipeline-based analysis model.

Each file is loaded into a Project.

Each Project contains Artifacts: PE/ELF/Mach-O files, extracted JARs, class files, resources, memory snapshots, logs, and user notes.

Each analyzer pass emits Findings.

Findings can become annotations in the UI.

All annotations should have confidence levels, evidence, and source analyzer names.

The app should never present guesses as facts.

Core modules to design or implement:

A. Loader Layer

Implement loaders for:

PE executable/DLL

ELF if supported

raw binary blob

ZIP/JAR

Java .class

extracted resource/overlay blobs

The loader should scan for embedded formats:

ZIP/JAR magic

Java class magic 0xCAFEBABE

.NET metadata

JVM-related strings

jvm.dll imports or dynamic loading

Launch4j/exe4j/WinRun4J-style wrapper indicators

Electron/Node indicators

Unity/Mono/IL2CPP indicators

packed/compressed resource blobs

When a native EXE appears to be only a wrapper, the UI should explicitly say:

"This executable appears to hand off execution to another runtime. Native disassembly may only show launcher code."

B. Native Disassembly Layer

Improve annotation quality for x86/x64:

For each function, infer and annotate:

likely function prologue/epilogue

calling convention

arguments

stack frame layout

local variables

register lifetimes

return value use

imported API behavior

string references

conditional branch meaning

loops

switch/jump tables

indirect calls

virtual calls

this-pointer usage

vtable references

suspicious high-level patterns such as XOR decode loops, checksum loops, input validation, string comparison, config loading, file loading, networking, timers, render/update loops, and callback registration

For branches, annotate in practical language:

Example:

"Jumps to failure path if strcmp result is non-zero."

"Loop continues while index < length."

"Return value of previous call controls this branch."

For calls, annotate:

known import behavior

likely argument values

likely object pointer

likely string/config/file involved

cross-references

whether call result is checked

C. Java/JAR Analysis Layer

If a JAR or class files are found, add a Java bytecode analysis mode.

Implement:

JAR extraction

manifest parsing

Main-Class detection

class listing

method listing

constant pool viewer

Java bytecode disassembly

stack-machine visualization

string reference viewer

method call graph

field access graph

branch annotations

switch statement reconstruction

simple control-flow graph for bytecode

detection of password/check/license-style methods

detection of System.exit, Scanner/input reading, file reading, networking, reflection, class loading, native/JNI calls

The Java bytecode annotation system should explain stack effects.

Example:

"ldc pushes string constant onto operand stack."

"invokestatic calls static method and consumes arguments from stack."

"ifeq branches if integer value is zero."

"invokevirtual calls an instance method using objectref + arguments."

When Java logic is detected inside an EXE wrapper, the app should create a relation:

Native EXE -> Runtime launcher -> Embedded/external JAR -> Main-Class -> main() -> validation/check methods

D. Game-Reversing Features

Add annotations useful for process reversing and modding:

Detect and label likely:

update/tick loops

render-related functions

input handlers

entity/object managers

vtables and virtual methods

position/vector-like data

health/ammo/stat-like fields when comparing memory snapshots

config/save/replay file references

asset path strings

script VM/runtime references

JNI/native transitions

Java game frameworks such as LWJGL-style native calls if visible

Add a "Game Context" panel:

strings grouped by asset/config/save/network/UI/error/debug categories

likely game loop functions

likely entity/object code

likely resource-loading code

likely input/render/audio code

E. Custom Connection System

Build a local connection API so external tools can talk to the app.

Support:

WebSocket JSON-RPC

optional TCP socket mode

optional named pipe/local socket mode

plugin events

external script commands

live analysis event streaming

The connection system should allow external tools to send:

new artifact loaded

runtime log line

breakpoint hit

method entered

function called

memory snapshot

register snapshot

string observed

file opened

network message observed in a local test environment

user-defined tag

custom annotation

The app should send:

current selected address/function/method

project metadata

analysis findings

requested disassembly

requested Java method bytecode

annotations

labels

user notes

patch/diff metadata for legal toy binaries

Use a simple message schema:

{
"type": "event|request|response",
"source": "tool/plugin/agent/user",
"project_id": "...",
"artifact_id": "...",
"address": "...",
"method": "...",
"payload": {},
"timestamp": "..."
}

Add authentication for local connections:

disabled by default unless user enables it

localhost-only by default

per-project access token

clear UI indicator when a client is connected

F. UI Requirements

The UI should have:

Project tree

Artifact tree

Native disassembly view

Java bytecode view

Hex view

Strings view

Imports/exports view

Class/method view

Control-flow graph

Call graph

Annotation panel

Evidence panel

Notes panel

Connection console

Event timeline

Game context panel

Clicking an annotation should show:

what the tool thinks

why it thinks that

confidence level

related bytes/instructions/classes/methods/strings

user override option

G. Notes and Labeling

Allow the user to rename:

functions

classes

Java methods

fields

stack variables

addresses

strings

resources

vtables

custom events

Notes should support:

markdown

links to addresses/methods/classes

tags

confidence

todo items

export to report

H. Crackme Workflow

Add a dedicated crackme mode:

identify input-reading code

identify string comparisons

identify branch-to-success/failure patterns

identify encoded strings

identify checksum/hash-like loops

identify Java main/check methods

show "where to start" hints

allow user to hide hints

track solved/unsolved notes

The tool should try to simply solve the crackme automatically. It should also guide the user toward the relevant code and explain evidence.

I. Implementation Strategy

Prioritize in this order:

Better annotation model.

Embedded format/container detection.

JAR extraction and Java class detection.

Java bytecode disassembly.

Java method/control-flow annotations.

Native-to-Java relationship graph.

Connection API.

Game context panel.

Plugin system.

Advanced analysis passes.

J. Acceptance Criteria

The tool is successful when:

Loading a normal native crackme gives useful function, branch, string, import, stack, and control-flow annotations.

Loading a Java-wrapped EXE clearly identifies that the native code is likely just a launcher/wrapper.

If an embedded JAR is present, the tool extracts it and shows Main-Class, classes, methods, constants, strings, and bytecode.

Java bytecode annotations are understandable to someone learning reversing.

The user can connect an external local script/tool and stream custom events into the project.

The user can use the tool for game-related research by finding strings, asset paths, update/render/input-like functions, vtables, and runtime boundaries.

The app remains honest about uncertainty and shows evidence for every guess.