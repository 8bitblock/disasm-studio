// In-process fixture for the built-in helper's bounded state machines. It does
// not install hooks, load a game, inject, attach, or execute any target code.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "../src/GameMakerHelper/GameMakerHelper.cpp"
#include <cstdio>
#include <memory>

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL %d: %s\n", __LINE__, #x); ++failures; } } while (0)

int main() {
    void* memory = VirtualAlloc(nullptr, sizeof(State), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return 2;
    gState = new (memory) State{};
    gDsGmlEnabled = 1;
    constexpr uint64_t object = 0x12345000;
    const uint64_t initial = instanceToken(object);
    CHECK(initial && instanceToken(object) == initial);
    auto* life = lifetimeSlot(object, false);
    CHECK(life && life->instanceId == initial && life->sequence && !(life->sequence & 1));
    GateRegisters registers{};
    registers.rcx = object;
    DsGmlOnInstanceDestructor(&registers);
    CHECK(!instanceToken(object)); // observed destructor must never be treated as a preexisting object
    CHECK(!life->instanceId && !(life->sequence & 1));
    DsGmlOnInstanceConstructor(&registers);
    const uint64_t replacement = instanceToken(object);
    CHECK(replacement && replacement != initial);
    CHECK(instanceToken(object) == replacement);
    // No raw instance number participates in lifetime identity: cloned/restored
    // IDs may change without reallocating this object.
    const uint64_t colliding = object + uint64_t(kGmlMaxInstanceLifetimes) * 16;
    const uint64_t collisionToken = instanceToken(colliding);
    CHECK(collisionToken && collisionToken != replacement && instanceToken(object) == replacement);

    ThreadTrack thread;
    auto* context = contextTrack(thread, 0x77770000, true);
    GmlRunnerContextView view;
    view.operandBufferEnd = 0x10000;
    view.anchor = 0xff00;
    view.logicalDepth = 1;
    CHECK(updateTrack(*context, view));
    const uint64_t calledFrame = context->frames[1];
    view.logicalDepth = 0;
    CHECK(updateTrack(*context, view) && context->frames[1] == 0);
    view.logicalDepth = 1;
    CHECK(updateTrack(*context, view) && context->frames[1] && context->frames[1] != calledFrame);
    view.logicalDepth = kGmlMaxFrames;
    CHECK(!updateTrack(*context, view));
    // Model the verified dispatch-visible depth/anchor transitions through a
    // recursive call, a loop, and an exception that unwinds several GML frames.
    *context={};context->frames[0]=nextId();
    view.logicalDepth=0;view.anchor=0xff00;CHECK(updateTrack(*context,view));
    const auto rootFrame=context->frames[0];
    uint64_t recursiveFrames[4]{};
    for(uint32_t depth=1;depth<=4;++depth){view.logicalDepth=depth;view.anchor-=0x78;
        CHECK(updateTrack(*context,view));recursiveFrames[depth-1]=context->frames[depth];
        CHECK(recursiveFrames[depth-1] && recursiveFrames[depth-1]!=rootFrame);
        if(depth>1)CHECK(recursiveFrames[depth-1]!=recursiveFrames[depth-2]);}
    CHECK(updateTrack(*context,view) && context->frames[4]==recursiveFrames[3]); // loop/revisit
    view.logicalDepth=2;view.anchor=0xff00-2*0x78;
    CHECK(updateTrack(*context,view) && !context->frames[3] && !context->frames[4]);
    CHECK(context->frames[2]==recursiveFrames[1]); // surviving recursive caller
    view.logicalDepth=0;view.anchor=0xff00;
    CHECK(updateTrack(*context,view) && context->frames[0]==rootFrame);
    for(uint32_t depth=1;depth<=4;++depth)CHECK(!context->frames[depth]);
    view.logicalDepth=1;view.anchor-=0x78;CHECK(updateTrack(*context,view));
    CHECK(context->frames[1]!=recursiveFrames[0]); // recreated frame at the same stack anchor
    const auto replaced=context->frames[1];view.anchor-=0x40;
    CHECK(updateTrack(*context,view) && context->frames[1]!=replaced); // same-depth replaced anchor
    CHECK(privateExceptionFilter(kGmlStopExceptionCode)==EXCEPTION_EXECUTE_HANDLER);
    CHECK(privateExceptionFilter(EXCEPTION_BREAKPOINT)==EXCEPTION_CONTINUE_SEARCH);
    CHECK(privateExceptionFilter(EXCEPTION_ACCESS_VIOLATION)==EXCEPTION_CONTINUE_SEARCH);

    auto mailbox = std::make_unique<GmlHelperMailbox>();
    gState->mailbox = mailbox.get();
    gState->nonce = 11; gState->archive = 22;
    gState->codeCount = 1;
    gState->codes[0] = {3, kGmlNoCodeIndex, 0, 32};
    mailbox->control.nonce = 11;
    mailbox->control.command = GmlControlCommand::Continue;
    mailbox->control.commandSequence = 1;
    mailbox->control.breakpointCount = 1;
    mailbox->control.breakpoints[0] = {22, 3, 12};
    CHECK(refreshControls() && gState->sequence == 1 && !gDsGmlFastAlwaysSlow);
    const uint32_t bit = DsGmlBreakpointBloomBit(3, 12);
    CHECK((gDsGmlBreakpointBloom[bit >> 3] & (1u << (bit & 7))) != 0);
    CHECK(breakpointAt({22, 345, 12, 3})); // root target admits the matching child
    CHECK(!breakpointAt({22, 345, 16, 3}));
    CHECK(!breakpointAt({22, 345, 13, 3}));
    CHECK(!breakpointAt({22, 345, 12, 4}));
    mailbox->control.nonce = 12; mailbox->control.commandSequence = 2;
    CHECK(!refreshControls() && gState->sequence == 1);
    mailbox->control.nonce = 11; mailbox->control.selectedObjectIndex = 1; mailbox->control.selectedInstanceId = 2;
    CHECK(!refreshControls() && gState->sequence == 1);
    mailbox->control.selectedObjectIndex = kGmlNoCodeIndex; mailbox->control.selectedInstanceId = 0;
    mailbox->control.command = GmlControlCommand::Disable;
    CHECK(refreshControls() && gState->sequence == 2 && !gDsGmlEnabled); // cleanup permits zero expectedStop

    // A callback still inside a gate, a stale command owner, or an armed helper
    // must refuse unload. Only refusal paths run here: a successful shutdown
    // deliberately exits its caller thread and unloads the production module.
    gDsGmlActiveGates = 1;
    CHECK(DsGmlShutdown(nullptr) == ERROR_BUSY && gState);
    gDsGmlActiveGates = 0;
    mailbox->control.nonce = 12;
    CHECK(DsGmlShutdown(nullptr) == ERROR_BUSY && gState);
    mailbox->control.nonce = 11;
    mailbox->control.command = GmlControlCommand::Continue;
    CHECK(DsGmlShutdown(nullptr) == ERROR_BUSY && gState);
    mailbox->control.command = GmlControlCommand::Disable;

    // Reclaim retired hash slots without conflating a still-live collision.
    publishLifetime(*lifetimeSlot(object, false), object, 0);
    const uint64_t another = colliding + uint64_t(kGmlMaxInstanceLifetimes) * 16;
    CHECK(instanceToken(another) && instanceToken(colliding) == collisionToken);
    freeState(gState);
    memory = VirtualAlloc(nullptr, sizeof(State), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return 2;
    gState = new (memory) State{};
    for (uint32_t i = 0; i < kGmlMaxInstanceLifetimes; ++i)
        CHECK(instanceToken(0x100000 + uint64_t(i) * 16) != 0);
    CHECK(!instanceToken(0x80000000));
    CHECK(!gState->lifetimesComplete);
    for (const auto& slot : gState->lifetimes) CHECK(!slot.instanceId && !(slot.sequence & 1));
    freeState(gState); gState = nullptr;
    CHECK(DsGmlShutdown(nullptr) == ERROR_INVALID_STATE);
    // Bootstrap must work with a small inherited stack reserve. This catches
    // accidental full init/code-map or mailbox automatic arrays in the entry.
    auto bootstrap = std::make_unique<GmlHelperInitConfig>();
    bootstrap->magic = 0;
    HANDLE init = CreateThread(nullptr, 64 * 1024, DsGmlInitialize, bootstrap.get(), STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    CHECK(init != nullptr);
    if (init) {
        CHECK(WaitForSingleObject(init, 10000) == WAIT_OBJECT_0);
        DWORD code = 0; CHECK(GetExitCodeThread(init, &code) && code == ERROR_INVALID_PARAMETER);
        CHECK(bootstrap->status == GmlHelperInitStatus::InvalidConfig);
        CloseHandle(init);
    }
    bootstrap = std::make_unique<GmlHelperInitConfig>();
    bootstrap->nonce = 1; bootstrap->pid = GetCurrentProcessId();
    bootstrap->sessionGeneration = 1; bootstrap->helperGeneration = 1;
    bootstrap->archiveHash = 1; bootstrap->mailboxAddress = 1;
    bootstrap->hostProcessHandle = 1; bootstrap->codeCount = 1;
    gInitializing = 1;
    CHECK(DsGmlInitialize(bootstrap.get()) == ERROR_ALREADY_EXISTS);
    CHECK(bootstrap->status == GmlHelperInitStatus::AlreadyInitialized);
    gInitializing = 0;
    std::printf("gamemaker_helper_state_test: %s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
