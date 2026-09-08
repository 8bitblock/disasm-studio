// Actual decoder and listing renderer: scalar values preserve the address
// domain and existing comments, and cached observations cannot cross sessions.
static void checkMemoryValueHints(const std::string& path) {
    Fixture f(path);
    constexpr uint64_t dataAddress = 0x12340;
    const uint8_t code[] = {0x8B, 0x05, 0x3A, 0x21, 0x01, 0x00}; // mov eax,[rip+0x1213A]
    const uint8_t ten[] = {10, 0, 0, 0};
    CHECK(f.ctx.writeStaticImage(dataAddress, ten, sizeof(ten)) == sizeof(ten));
    const auto decoded = f.ctx.staticDisassembler()->disassemble(code, sizeof(code), 0x200, 1);
    CHECK(decoded.size() == 1);
    if (decoded.size() != 1) return;
    Instruction instruction = decoded.front();
    const auto originalHint = f.tab->memoryValueHint(f.ctx, instruction);
    CHECK(originalHint.text == "FILE [0x12340] = 10 (u32, 0x0000000A)");
    CHECK(originalHint.tooltip.find("not a runtime value") != std::string::npos);

    instruction.comment = "decoder annotation retained";
    f.tab->comments_[instruction.address] = "analyst comment retained";
    f.tab->showStringComments_ = f.tab->showFnNotes_ = f.tab->showHints_ = false;
    auto renderLoggedRow = [&] {
        std::string text;
        frame([&] {
            ImGui::LogToBuffer();
            if (ImGui::BeginTable("Memory value row", 6,
                    ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoSavedSettings)) {
                const char* names[] = {"", "", "Address", "Bytes", "Instruction", "Comment"};
                const float widths[] = {18, 40, 115, 120, 260, 1000};
                for (int i = 0; i < 6; ++i)
                    ImGui::TableSetupColumn(names[i], ImGuiTableColumnFlags_WidthFixed, widths[i]);
                std::string hover;
                f.tab->renderAsmRow(f.ctx, instruction, f.detached, {}, hover, false, true);
                ImGui::EndTable();
            }
            text = ImGui::GetCurrentContext()->LogBuffer.c_str();
            ImGui::LogFinish();
        });
        return text;
    };
    f.tab->showMemoryValues_ = true;
    std::string rendered = renderLoggedRow();
    CHECK(rendered.find(originalHint.text) != std::string::npos);
    CHECK(rendered.find("decoder annotation retained") != std::string::npos);
    CHECK(rendered.find("analyst comment retained") != std::string::npos);
    f.tab->showMemoryValues_ = false;
    rendered = renderLoggedRow();
    CHECK(rendered.find("FILE [0x12340]") == std::string::npos);
    CHECK(rendered.find("analyst comment retained") != std::string::npos);

    // The loaded image is authoritative on the next draw, including edits.
    const uint8_t eleven[] = {11, 0, 0, 0};
    CHECK(f.ctx.writeStaticImage(dataAddress, eleven, sizeof(eleven)) == sizeof(eleven));
    CHECK(f.tab->memoryValueHint(f.ctx, instruction).text ==
          "FILE [0x12340] = 11 (u32, 0x0000000B)");
    Instruction partial = instruction;
    for (auto& operand : partial.typedOperands) {
        if (operand.kind != OperandKind::Memory) continue;
        operand.baseRegister.clear();
        operand.displacement = 128 * 4096 - 2;
        operand.displacementValid = true;
    }
    CHECK(f.tab->memoryValueHint(f.ctx, partial).text.find("unavailable (u32)") != std::string::npos);

    // The actual debugger is detached even though the retained frame claims a
    // pause. A still-fresh cached sample must not be mistaken for authority.
    DbgSnapshot live;
    live.state = DbgState::Paused;
    live.pid = 12345;
    live.sessionGeneration = 7;
    live.activeTid = 11;
    auto seed = [&](double sampledAt) {
        f.tab->memoryValueCache_.clear();
        f.tab->memoryValueOwner_ = {live.pid, live.sessionGeneration};
        f.tab->memoryValueStopKey_ = f.tab->liveStopKey(live);
        BinaryViewTab::MemoryValueSample sample;
        std::memcpy(sample.bytes, ten, sizeof(ten));
        sample.count = sizeof(ten);
        sample.sampledAt = sampledAt;
        f.tab->memoryValueCache_[{dataAddress, 32}] = sample;
    };
    seed(ImGui::GetTime());
    CHECK(!f.ctx.debug.memorySessionMatches({live.pid, live.sessionGeneration}));
    CHECK(f.tab->memoryValueHint(f.ctx, instruction, &live).text.empty());
    CHECK(f.tab->memoryValueCache_.empty());
    CHECK(!f.tab->memoryValueOwner_.valid());
    Instruction byteInstruction = instruction;
    for (auto& operand : byteInstruction.typedOperands)
        if (operand.kind == OperandKind::Memory) operand.widthBits = 8;
    seed(ImGui::GetTime());
    CHECK(f.tab->memoryValueHint(f.ctx, byteInstruction, &live).text.empty());
    seed(ImGui::GetTime() - 1.0);
    CHECK(f.tab->memoryValueHint(f.ctx, instruction, &live).text.empty());
    seed(ImGui::GetTime());
    ++live.sessionGeneration;
    CHECK(f.tab->memoryValueHint(f.ctx, instruction, &live).text.empty());
    live.state = DbgState::Detached;
    CHECK(f.tab->memoryValueHint(f.ctx, instruction, &live).text.empty());
}
