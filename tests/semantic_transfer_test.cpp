#include "Core/SemanticTransfer.h"

#include <cassert>
#include <iostream>

using namespace ds;

static SemanticImage fixture() {
    SemanticImage image;
    image.arch = Arch::X64;
    image.contentIdentity = 0x1234;
    SemanticFunction function;
    function.address = 0; // VA zero is valid
    function.instructions.push_back({});
    function.instructions[0].address = 0;
    function.instructions.push_back({});
    function.instructions[1].address = 1;
    image.functions.push_back(std::move(function));
    return image;
}

int main() {
    SemanticImage image = fixture();
    ProjectState project;
    project.hash = 0x1234;
    auto mapped = [](uint64_t address) { return address <= 1; };

    MetadataTransferProposal name;
    name.kind = MetadataTransferKind::Name;
    name.targetFunction = 0;
    name.value = "entry";
    auto applied = ApplySemanticTransferProposal(project, 0x1234, image, name, mapped);
    assert(applied.status == SemanticTransferStatus::Applied);
    assert(applied.targetAddressValid && applied.targetAddress == 0);
    assert(project.names.at(0) == "entry");
    assert(ApplySemanticTransferProposal(project, 0x1234, image, name, mapped).status ==
           SemanticTransferStatus::Unchanged);

    MetadataTransferProposal comment;
    comment.kind = MetadataTransferKind::Comment;
    comment.targetFunction = 0;
    comment.targetInstructionValid = true;
    comment.targetInstructionIndex = 1;
    comment.value = "checked";
    assert(ApplySemanticTransferProposal(project, 0x1234, image, comment, mapped).status ==
           SemanticTransferStatus::Applied);
    assert(project.comments.at(1) == "checked");

    MetadataTransferProposal malformed = comment;
    malformed.targetInstructionIndex = 2;
    assert(ApplySemanticTransferProposal(project, 0x1234, image, malformed, mapped).status ==
           SemanticTransferStatus::InvalidProposal);
    assert(ApplySemanticTransferProposal(project, 0x9999, image, comment, mapped).status ==
           SemanticTransferStatus::WrongProject);
    auto unmapped = [](uint64_t) { return false; };
    assert(ApplySemanticTransferProposal(project, 0x1234, image, comment, unmapped).status ==
           SemanticTransferStatus::UnmappedTarget);
    assert(project.comments.size() == 1); // rejection is atomic

    MetadataTransferProposal prototype;
    prototype.kind = MetadataTransferKind::Prototype;
    prototype.targetFunction = 0;
    prototype.value = "void entry(void)";
    project.functionOverrides.push_back({0, PjFunctionAction::Undefine});
    assert(ApplySemanticTransferProposal(project, 0x1234, image, prototype, mapped).status ==
           SemanticTransferStatus::TargetExplicitlyUndefined);
    project.functionOverrides.clear();
    assert(ApplySemanticTransferProposal(project, 0x1234, image, prototype, mapped).status ==
           SemanticTransferStatus::Applied);
    assert(project.functionOverrides.size() == 1);
    assert(project.functionOverrides[0].address == 0);
    assert(project.functionOverrides[0].prototype == "void entry(void)");

    MetadataTransferProposal bookmark;
    bookmark.kind = MetadataTransferKind::Bookmark;
    bookmark.targetFunction = 0;
    bookmark.targetInstructionValid = true;
    bookmark.targetInstructionIndex = 1;
    assert(ApplySemanticTransferProposal(project, 0x1234, image, bookmark, mapped).status ==
           SemanticTransferStatus::Applied);
    assert(project.bookmarks.size() == 1 && project.bookmarks[0].address == 1);

    std::cout << "semantic_transfer_test: OK\n";
    return 0;
}
