#include "Core/DocumentResultIdentity.h"

#include <cassert>

using namespace ds;

int main() {
    const auto first = MakeDocumentResultIdentity(
        DocumentId{1}, 7, true, 0x1234, 9);
    assert(first);
    assert(SameDocumentResultImage(first, first));

    // Equal bytes are not sufficient ownership when another document can map
    // them differently.
    const auto otherDocument = MakeDocumentResultIdentity(
        DocumentId{2}, 7, true, 0x1234, 9);
    assert(!SameDocumentResultImage(first, otherDocument));

    // Replacing an image within the same document invalidates results even if
    // its bytes and BinaryFile-local revision happen to repeat.
    const auto replacement = MakeDocumentResultIdentity(
        DocumentId{1}, 8, true, 0x1234, 9);
    assert(!SameDocumentResultImage(first, replacement));

    // In-place writes are caught by BinaryFile's revision while the pristine
    // content hash remains unchanged.
    const auto patched = MakeDocumentResultIdentity(
        DocumentId{1}, 7, true, 0x1234, 10);
    assert(!SameDocumentResultImage(first, patched));

    const auto empty = MakeDocumentResultIdentity(
        DocumentId{1}, 7, false, 0, 0);
    assert(!empty);
    assert(!SameDocumentResultImage(DocumentResultIdentity{}, first));
    assert(!SameDocumentResultImage(empty, empty));
    assert(!SameDocumentResultImage(first, empty));
    return 0;
}
