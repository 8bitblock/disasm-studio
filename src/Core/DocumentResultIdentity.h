#pragma once

// Immutable ownership token for UI results derived from one static document
// image. Content hashes alone are insufficient: two documents may hold the
// same bytes at different raw mappings, and a replacement image may reuse both
// the hash and BinaryFile's local revision sequence.

#include "DocumentContext.h"

#include <cstdint>

namespace ds {

struct DocumentResultIdentity {
    DocumentId document;
    uint64_t   imageGeneration = 0;
    uint64_t   contentHash = 0;
    uint64_t   imageRevision = 0;
    bool       loaded = false;

    explicit operator bool() const {
        return loaded && static_cast<bool>(document) && imageGeneration != 0;
    }

    friend bool operator==(const DocumentResultIdentity&,
                           const DocumentResultIdentity&) = default;
};

inline DocumentResultIdentity MakeDocumentResultIdentity(
    DocumentId document, uint64_t imageGeneration, bool loaded,
    uint64_t contentHash, uint64_t imageRevision) {
    return { document, imageGeneration, contentHash, imageRevision, loaded };
}

// Invalid identities never own results, including another invalid identity.
// This keeps an empty scratch document from validating cached data after a
// failed or interrupted transition.
inline bool SameDocumentResultImage(const DocumentResultIdentity& owner,
                                    const DocumentResultIdentity& current) {
    return static_cast<bool>(owner) && static_cast<bool>(current) &&
           owner == current;
}

} // namespace ds
