#pragma once
#include <memory>
#include <vector>
#include <cstdint>

namespace ds {
// Copies retain the exact image allocation. Readers expose no mutable storage;
// the image owner explicitly detaches before writing. Empty/moved-from images
// remain readable, and clear never allocates (including failed-load cleanup).
class OwnedImage {
    std::shared_ptr<std::vector<uint8_t>> storage_;
public:
    const std::vector<uint8_t>& bytes() const {
        static const std::vector<uint8_t> empty;
        return storage_ ? *storage_ : empty;
    }
    operator const std::vector<uint8_t>&() const { return bytes(); }
    auto begin() const { return bytes().begin(); }
    auto end() const { return bytes().end(); }
    bool empty() const { return bytes().empty(); }
    size_t size() const { return bytes().size(); }
    size_t max_size() const { return bytes().max_size(); }
    const uint8_t* data() const { return bytes().data(); }
    uint8_t operator[](size_t index) const { return bytes()[index]; }
    void clear() noexcept { storage_.reset(); }
    void resize(size_t size) { storage_ = std::make_shared<std::vector<uint8_t>>(size); }
    OwnedImage& operator=(std::vector<uint8_t>&& bytes) {
        storage_ = std::make_shared<std::vector<uint8_t>>(std::move(bytes));
        return *this;
    }
    uint8_t* mutableData() {
        if (!storage_ || storage_.use_count() != 1)
            storage_ = std::make_shared<std::vector<uint8_t>>(bytes());
        return storage_->data();
    }
    std::shared_ptr<const std::vector<uint8_t>> snapshot() const { return storage_; }
};
} // namespace ds
