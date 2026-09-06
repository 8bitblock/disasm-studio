#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <optional>

namespace ds::ui {

// Graph and viewport coordinates are logical pixels. The renderer applies DPI
// once at the boundary, so dragging/zooming survives a monitor scale change.
struct GraphPoint { float x = 0, y = 0; };

struct GraphViewport {
    static constexpr float minZoom = 0.001f;
    static constexpr float maxZoom = 3.0f;
    float zoom = 1.0f;
    GraphPoint pan{24.0f, 12.0f};

    GraphPoint project(GraphPoint world) const {
        return {world.x * zoom + pan.x, world.y * zoom + pan.y};
    }
    GraphPoint unproject(GraphPoint view) const {
        return {(view.x - pan.x) / zoom, (view.y - pan.y) / zoom};
    }
    void zoomAt(float requestedZoom, GraphPoint anchor) {
        if (!std::isfinite(requestedZoom)) return;
        const GraphPoint world = unproject(anchor);
        zoom = std::clamp(requestedZoom, minZoom, maxZoom);
        pan = {anchor.x - world.x * zoom, anchor.y - world.y * zoom};
    }
    void center(GraphPoint world, GraphPoint extent) {
        pan = {extent.x * 0.5f - world.x * zoom,
               extent.y * 0.5f - world.y * zoom};
    }
    bool fit(GraphPoint low, GraphPoint high, GraphPoint extent, float margin = 24.0f) {
        const float width = high.x - low.x, height = high.y - low.y;
        if (!(width > 0 && height > 0 && extent.x > margin * 2 && extent.y > margin * 2))
            return false;
        zoom = std::clamp(std::min({(extent.x - margin * 2) / width,
                                    (extent.y - margin * 2) / height, 1.0f}),
                          minZoom, maxZoom);
        center({low.x + width * 0.5f, low.y + height * 0.5f}, extent);
        return true;
    }
};

// Hit-test the same row geometry used for drawing. Header/padding clicks never
// round to the first or final instruction, including at overview zoom levels.
inline std::optional<size_t> GraphInstructionRow(float worldY, float firstRowY,
                                                float rowHeight, size_t count) {
    if (!(rowHeight > 0) || !std::isfinite(worldY) || worldY < firstRowY)
        return std::nullopt;
    const double row = std::floor((double(worldY) - firstRowY) / rowHeight);
    if (!(row >= 0 && row < static_cast<double>(count))) return std::nullopt;
    return static_cast<size_t>(row);
}

} // namespace ds::ui
