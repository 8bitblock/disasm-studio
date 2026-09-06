#include "Ui/GraphViewport.h"

#include <cmath>
#include <cstdio>
#include <limits>

using namespace ds::ui;
static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)
static bool near(float a, float b) { return std::fabs(a - b) < 0.01f; }

int main() {
    GraphViewport view;
    const GraphPoint cursor{431.0f, 287.0f};
    const GraphPoint selected = view.unproject(cursor);
    view.zoomAt(2.4f, cursor);
    CHECK(near(view.project(selected).x, cursor.x));
    CHECK(near(view.project(selected).y, cursor.y));
    view.zoomAt(100.0f, cursor);
    CHECK(view.zoom == GraphViewport::maxZoom);
    CHECK(near(view.project(selected).x, cursor.x));
    view.zoomAt(0.0f, cursor);
    CHECK(view.zoom == GraphViewport::minZoom);
    CHECK(near(view.project(selected).y, cursor.y));
    view.zoomAt(std::numeric_limits<float>::infinity(), cursor);
    CHECK(view.zoom == GraphViewport::minZoom);

    // A manually dragged block can live above/left of the original origin.
    CHECK(view.fit({-500.0f, -700.0f}, {1500.0f, 9300.0f}, {800.0f, 600.0f}));
    const auto low = view.project({-500.0f, -700.0f});
    const auto high = view.project({1500.0f, 9300.0f});
    CHECK(low.x >= 23.99f && low.y >= 23.99f);
    CHECK(high.x <= 776.01f && high.y <= 576.01f);
    const float before = view.zoom;
    CHECK(!view.fit({0, 0}, {0, 100}, {800, 600}));
    CHECK(view.zoom == before);

    // Selecting an instruction after zoom, pan and a DPI conversion still
    // returns its exact row. Row zero is valid; header/bottom padding are not.
    for (float dpi : {1.0f, 1.5f, 2.0f}) {
        view.zoomAt(0.55f, {200, 120});
        view.pan.x -= 61;
        view.pan.y += 90;
        const auto p = view.project({17.0f, 26.0f + 17.0f * 3.5f});
        const GraphPoint physical{p.x * dpi, p.y * dpi};
        const auto world = view.unproject({physical.x / dpi, physical.y / dpi});
        CHECK(GraphInstructionRow(world.y, 26.0f, 17.0f, 8) == 3);
    }
    CHECK(GraphInstructionRow(26.0f, 26.0f, 17.0f, 8) == 0);
    CHECK(!GraphInstructionRow(25.99f, 26.0f, 17.0f, 8));
    CHECK(GraphInstructionRow(161.99f, 26.0f, 17.0f, 8) == 7);
    CHECK(!GraphInstructionRow(162.0f, 26.0f, 17.0f, 8));
    CHECK(!GraphInstructionRow(26.0f, 26.0f, 17.0f, 0));
    CHECK(!GraphInstructionRow(26.0f, 26.0f, 0, 8));
    std::printf("graph_viewport_test: %s\n", failures ? "FAILED" : "OK");
    return failures ? 1 : 0;
}
