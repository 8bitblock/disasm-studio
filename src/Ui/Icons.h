#pragma once
//
// Icons.h
// Named Segoe MDL2 Assets glyphs (C:\Windows\Fonts\segmdl2.ttf, ships with
// Windows 10/11 - no extra dependency). The font is merged into the UI font by
// ds::ui::LoadFonts; gate every icon emission on ds::ui::IconsLoaded() so a
// missing font degrades to text-only instead of '?' boxes.
//
// The constants are hand-encoded UTF-8 for the PUA codepoints (the project
// does not compile with /utf-8, so \u escapes in narrow literals are unsafe).
//
#include "Fonts.h"   // ds::ui::IconsLoaded()

// U+E700 GlobalNavButton (hamburger)
#define DS_ICON_NAV       "\xEE\x9C\x80"
// U+E710 Add
#define DS_ICON_ADD       "\xEE\x9C\x90"
// U+E711 Cancel
#define DS_ICON_CANCEL    "\xEE\x9C\x91"
// U+E713 Settings (gear)
#define DS_ICON_SETTINGS  "\xEE\x9C\x93"
// U+E71A Stop
#define DS_ICON_STOP      "\xEE\x9C\x9A"
// U+E721 Search (magnifier)
#define DS_ICON_SEARCH    "\xEE\x9C\xA1"
// U+E72C Refresh
#define DS_ICON_REFRESH   "\xEE\x9C\xAC"
// U+E73E CheckMark
#define DS_ICON_CHECK     "\xEE\x9C\xBE"
// U+E74E Save (floppy)
#define DS_ICON_SAVE      "\xEE\x9D\x8E"
// U+E768 Play
#define DS_ICON_PLAY      "\xEE\x9D\xA8"
// U+E769 Pause
#define DS_ICON_PAUSE     "\xEE\x9D\xA9"
// U+E783 Error (circled !)
#define DS_ICON_ERROR     "\xEE\x9E\x83"
// U+E7BA Warning (triangle !)
#define DS_ICON_WARNING   "\xEE\x9E\xBA"
// U+E8A4 Bookmarks
#define DS_ICON_BOOKMARKS "\xEE\xA2\xA4"
// U+E8AB Switch (two opposing arrows - used for Binary Diff)
#define DS_ICON_SWITCH    "\xEE\xA2\xAB"
// U+E8B7 Folder
#define DS_ICON_FOLDER    "\xEE\xA2\xB7"
// U+E943 Code (angle brackets)
#define DS_ICON_CODE      "\xEE\xA5\x83"
// U+E945 LightningBolt
#define DS_ICON_LIGHTNING "\xEE\xA5\x85"
// U+E946 Info (circled i)
#define DS_ICON_INFO      "\xEE\xA5\x86"
// U+E950 Memory (RAM chip)
#define DS_ICON_MEMORY    "\xEE\xA5\x90"
// U+E968 Network
#define DS_ICON_NETWORK   "\xEE\xA5\xA8"
// U+EA18 Shield (used for Binary Tech / capabilities)
#define DS_ICON_SHIELD    "\xEE\xAA\x98"
// U+E72B Back (left arrow) / U+E72A Forward (right arrow)
#define DS_ICON_BACK      "\xEE\x9C\xAB"
#define DS_ICON_FORWARD   "\xEE\x9C\xAA"
// U+E74B Down / U+E74A Up (step into / step out)
#define DS_ICON_DOWN      "\xEE\x9D\x8B"
#define DS_ICON_UP        "\xEE\x9D\x8A"
// U+E7A6 Redo (curved arrow - step over)
#define DS_ICON_REDO      "\xEE\x9E\xA6"
// U+E707 MapPin (run to cursor)
#define DS_ICON_PIN       "\xEE\x9C\x87"
