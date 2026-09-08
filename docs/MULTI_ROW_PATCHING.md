# Multi-row instruction patches

- In Assembly or Live Assembly, click the first row and Shift-click the last row, or drag across the Address, Bytes, or Instruction columns. Ctrl-click toggles individual rows. Breakpoint gutters and destination links keep their separate actions.
- Press **P**, choose **Patch** from the row menu or **More**, or choose **Patch selection (asm / bytes)**. When the action targets a selected row, the dialog starts at the first selected instruction and includes the complete last instruction.
- The selected rows must be adjacent. A disjoint selection is refused rather than including unselected bytes between rows. A replacement longer than the complete selection remains refused; close the dialog and select more rows first.
- Assembly and hex drafts retain the entire input without the previous 256-character assembly / 128-character hex buffers. Short replacements follow the existing NOP-padding option. Architectures without assembly support can use hex bytes.
- FILE patches retain checked instruction snapshots independently of the listing cache. LIVE patches retain the exact debugger session and masked original bytes. Changed or unreadable bytes require reopening the patch from current rows.
- Mouse selection retains the visible listing position, so extending a range does not recenter or rebuild the rows beneath the pointer.

Regression coverage is in `tests/multi_row_patch_fixture.inc`, linked against the production application objects by `tests/run_static_listing_actions_test.ps1`.
