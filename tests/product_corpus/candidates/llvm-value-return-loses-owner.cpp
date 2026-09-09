// Derived from LLVM clang/test/Analysis/NewDeleteLeaks.cpp, lines 199-220.
// Revision: 87f0227cb60147a26a1eeb4fb06e3b505e9c7261 (llvmorg-20.1.8).
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Standalone C++17 proposal: removed only upstream diagnostic comments and
// the surrounding harness. No original simulator-harness equivalence is claimed.
// Not admitted; the caller is not a second independent safe sample.
namespace symbol_reaper_lifetime {
struct Nested {
  int buf[2];
};
struct Wrapping {
  Nested data;
};

Nested allocateWrappingAndReturnNested() {
  Wrapping const* p = new Wrapping();
  return p->data;
}

void caller() {
  Nested n = allocateWrappingAndReturnNested();
  (void)n;
}
}
