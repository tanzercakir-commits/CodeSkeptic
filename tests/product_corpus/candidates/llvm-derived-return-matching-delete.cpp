// Derived from LLVM clang/test/Analysis/NewDelete-checker-test.cpp, lines 396-410.
// Revision: 87f0227cb60147a26a1eeb4fb06e3b505e9c7261 (llvmorg-20.1.8).
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// See ../licenses/LLVM.txt. Modification: isolated these declarations/functions;
// removed unrelated tests, harness directives and the unused simulator include.
// Candidate only: source/dependency/addressability review is not yet an admitted freeze.
struct Base {
  virtual ~Base() {}
};

struct Derived : Base {
};

Base *allocate() {
  return new Derived;
}

void shouldNotReportLeak() {
  Derived *p = (Derived *)allocate();
  delete p;
}
