// 64 distinct switch arms plus loop/back-edge, early exit and nested branches.
#define ARM(n) case n: value = n + 1; break
int cfg_stress(unsigned input) {
    int value = 1;
    for (unsigned step = 0; step < 3; ++step) {
        if (input > 1000) return 0;
        switch (input & 63) {
        ARM(0); ARM(1); ARM(2); ARM(3); ARM(4); ARM(5); ARM(6); ARM(7);
        ARM(8); ARM(9); ARM(10); ARM(11); ARM(12); ARM(13); ARM(14); ARM(15);
        ARM(16); ARM(17); ARM(18); ARM(19); ARM(20); ARM(21); ARM(22); ARM(23);
        ARM(24); ARM(25); ARM(26); ARM(27); ARM(28); ARM(29); ARM(30); ARM(31);
        ARM(32); ARM(33); ARM(34); ARM(35); ARM(36); ARM(37); ARM(38); ARM(39);
        ARM(40); ARM(41); ARM(42); ARM(43); ARM(44); ARM(45); ARM(46); ARM(47);
        ARM(48); ARM(49); ARM(50); ARM(51); ARM(52); ARM(53); ARM(54); ARM(55);
        ARM(56); ARM(57); ARM(58); ARM(59); ARM(60); ARM(61); ARM(62); ARM(63);
        }
        if (value > 32) {
            if (input & 1) continue;
            if (input & 2) break;
        }
    }
#if STRESS_BUG
    int* p = nullptr;
    return value + *p;
#else
    return value;
#endif
}
