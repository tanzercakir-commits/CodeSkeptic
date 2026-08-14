#define CS_CASE(N) case N: divisor = N + 1; break

int high_cfg_clean(int selector) {
    int divisor = 1;
    switch (selector) {
        CS_CASE(0);  CS_CASE(1);  CS_CASE(2);  CS_CASE(3);
        CS_CASE(4);  CS_CASE(5);  CS_CASE(6);  CS_CASE(7);
        CS_CASE(8);  CS_CASE(9);  CS_CASE(10); CS_CASE(11);
        CS_CASE(12); CS_CASE(13); CS_CASE(14); CS_CASE(15);
        CS_CASE(16); CS_CASE(17); CS_CASE(18); CS_CASE(19);
        CS_CASE(20); CS_CASE(21); CS_CASE(22); CS_CASE(23);
        CS_CASE(24); CS_CASE(25); CS_CASE(26); CS_CASE(27);
        CS_CASE(28); CS_CASE(29); CS_CASE(30); CS_CASE(31);
        CS_CASE(32); CS_CASE(33); CS_CASE(34); CS_CASE(35);
        CS_CASE(36); CS_CASE(37); CS_CASE(38); CS_CASE(39);
        CS_CASE(40); CS_CASE(41); CS_CASE(42); CS_CASE(43);
        CS_CASE(44); CS_CASE(45); CS_CASE(46); CS_CASE(47);
        CS_CASE(48); CS_CASE(49); CS_CASE(50); CS_CASE(51);
        CS_CASE(52); CS_CASE(53); CS_CASE(54); CS_CASE(55);
        CS_CASE(56); CS_CASE(57); CS_CASE(58); CS_CASE(59);
        CS_CASE(60); CS_CASE(61); CS_CASE(62); CS_CASE(63);
        default: break;
    }
    if (divisor == 0) return 0;
    return 4096 / divisor;
}

int high_cfg_seeded(int selector) {
    int divisor = 1;
    switch (selector) {
        CS_CASE(0);  CS_CASE(1);  CS_CASE(2);  CS_CASE(3);
        CS_CASE(4);  CS_CASE(5);  CS_CASE(6);  CS_CASE(7);
        CS_CASE(8);  CS_CASE(9);  CS_CASE(10); CS_CASE(11);
        CS_CASE(12); CS_CASE(13); CS_CASE(14); CS_CASE(15);
        CS_CASE(16); CS_CASE(17); CS_CASE(18); CS_CASE(19);
        CS_CASE(20); CS_CASE(21); CS_CASE(22); CS_CASE(23);
        CS_CASE(24); CS_CASE(25); CS_CASE(26); CS_CASE(27);
        CS_CASE(28); CS_CASE(29); CS_CASE(30); CS_CASE(31);
        CS_CASE(32); CS_CASE(33); CS_CASE(34); CS_CASE(35);
        CS_CASE(36); CS_CASE(37); CS_CASE(38); CS_CASE(39);
        CS_CASE(40); CS_CASE(41); CS_CASE(42); CS_CASE(43);
        CS_CASE(44); CS_CASE(45); CS_CASE(46); CS_CASE(47);
        CS_CASE(48); CS_CASE(49); CS_CASE(50); CS_CASE(51);
        CS_CASE(52); CS_CASE(53); CS_CASE(54); CS_CASE(55);
        CS_CASE(56); CS_CASE(57); CS_CASE(58); CS_CASE(59);
        CS_CASE(60); CS_CASE(61); CS_CASE(62);
        case 63: divisor = 0; break;
        default: break;
    }
    return 4096 / divisor;
}
