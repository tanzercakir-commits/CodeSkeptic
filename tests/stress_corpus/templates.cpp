// Bounded dependent types, constexpr recursion and instantiated function bodies.
// No standard library or external headers are required.
template <int N> struct Chain { static constexpr int value = 1 + Chain<N - 1>::value; };
template <> struct Chain<0> { static constexpr int value = 1; };
template <typename T> struct Box {
    using value_type = T;
    T value;
    template <int N> T get() const {
        if constexpr (N > 0) return value + N;
        return value;
    }
};
template <typename T> int dependent(const T& box) {
    typename T::value_type value = box.template get<3>();
    return value;
}
int template_stress() {
    Box<int> box{Chain<32>::value};
    int result = dependent(box);
#if STRESS_BUG
    int* p = nullptr;
    return result + *p;
#else
    return result;
#endif
}
