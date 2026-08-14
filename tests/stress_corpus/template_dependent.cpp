template <typename Range>
int dependent_range_sum(Range&& range) {
    int total = 0;
    for (auto value : range) total += value;
    return total;
}

int dependent_template_anchor() { return 0; }
