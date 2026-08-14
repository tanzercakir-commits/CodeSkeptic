template <typename T>
int malformed_template(T value) {
    return value + ;
}

int instantiate_malformed_template() {
    return malformed_template(0);
}
