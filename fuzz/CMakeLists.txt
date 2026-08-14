function(add_codeskeptic_fuzzer target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE codeskeptic_core)
    target_compile_options(${target} PRIVATE
        -fsanitize=fuzzer -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
endfunction()

add_codeskeptic_fuzzer(codeskeptic_fuzz_config FuzzConfig.cpp)
add_codeskeptic_fuzzer(codeskeptic_fuzz_compile_database
                       FuzzCompileDatabase.cpp)
add_codeskeptic_fuzzer(codeskeptic_fuzz_summary FuzzSummary.cpp)
add_codeskeptic_fuzzer(codeskeptic_fuzz_mcp_json_rpc FuzzMcpJsonRpc.cpp)
