#include "engine/AllocFunctions.h"

#include <utility>

namespace zerodefect {

namespace {
std::set<std::string>& allocStorage() {
    static std::set<std::string> names;
    return names;
}
std::set<std::string>& freeStorage() {
    static std::set<std::string> names;
    return names;
}
std::set<std::string>& owningPtrStorage() {
    static std::set<std::string> names;
    return names;
}
} // namespace

void setAllocFunctionNames(std::set<std::string> names) {
    allocStorage() = std::move(names);
}

const std::set<std::string>& allocFunctionNames() {
    return allocStorage();
}

void setFreeFunctionNames(std::set<std::string> names) {
    freeStorage() = std::move(names);
}

const std::set<std::string>& freeFunctionNames() {
    return freeStorage();
}

void setOwningPointerNames(std::set<std::string> names) {
    owningPtrStorage() = std::move(names);
}

const std::set<std::string>& owningPointerNames() {
    return owningPtrStorage();
}

} // namespace zerodefect
