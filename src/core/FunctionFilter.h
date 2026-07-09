#ifndef ZERODEFECT_FUNCTION_FILTER_H
#define ZERODEFECT_FUNCTION_FILTER_H

#include <set>
#include <string>

namespace clang {
class FunctionDecl;
}

namespace zerodefect {

// Artimli analiz primitifi: filtre bos degilse yalnizca adi eslesen
// fonksiyonlar analiz edilir. Ajan/IDE dongusunde "yalnizca degisen
// fonksiyonu yeniden kontrol et" icin. setLang gibi surec-geneli tek
// ayar (analiz tek is parcaciginda kosar).
void setFunctionFilter(std::set<std::string> names);
const std::set<std::string>& functionFilter();

// Bos filtre herkese izin verir; aksi halde duz ad ("parse") veya
// nitelikli ad ("Parser::parse") eslesmesi aranir.
bool functionFilterAllows(const clang::FunctionDecl& func);

} // namespace zerodefect

#endif // ZERODEFECT_FUNCTION_FILTER_H
