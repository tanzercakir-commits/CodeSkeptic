#ifndef ZERODEFECT_FUNCTION_FILTER_H
#define ZERODEFECT_FUNCTION_FILTER_H

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace clang {
class FunctionDecl;
class SourceManager;
}

namespace zerodefect {

// Artimli analiz primitifleri: filtreler bos degilse yalnizca kapsam
// icindeki fonksiyonlar analiz edilir. Ajan/IDE dongusunde "yalnizca
// degiseni yeniden kontrol et" icin. setLang gibi surec-geneli tek
// ayar (analiz tek is parcaciginda kosar).

// --- Ad filtresi (--function) ---
void setFunctionFilter(std::set<std::string> names);
const std::set<std::string>& functionFilter();

// Bos filtre herkese izin verir; aksi halde duz ad ("parse") veya
// nitelikli ad ("Parser::parse") eslesmesi aranir.
bool functionFilterAllows(const clang::FunctionDecl& func);

// --- Satir araligi filtresi (--lines, hunk -> fonksiyon eslemesi) ---
// Araliklar analiz edilen ANA dosyaya uygulanir (diff hunk'lari zaten o
// dosyaya aittir); header'daki fonksiyonlar kapsam disidir.
using LineRanges = std::vector<std::pair<unsigned, unsigned>>;
void setLineRanges(LineRanges ranges);
const LineRanges& lineRanges();

// Bos filtre herkese izin verir; aksi halde fonksiyonun [baslangic,
// bitis] satir araligi verilen araliklardan biriyle kesismelidir.
bool lineFilterAllows(const clang::FunctionDecl& func,
                      const clang::SourceManager& sm);

} // namespace zerodefect

#endif // ZERODEFECT_FUNCTION_FILTER_H
