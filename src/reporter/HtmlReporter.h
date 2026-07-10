#ifndef ZERODEFECT_HTML_REPORTER_H
#define ZERODEFECT_HTML_REPORTER_H

#include "reporter/Reporter.h"

namespace zerodefect {

// Tek, kendine yeten HTML rapor: bagimlilik yok, offline acilir,
// e-posta/PR eki kadar kolay paylasilir. Ozet kartlari ayni zamanda
// filtre (severity/kural), metin kutusu dosya/mesaj suzer; her bulgunun
// dataflow izi tiklaninca kaynak baglamiyla acilir (rapor uretilirken
// kaynak satirlari goturulur — rapor tasindiginda baglam kaybolmaz).
class HtmlReporter : public Reporter {
public:
    explicit HtmlReporter(const std::string& output_path);

    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;

private:
    std::string output_path_;
};

} // namespace zerodefect

#endif // ZERODEFECT_HTML_REPORTER_H
