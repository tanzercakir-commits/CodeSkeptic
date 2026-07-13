#include "contracts/ContractParser.h"

#include <cctype>
#include <optional>

namespace zerodefect {

namespace {

// --- Tokenizer ---

struct Token {
    enum Kind {
        Ident,
        Int,
        LParen,
        RParen,
        Cmp,     // == != < <= > >=
        AndAnd,
        OrOr,
        Bang,
        End,
        Bad,
    } kind = End;
    std::string text;
    long long value = 0;
    ContractCmpOp cmp = ContractCmpOp::EQ;
};

class Lexer {
public:
    explicit Lexer(const std::string& s) : s_(s) {}

    Token next() {
        while (pos_ < s_.size() && std::isspace(
                   static_cast<unsigned char>(s_[pos_])))
            ++pos_;
        if (pos_ >= s_.size()) return {Token::End, "", 0, {}};

        const char c = s_[pos_];
        if (c == '(') { ++pos_; return {Token::LParen, "(", 0, {}}; }
        if (c == ')') { ++pos_; return {Token::RParen, ")", 0, {}}; }

        if (c == '&' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '&') {
            pos_ += 2;
            return {Token::AndAnd, "&&", 0, {}};
        }
        if (c == '|' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '|') {
            pos_ += 2;
            return {Token::OrOr, "||", 0, {}};
        }
        if (c == '!') {
            if (pos_ + 1 < s_.size() && s_[pos_ + 1] == '=') {
                pos_ += 2;
                return {Token::Cmp, "!=", 0, ContractCmpOp::NE};
            }
            ++pos_;
            return {Token::Bang, "!", 0, {}};
        }
        if (c == '=') {
            if (pos_ + 1 < s_.size() && s_[pos_ + 1] == '=') {
                pos_ += 2;
                return {Token::Cmp, "==", 0, ContractCmpOp::EQ};
            }
            ++pos_;
            return {Token::Bad, "=", 0, {}};
        }
        if (c == '<') {
            if (pos_ + 1 < s_.size() && s_[pos_ + 1] == '=') {
                pos_ += 2;
                return {Token::Cmp, "<=", 0, ContractCmpOp::LE};
            }
            ++pos_;
            return {Token::Cmp, "<", 0, ContractCmpOp::LT};
        }
        if (c == '>') {
            if (pos_ + 1 < s_.size() && s_[pos_ + 1] == '=') {
                pos_ += 2;
                return {Token::Cmp, ">=", 0, ContractCmpOp::GE};
            }
            ++pos_;
            return {Token::Cmp, ">", 0, ContractCmpOp::GT};
        }
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '-' && pos_ + 1 < s_.size() &&
             std::isdigit(static_cast<unsigned char>(s_[pos_ + 1])))) {
            size_t start = pos_;
            if (c == '-') ++pos_;
            while (pos_ < s_.size() &&
                   std::isdigit(static_cast<unsigned char>(s_[pos_])))
                ++pos_;
            Token t{Token::Int, s_.substr(start, pos_ - start), 0, {}};
            t.value = std::stoll(t.text);
            return t;
        }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t start = pos_;
            while (pos_ < s_.size() &&
                   (std::isalnum(static_cast<unsigned char>(s_[pos_])) ||
                    s_[pos_] == '_'))
                ++pos_;
            return {Token::Ident, s_.substr(start, pos_ - start), 0, {}};
        }
        ++pos_;
        return {Token::Bad, std::string(1, c), 0, {}};
    }

private:
    const std::string& s_;
    size_t pos_ = 0;
};

// --- Recursive-descent parser over one clause body ---

class Parser {
public:
    explicit Parser(const std::string& s) : lex_(s) { advance(); }

    bool failed() const { return failed_; }
    bool atEnd() const { return tok_.kind == Token::End; }
    const Token& tok() const { return tok_; }

    void advance() { tok_ = lex_.next(); if (tok_.kind == Token::Bad) failed_ = true; }

    bool eatIdent(const char* word) {
        if (tok_.kind == Token::Ident && tok_.text == word) {
            advance();
            return true;
        }
        return false;
    }

    std::optional<ContractOperand> parseOperand() {
        if (tok_.kind == Token::Int) {
            ContractOperand o;
            o.kind = ContractOperandKind::IntLit;
            o.value = tok_.value;
            advance();
            return o;
        }
        if (tok_.kind == Token::Ident) {
            ContractOperand o;
            if (tok_.text == "return") {
                o.kind = ContractOperandKind::Return;
            } else if (tok_.text == "null") {
                o.kind = ContractOperandKind::Null;
            } else if (tok_.text == "if") {
                // `if` is a clause-level keyword, never an operand.
                return std::nullopt;
            } else {
                o.kind = ContractOperandKind::Param;
                o.param = tok_.text;
            }
            advance();
            return o;
        }
        return std::nullopt;
    }

    std::optional<ContractPred> parseAtom() {
        if (tok_.kind == Token::LParen) {
            advance();
            auto inner = parsePred();
            if (!inner) return std::nullopt;
            if (tok_.kind != Token::RParen) { failed_ = true; return std::nullopt; }
            advance();
            return inner;
        }
        auto lhs = parseOperand();
        if (!lhs) return std::nullopt;
        if (tok_.kind == Token::Cmp) {
            ContractPred p;
            p.kind = ContractPred::Cmp;
            p.lhs = *lhs;
            p.op = tok_.cmp;
            advance();
            auto rhs = parseOperand();
            if (!rhs) { failed_ = true; return std::nullopt; }
            p.rhs = *rhs;
            return p;
        }
        ContractPred p;
        p.kind = ContractPred::Truth;
        p.lhs = *lhs;
        return p;
    }

    std::optional<ContractPred> parseUnary() {
        if (tok_.kind == Token::Bang) {
            advance();
            auto sub = parseUnary();
            if (!sub) return std::nullopt;
            ContractPred p;
            p.kind = ContractPred::Not;
            p.children.push_back(std::move(*sub));
            return p;
        }
        return parseAtom();
    }

    std::optional<ContractPred> parseAnd() {
        auto first = parseUnary();
        if (!first) return std::nullopt;
        if (tok_.kind != Token::AndAnd) return first;
        ContractPred p;
        p.kind = ContractPred::And;
        p.children.push_back(std::move(*first));
        while (tok_.kind == Token::AndAnd) {
            advance();
            auto next = parseUnary();
            if (!next) { failed_ = true; return std::nullopt; }
            p.children.push_back(std::move(*next));
        }
        return p;
    }

    std::optional<ContractPred> parsePred() {
        auto first = parseAnd();
        if (!first) return std::nullopt;
        if (tok_.kind != Token::OrOr) return first;
        ContractPred p;
        p.kind = ContractPred::Or;
        p.children.push_back(std::move(*first));
        while (tok_.kind == Token::OrOr) {
            advance();
            auto next = parseAnd();
            if (!next) { failed_ = true; return std::nullopt; }
            p.children.push_back(std::move(*next));
        }
        return p;
    }

private:
    Lexer lex_;
    Token tok_;
    bool failed_ = false;
};

// Parses ONE clause body (the text after "zd:"/"zd:ai"). Returns
// nullopt on any syntax problem — the caller records the line.
std::optional<ContractClause> parseClauseBody(const std::string& body) {
    Parser p(body);
    ContractClause clause;
    clause.text = body;

    if (p.eatIdent("requires")) {
        clause.kind = ContractClauseKind::Requires;
        auto pred = p.parsePred();
        if (!pred || p.failed() || !p.atEnd()) return std::nullopt;
        clause.pred = std::move(*pred);
        return clause;
    }
    if (p.eatIdent("ensures")) {
        clause.kind = ContractClauseKind::Ensures;
        auto pred = p.parsePred();
        if (!pred || p.failed()) return std::nullopt;
        clause.pred = std::move(*pred);
        if (p.eatIdent("if")) {
            auto guard = p.parsePred();
            if (!guard || p.failed() || !p.atEnd()) return std::nullopt;
            clause.hasGuard = true;
            clause.guard = std::move(*guard);
        } else if (!p.atEnd()) {
            return std::nullopt;
        }
        return clause;
    }
    if (p.eatIdent("owns") || p.eatIdent("borrows")) {
        // eatIdent advanced past the keyword; recover which one from
        // the clause text (single leading word).
        clause.kind = body.rfind("owns", 0) == 0
                          ? ContractClauseKind::Owns
                          : ContractClauseKind::Borrows;
        if (p.tok().kind != Token::LParen) return std::nullopt;
        p.advance();
        if (p.tok().kind != Token::Ident) return std::nullopt;
        clause.paramName = p.tok().text;
        p.advance();
        if (p.tok().kind != Token::RParen) return std::nullopt;
        p.advance();
        if (!p.atEnd()) return std::nullopt;
        return clause;
    }
    if (p.eatIdent("returns")) {
        if (!p.eatIdent("owned") || !p.atEnd()) return std::nullopt;
        clause.kind = ContractClauseKind::ReturnsOwned;
        return clause;
    }
    if (p.eatIdent("policy")) {
        if (p.tok().kind != Token::Ident) return std::nullopt;
        clause.kind = ContractClauseKind::Policy;
        // Policy names may contain '-' (no-absolute-paths): consume
        // ident ('-' ident)* — the lexer sees '-' as Bad, so read the
        // remainder of the body verbatim instead.
        auto pos = body.find("policy");
        std::string rest = body.substr(pos + 6);
        while (!rest.empty() && std::isspace(
                   static_cast<unsigned char>(rest.front())))
            rest.erase(rest.begin());
        while (!rest.empty() && std::isspace(
                   static_cast<unsigned char>(rest.back())))
            rest.pop_back();
        if (rest.empty()) return std::nullopt;
        for (char c : rest) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' &&
                c != '_')
                return std::nullopt;
        }
        clause.policyName = rest;
        return clause;
    }
    return std::nullopt;
}

// Trims whitespace and comment leaders from a raw comment line.
std::string stripCommentLine(std::string line) {
    size_t i = 0;
    while (i < line.size()) {
        const char c = line[i];
        if (std::isspace(static_cast<unsigned char>(c)) || c == '/' ||
            c == '*') {
            ++i;
            continue;
        }
        break;
    }
    line.erase(0, i);
    // Strip a trailing block-comment terminator.
    const auto endPos = line.find("*/");
    if (endPos != std::string::npos) line.erase(endPos);
    while (!line.empty() &&
           std::isspace(static_cast<unsigned char>(line.back())))
        line.pop_back();
    return line;
}

} // anonymous namespace

ParsedContracts parseContractComment(const std::string& commentText) {
    ParsedContracts out;
    unsigned lineNo = 0;
    size_t start = 0;
    while (start <= commentText.size()) {
        size_t end = commentText.find('\n', start);
        std::string rawLine =
            commentText.substr(start, end == std::string::npos
                                          ? std::string::npos
                                          : end - start);
        ++lineNo;
        start = (end == std::string::npos) ? commentText.size() + 1 : end + 1;

        std::string line = stripCommentLine(rawLine);
        if (line.rfind("zd:", 0) != 0) continue;

        std::string body = line.substr(3);
        bool machine = false;
        // "zd:ai <clause>" — the tag is glued to the prefix.
        if (body.rfind("ai", 0) == 0 &&
            (body.size() == 2 ||
             std::isspace(static_cast<unsigned char>(body[2])))) {
            machine = true;
            body.erase(0, 2);
        }
        while (!body.empty() &&
               std::isspace(static_cast<unsigned char>(body.front())))
            body.erase(body.begin());

        auto clause = parseClauseBody(body);
        if (!clause) {
            out.syntaxErrors.push_back({lineNo, line});
            continue;
        }
        clause->machineProposed = machine;
        clause->line = lineNo;
        out.clauses.push_back(std::move(*clause));
    }
    return out;
}

} // namespace zerodefect
