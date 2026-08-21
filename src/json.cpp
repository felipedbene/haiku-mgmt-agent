#include "json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace json {

const Value* Value::find(const std::string& key) const {
    if (type != Obj) return nullptr;
    auto it = object.find(key);
    return it == object.end() ? nullptr : &it->second;
}

std::string Value::str(const std::string& fallback) const {
    return type == String ? string : fallback;
}

double Value::num(double fallback) const {
    if (type == Number) return number;
    // SSM documents routinely carry numbers as strings ("timeoutSeconds": "3600").
    if (type == String && !string.empty()) {
        char* end = nullptr;
        double d = std::strtod(string.c_str(), &end);
        if (end && *end == '\0') return d;
    }
    return fallback;
}

bool Value::bl(bool fallback) const {
    if (type == Bool) return boolean;
    if (type == String) {
        if (string == "true") return true;
        if (string == "false") return false;
    }
    return fallback;
}

std::string Value::str_at(const std::string& key, const std::string& fallback) const {
    const Value* v = find(key);
    return v ? v->str(fallback) : fallback;
}

double Value::num_at(const std::string& key, double fallback) const {
    const Value* v = find(key);
    return v ? v->num(fallback) : fallback;
}

Value str(std::string s) {
    Value v;
    v.type = Value::String;
    v.string = std::move(s);
    return v;
}

Value num(double n, bool integral) {
    Value v;
    v.type = Value::Number;
    v.number = n;
    v.integral = integral;
    return v;
}

Value boolean(bool b) {
    Value v;
    v.type = Value::Bool;
    v.boolean = b;
    return v;
}

Value obj() {
    Value v;
    v.type = Value::Obj;
    return v;
}

Value arr() {
    Value v;
    v.type = Value::Arr;
    return v;
}

// ---------------------------------------------------------------- parser

namespace {

struct Parser {
    const std::string& in;
    size_t i = 0;
    std::string err;

    explicit Parser(const std::string& s) : in(s) {}

    void ws() {
        while (i < in.size() && (in[i] == ' ' || in[i] == '\t' || in[i] == '\n' || in[i] == '\r')) i++;
    }

    bool fail(const char* msg) {
        if (err.empty()) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "%s at offset %zu", msg, i);
            err = buf;
        }
        return false;
    }

    // Encode one code point as UTF-8. Haiku is UTF-8 throughout, so this is
    // the only encoding we need.
    static void utf8(unsigned cp, std::string& out) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(unsigned& out) {
        if (i + 4 > in.size()) return fail("truncated \\u escape");
        out = 0;
        for (int k = 0; k < 4; k++) {
            char c = in[i++];
            out <<= 4;
            if (c >= '0' && c <= '9') out |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') out |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= static_cast<unsigned>(c - 'A' + 10);
            else return fail("bad hex digit in \\u escape");
        }
        return true;
    }

    bool string_(std::string& out) {
        if (i >= in.size() || in[i] != '"') return fail("expected string");
        i++;
        while (true) {
            if (i >= in.size()) return fail("unterminated string");
            char c = in[i++];
            if (c == '"') return true;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i >= in.size()) return fail("unterminated escape");
            char e = in[i++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned cp = 0;
                    if (!hex4(cp)) return false;
                    // Surrogate pair.
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < in.size() && in[i] == '\\' && in[i + 1] == 'u') {
                        i += 2;
                        unsigned lo = 0;
                        if (!hex4(lo)) return false;
                        if (lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else
                            utf8(lo, out);  // lone low surrogate: emit as-is
                    }
                    utf8(cp, out);
                    break;
                }
                default: return fail("unknown escape");
            }
        }
    }

    bool value(Value& out) {
        ws();
        if (i >= in.size()) return fail("unexpected end of input");
        char c = in[i];
        if (c == '{') {
            i++;
            out = obj();
            ws();
            if (i < in.size() && in[i] == '}') { i++; return true; }
            while (true) {
                ws();
                std::string key;
                if (!string_(key)) return false;
                ws();
                if (i >= in.size() || in[i] != ':') return fail("expected ':'");
                i++;
                Value v;
                if (!value(v)) return false;
                out.object[key] = std::move(v);
                ws();
                if (i < in.size() && in[i] == ',') { i++; continue; }
                if (i < in.size() && in[i] == '}') { i++; return true; }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            i++;
            out = arr();
            ws();
            if (i < in.size() && in[i] == ']') { i++; return true; }
            while (true) {
                Value v;
                if (!value(v)) return false;
                out.array.push_back(std::move(v));
                ws();
                if (i < in.size() && in[i] == ',') { i++; continue; }
                if (i < in.size() && in[i] == ']') { i++; return true; }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') {
            std::string s;
            if (!string_(s)) return false;
            out = str(std::move(s));
            return true;
        }
        if (in.compare(i, 4, "true") == 0) { i += 4; out = boolean(true); return true; }
        if (in.compare(i, 5, "false") == 0) { i += 5; out = boolean(false); return true; }
        if (in.compare(i, 4, "null") == 0) { i += 4; out = Value(); return true; }

        // number
        size_t start = i;
        if (i < in.size() && (in[i] == '-' || in[i] == '+')) i++;
        bool any = false, isint = true;
        while (i < in.size() && in[i] >= '0' && in[i] <= '9') { i++; any = true; }
        if (i < in.size() && in[i] == '.') { isint = false; i++; while (i < in.size() && in[i] >= '0' && in[i] <= '9') i++; }
        if (i < in.size() && (in[i] == 'e' || in[i] == 'E')) {
            isint = false;
            i++;
            if (i < in.size() && (in[i] == '-' || in[i] == '+')) i++;
            while (i < in.size() && in[i] >= '0' && in[i] <= '9') i++;
        }
        if (!any) return fail("invalid value");
        out = num(std::strtod(in.substr(start, i - start).c_str(), nullptr), isint);
        return true;
    }
};

}  // namespace

Value parse(const std::string& text, std::string* err) {
    Parser p(text);
    Value v;
    if (!p.value(v)) {
        if (err) *err = p.err;
        return Value();
    }
    p.ws();
    if (p.i != text.size()) {
        // Trailing garbage is a protocol error, not something to shrug off.
        if (err) *err = "trailing data after JSON value";
        return Value();
    }
    if (err) err->clear();
    return v;
}

// ------------------------------------------------------------- serializer

namespace {

void escape(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    // UTF-8 bytes pass through unchanged.
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

void dump_to(const Value& v, std::string& out) {
    switch (v.type) {
        case Value::Null: out += "null"; break;
        case Value::Bool: out += v.boolean ? "true" : "false"; break;
        case Value::Number: {
            char buf[40];
            if (v.integral && std::fabs(v.number) < 1e15 && v.number == std::floor(v.number))
                std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v.number));
            else
                std::snprintf(buf, sizeof(buf), "%.17g", v.number);
            out += buf;
            break;
        }
        case Value::String: escape(v.string, out); break;
        case Value::Obj: {
            out += '{';
            bool first = true;
            for (const auto& kv : v.object) {
                if (!first) out += ',';
                first = false;
                escape(kv.first, out);
                out += ':';
                dump_to(kv.second, out);
            }
            out += '}';
            break;
        }
        case Value::Arr: {
            out += '[';
            for (size_t k = 0; k < v.array.size(); k++) {
                if (k) out += ',';
                dump_to(v.array[k], out);
            }
            out += ']';
            break;
        }
    }
}

}  // namespace

std::string dump(const Value& v) {
    std::string out;
    dump_to(v, out);
    return out;
}

}  // namespace json
