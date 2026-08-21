// json.h -- minimal JSON parser/serializer.
//
// Exists because haiku/arm64 has no package repository: there is no jq, no
// nlohmann, nothing to link against. This is only as complete as the SSM wire
// protocol needs (BRIEF.md 9.2): objects, arrays, strings with escapes,
// numbers, bools, null.
#pragma once

#include <map>
#include <string>
#include <vector>

namespace json {

struct Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

struct Value {
    enum Type { Null, Bool, Number, String, Obj, Arr };

    Type type = Null;
    bool boolean = false;
    double number = 0;
    bool integral = true;  // print 0 rather than 0.0 -- SSM's "code" field is an int
    std::string string;
    Object object;
    Array array;

    Value() = default;

    // Lookup that never throws: returns nullptr when absent or not an object.
    const Value* find(const std::string& key) const;

    // Typed accessors with defaults, for reading untrusted service payloads.
    std::string str(const std::string& fallback = "") const;
    double num(double fallback = 0) const;
    bool bl(bool fallback = false) const;

    // Convenience: str(key) == find(key)->str()
    std::string str_at(const std::string& key, const std::string& fallback = "") const;
    double num_at(const std::string& key, double fallback = 0) const;

    bool is_null() const { return type == Null; }
    bool is_obj() const { return type == Obj; }
    bool is_arr() const { return type == Arr; }
    bool is_str() const { return type == String; }
};

Value str(std::string s);
Value num(double n, bool integral = true);
Value boolean(bool b);
Value obj();
Value arr();

// Returns a Null value and sets *err on malformed input. Callers must treat a
// parse failure as a protocol error, never as an empty document.
Value parse(const std::string& text, std::string* err = nullptr);

std::string dump(const Value& v);

}  // namespace json
