// generator from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml

//#include <primitives/http.h>
#include <primitives/sw/main.h>
#include <pugixml.hpp>

struct emitter {
    std::string s;
    void add_line(auto &&t) {
        s += t + "\n"s;
    }
    auto enum_(auto &&n) {
        struct en {
            emitter &e;
            std::string n;
            std::string s;
            int bytes{1};
            void add_line(const std::string &t) {
                s += t + "\n"s;
            }
            ~en() {
                std::string b = "uint" + std::to_string(bytes*8) + "_t";
                e.add_line("enum class "s + n + " : " + b + " {");
                if (s.ends_with("\n")) {
                    s.resize(s.size() - 1);
                }
                e.add_line(s);
                e.add_line("};\n");
            }
        };
        return en{*this,n};
    }
};

int main(int argc, char *argv[]) {
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file("d:/dev/crypto/tls-parameters.xml");
    if (!result) {
        throw SW_RUNTIME_ERROR("Load result: "s + result.description());
    }

    emitter e;
    e.add_line("// autogenerated by tools/tlsparams.cpp\n");
    for (auto &&q : doc.select_nodes("/registry/registry[*]")) {
        auto n = q.node();
        std::string name = n.select_node("./title").node().first_child().value();
        if (name.starts_with("TLS ")) {
            name = name.substr(4);
        }
        boost::replace_all(name, " ", "_");
        boost::replace_all(name, "(", "_");
        boost::replace_all(name, ")", "_");
        //boost::to_lower(name);
        std::string name2;
        for (int i = 0; i < name.size(); ++i) {
            if (isupper(name[i])) {
                if (i && name[i-1] != '_') {
                    name2 += "_";
                }
                name[i] = tolower(name[i]);
            }
            name2 += name[i];
        }
        auto en = e.enum_(name2);
        for (auto &&q : n.select_nodes("./record[*]")) {
            auto r = q.node();
            std::string v = r.select_node("./value").node().first_child().value();
            std::string d = r.select_node("./description").node().first_child().value();
            std::optional<bool> rec;
            if (auto n = r.select_node("./rec").node()) {
                rec = n.first_child().value() == "Y"s;
            } else if (auto n = r.select_node("./recommended").node(); n && n.first_child()) {
                rec = n.first_child().value() == "Y"s;
            }
            std::replace(d.begin(), d.end(), '\n', ' ');
            boost::replace_all(d, "  ", " ");
            boost::replace_all(d, "(renamed from \"NewSessionTicket\")", "");
            boost::trim(d);
            boost::replace_all(v, ",0x", "");
            boost::trim(v);
            auto fs = " -*\"()";
            if (d.find_first_of(fs) != -1 || v.find_first_of(fs) != -1 || d.contains("Reserved") || d.contains("Unassigned")) {
                d = "// " + d;
            } else if (!v.empty()) {
                auto v2 = v;
                int base = 10;
                if (v2.starts_with("0x")) {
                    v2 = v;
                    base = 16;
                }
                auto v3 = std::stoi(v2, 0, base);
                if (v3 > 255) {
                    en.bytes = 2;
                }
            }
            std::string srec;
            if (rec) {
                srec = " // "s + (*rec ? "recommended" : "not recommended");
            }
            std::string line;
            if (v.empty()) {
                line = std::format("    {:88},    {}", d, srec);
            } else {
                line = std::format("    {:70} = {:15},    {}", d, v, srec);
            }
            en.add_line(line);
        }
    }
    std::cout << e.s;

    return 0;
}
