void build(Solution &s) {
    auto &crypto = s.addTarget<Executable>("crypto");
    {
        auto &t = crypto;
        t += cpp23;
        t += "src/.*\\.h"_rr;

        t.Public += "org.sw.demo.boost.asio"_dep;
        t.Public += "org.sw.demo.neargye.nameof"_dep;

        t += "bcrypt.lib"_slib;
    }

    auto &test = s.addTarget<Executable>("test");
    {
        auto &t = test;
        t += cpp23;
        t += "src/main.cpp";
        t += crypto;
    }

    {
        auto &t = s.addTarget<Executable>("tlsparams");
        t.PackageDefinitions = true;
        t += cpp23;
        t += "tools/tlsparams.cpp";
        //t += "pub.egorpugin.primitives.http"_dep;
        t += "pub.egorpugin.primitives.sw.main"_dep;
        t += "org.sw.demo.zeux.pugixml"_dep;
    }
}
