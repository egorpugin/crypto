void build(Solution &s) {
    auto &t = s.addTarget<Executable>("mycrypto");
    t += cpp23;
    t += "src/.*"_rr;

    t += "org.sw.demo.boost.asio"_dep;
    t += "org.sw.demo.neargye.nameof"_dep;

    t += "bcrypt.lib"_slib;

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
