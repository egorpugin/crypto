void build(Solution &s) {
    auto &crypto = s.addTarget<StaticLibrary>("crypto");
    {
        auto &t = crypto;
        t += cpp23;
        t += "src/.*\\.h"_rr;
        t.Public += "src/.*\\.natvis"_rr;

        t.Public += "org.sw.demo.boost.asio"_dep;

        if (t.getCompilerType() == CompilerType::MSVC) {
            t.Public.CompileOptions.push_back("/bigobj");
        }
        if (t.getBuildSettings().TargetOS.Type == OSType::Windows || t.getBuildSettings().TargetOS.Type == OSType::Mingw) {
            t += "bcrypt.lib"_slib;
            t += "Crypt32.lib"_slib;
        }
    }

    auto &test = s.addTarget<Executable>("test");
    {
        auto &t = test;
        t += cpp23;
        t += "src/main.cpp";
        t += crypto;
        if (s.getExternalVariables()["ci-build"] == "true") {
            t += "CI_TESTS"_def;
        }
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

    auto &test2 = s.addTarget<Executable>("test2");
    {
        auto &t = test2;
        t += cpp23;
        t += "src/test.cpp";
    }
}
