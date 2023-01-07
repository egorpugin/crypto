void build(Solution &s) {
    // Uncomment to make a project. Also replace s.addTarget(). with p.addTarget() below.
    // auto &p = s.addProject("myproject");
    // p += Git("enter your url here", "enter tag here", "or branch here");

    auto &t = s.addTarget<Executable>("mycrypto");
    t += cpp23;
    t += "src/.*"_rr;

    t += "org.sw.demo.boost.asio"_dep;
    t += "org.sw.demo.neargye.nameof"_dep;
    t += "org.sw.demo.gnu.gmp.cxx"_dep;

    t += "bcrypt.lib"_slib;

    // add deps here
    // example:
    // t += "org.sw.demo.someproject"_dep;

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
