void build(Solution &s) {
    // Uncomment to make a project. Also replace s.addTarget(). with p.addTarget() below.
    // auto &p = s.addProject("myproject");
    // p += Git("enter your url here", "enter tag here", "or branch here");

    auto &t = s.addTarget<Executable>("mycrypto");
    t += cpp23;
    t += "src/main.cpp";


    // add deps here
    // example:
    // t += "org.sw.demo.someproject"_dep;

}
