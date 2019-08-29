use::cmake::Config;

fn main() {
//  dynamically link to standard c++ lib so we can call boost functions in mymonero-core-cpp
//    println!("cargo:rustc-link-lib=dylib=stdc++"); // Linux/GCC
    println!("cargo:rustc-link-lib=dylib=c++");

    // link boost libraries (tested on OSX only!)
    println!("cargo:rustc-link-lib=boost_system");
    println!("cargo:rustc-link-lib=boost_thread");

    // build mymonero-core-cpp
    let mymonero_path = Config::new("mymonero-core-cpp").build();

    // let rustc know where mymonero-core-cpp is located
    println!("cargo:rustc-link-search=native={}", mymonero_path.display());

    // link mymonero-core-cpp library
    println!("cargo:rustc-link-lib=mymonero-core-cpp");
//    println!("cargo:rustc-link-lib=boost_thread");
}