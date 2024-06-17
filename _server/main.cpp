#include "Reciever.hpp"

#include <string>
#include <iostream>


int main() {
    Reciever r;
    r.connect();
    r.accept();
    // std::thread t1([&]{
    //     while (1)
    //     {
    //                 std::string str;
    //         std::cin >> str;
    //         r.send(str.c_str());
    //     }
    // });
    // std::thread t2([&]{
    //     r.accept();
    // });
    // t1.join();
    // t2.join();
    return 0;
}