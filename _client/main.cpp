#include <iostream>
#include <cstring>
#include <thread>

#include "Sender.hpp"

std::string_view ip_address = "127.0.0.1";

int main() {
    Sender s(ip_address, 8080);
    s.connect();
    // std::thread t1([&]{
    //     while (1)
    //     {
    //         std::string str;
    //         std::cin >> str;
    //         s.send(str.c_str());
    //     }
    // });

    s.send("Hello!!!");
    s.send({"1", "2", "3"});

    // std::thread t2([&]{
    //     while(1)
    //     {
    //         s.accept();
    //     }

    // });
    // t1.join();
    // t2.join();
    return 0;
}