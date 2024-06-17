#include <iostream>
#include <cstring>

#include "Sender.hpp"

std::string_view ip_address = "127.0.0.1";

int main() {
    Sender s(ip_address, 8080);
    s.connect();
    s.send("HELLO!!!");
    s.send({"hahaahaha", "lsdfjgblsdfg", "alsjdfgbalidfjgbf"});
        // s.send("HELLO!!!");
        //     s.send("HELLO!!!");
        //         s.send("HELLO!!!");
    // s.accept();
    return 0;
}