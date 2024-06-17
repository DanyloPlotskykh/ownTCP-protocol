#include "Reciever.hpp"



int main() {
    Reciever r;
    r.connect();
    // r.send("jjjjjjjjj");
    r.accept();
    return 0;
}