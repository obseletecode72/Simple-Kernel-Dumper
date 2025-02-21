#include "driver.hpp"

bool onlyNumbers(const std::string& str) {
    return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
}

int main()
{
    std::string nomeDriver;
    std::cout << "whats the name of driver or the pid?: ";
    std::getline(std::cin, nomeDriver);

    driver::initdriver();

    if (onlyNumbers(nomeDriver)) {
        DWORD pid = static_cast<DWORD>(std::stoul(nomeDriver));
        driver::dump_process(pid);
    }
    else {
        driver::dump_driver(nomeDriver.c_str());
    }

    return 0;
}
