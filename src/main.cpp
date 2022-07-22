
#include "parmasan-daemon.hpp"

int main() {
    PS::ParmasanDaemon daemon;

    if (!daemon.create_socket()) {
        std::cerr << "Failed to create socket\n";
        return EXIT_FAILURE;
    }

    if (!daemon.listen("/tmp/parmasan-socket.sock")) {
        std::cerr << "Failed to bind to socket\n";
        return EXIT_FAILURE;
    }

    daemon.loop();

    return 0;
}
