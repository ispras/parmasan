
#include "daemon-connection-data.hpp"
#include <sys/socket.h>

bool PS::DaemonConnectionData::mark_done() {
    if (m_done_flag)
        return false;
    m_done_flag = true;
    return true;
}
void PS::DaemonConnectionData::send_acknowledgement_packet() const {
    char packet[] = "ACK";
    send(m_fd, packet, sizeof(packet), 0);
}
