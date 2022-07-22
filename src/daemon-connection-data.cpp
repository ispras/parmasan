
#include "daemon-connection-data.hpp"
bool PS::DaemonConnectionData::mark_done() {
    if (m_done_flag)
        return false;
    m_done_flag = true;
    return true;
}
void PS::DaemonConnectionData::send_acknowledgement_packet() const {
    char packet[] = "ACK";
    m_connection->send(packet, sizeof(packet), 0);
}
