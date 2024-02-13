#include "dumper.hpp"
#include <iomanip>

void PS::ParmasanDumper::process_connected(PS::ParmasanDataSource* /* input */, pid_t pid)
{
    m_output << std::setw(10) << pid << " CONNECT\n";
}

void PS::ParmasanDumper::process_message(PS::ParmasanDataSource* /* input */, pid_t pid,
                                         std::string_view message)
{
    m_output << std::setw(10) << pid << " MSG " << std::setw(4) << message.size() << " " << message
             << "\n";
}

void PS::ParmasanDumper::process_disconnected(PS::ParmasanDataSource* /* input */, pid_t pid)
{
    m_output << std::setw(10) << pid << " DISCONNECT\n";
}
