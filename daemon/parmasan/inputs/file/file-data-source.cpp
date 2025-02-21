// SPDX-License-Identifier: MIT

#include "file-data-source.hpp"

bool PS::ParmasanFileDataSource::loop()
{
    pid_t pid = -1;
    int message_type = '\0';
    int message_length = -1;
    std::string message;

    while (m_input.good()) {
        m_input >> pid;
        skip_whitespaces();
        message_type = m_input.get();
        skip_word();

        switch (message_type) {
        case 'C':
            // Connect
            connected_pids.insert(pid);
            if (m_delegate != nullptr) {
                m_delegate->process_connected(this, pid);
            }
            break;

        case 'D':
            // Disconnect
            if (m_delegate != nullptr && connected_pids.count(pid) != 0) {
                m_delegate->process_disconnected(this, pid);
                connected_pids.erase(pid);
            }
            break;

        case 'M':
            // Message
            m_input >> message_length;
            skip_whitespaces();
            message.resize(message_length);
            m_input.read(message.data(), message_length);
            if (m_delegate != nullptr && connected_pids.count(pid) != 0) {
                m_delegate->process_message(this, pid, message);
            }
            break;

        default:
            break;
        }
    }
    return m_input.eof();
}

void PS::ParmasanFileDataSource::skip_word()
{
    int c = m_input.peek();
    while (c != EOF && c != ' ' && c != '\n') {
        c = m_input.get();
    }
}

void PS::ParmasanFileDataSource::skip_whitespaces()
{
    while (true) {
        int c = m_input.peek();
        if (c == EOF || c != ' ') {
            break;
        }
        m_input.get();
    }
}

void PS::ParmasanFileDataSource::disconnect_process(pid_t pid)
{
    connected_pids.erase(pid);
}

void PS::ParmasanFileDataSource::close()
{
    m_input.close();
}
