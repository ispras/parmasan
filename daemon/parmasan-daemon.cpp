
#include "parmasan-daemon.hpp"
#include "make-connection-data.hpp"
#include "tracer-connection-data.hpp"

DaemonAction PS::ParmasanDaemon::handle_message()
{
    auto action = action_for_message();
    auto code = action.action;

    if (code == DaemonActionCode::ERROR) {
        protocol_error();
    }

    if (code == DaemonActionCode::DISCONNECT || code == DaemonActionCode::ERROR) {
        auto pid = action.payload.pid;
        if (pid == 0) {
            pid = m_last_message_pid;
        }
        delete_connection(pid);
    }

    return action;
}
DaemonAction PS::ParmasanDaemon::action_for_message()
{
    m_last_message_pid = 0;

    const char* buffer = m_buffer.data();

    // Read the message author (M = MAKE or T = TRACER)
    char message_author = buffer[0];

    // Skip the first word
    while (*buffer != '\0' && *buffer != ' ')
        buffer++;

    if (message_author != MessageAuthorType::MESSAGE_TYPE_MAKE &&
        message_author != MessageAuthorType::MESSAGE_TYPE_TRACER) {
        return DaemonActionCode::ERROR;
    }

    int res = 0;

    if (sscanf(buffer, "%d %n", &m_last_message_pid, &res) != 1) {
        return DaemonActionCode::ERROR;
    }

    buffer += res;

    // Check if this pid is already registered
    if (m_connections.find(m_last_message_pid) == m_connections.end()) {
        // Make sure that this packet is initial packet
        char event_type = buffer[0];
        if (event_type != GeneralEventType::GENERAL_EVENT_INIT) {
            return DaemonActionCode::ERROR;
        }

        // Create a new connection

        if (message_author == MessageAuthorType::MESSAGE_TYPE_TRACER) {
            create_tracer_connection(m_last_message_pid);
        } else {
            create_make_connection(m_last_message_pid);
        }

        return DaemonActionCode::ACKNOWLEDGE;
    }

    auto* data = m_connections[m_last_message_pid].get();

    return data->handle_packet(buffer);
}

PS::TracerConnectionData* PS::ParmasanDaemon::get_tracer_for_pid(pid_t pid)
{
    for (TracerConnectionData* tracer : m_tracers) {
        if (tracer->has_child_with_pid(pid))
            return tracer;
    }
    return nullptr;
}

void PS::ParmasanDaemon::create_make_connection(pid_t pid)
{
    auto make_data = std::make_unique<MakeConnectionData>(-1, pid);

    TracerConnectionData* tracer = get_tracer_for_pid(pid);

    if (tracer) {
        make_data->attach_to_tracer(tracer);
        tracer->assign_make_process(pid, make_data.get());
    } else {
        std::cerr << "Warning: dangling make process pid=" << pid << "\n";
    }

    make_data->send_acknowledgement_packet();

    m_connections.insert({pid, std::move(make_data)});
}

void PS::ParmasanDaemon::create_tracer_connection(pid_t pid)
{
    auto tracer_data = std::make_unique<TracerConnectionData>(-1, m_dump_output);
    m_tracers.insert(tracer_data.get());

    m_connections.insert({pid, std::move(tracer_data)});
}

void PS::ParmasanDaemon::protocol_error()
{
    std::cerr << "Warning: Last message caused a protocol error\n";
}

void PS::ParmasanDaemon::delete_connection(pid_t pid)
{
    auto it = m_connections.find(pid);
    if (it != m_connections.end()) {
        m_connections.erase(it);
    }
}
