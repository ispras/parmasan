// SPDX-License-Identifier: MIT

#include "parmasan-daemon.hpp"
#include <csignal>
#include <sys/socket.h>
#include "make-connection-handler.hpp"
#include "tracer-process.hpp"

const char* PS::ParmasanInteractiveModeDescr[] = {
    "NONE", "SYNC"};

void PS::ParmasanDaemon::process_message(ParmasanDataSource* input, pid_t pid,
                                         std::string_view message)
{
    m_current_data_source = input;

    auto action = action_for_message(pid, message);
    auto code = action.action;

    if (code == DaemonActionCode::ERROR) {
        protocol_error();
    }

    if (code == DaemonActionCode::DISCONNECT || code == DaemonActionCode::ERROR) {
        auto pid_to_disconnect = action.payload.pid;
        if (pid_to_disconnect == 0) {
            pid_to_disconnect = pid;
        }
        delete_connection(pid_to_disconnect);
    }

    m_current_data_source = nullptr;
}

void PS::ParmasanDaemon::process_connected(ParmasanDataSource* /* input */, pid_t /* pid */)
{
}

void PS::ParmasanDaemon::process_disconnected(ParmasanDataSource* /* input */, pid_t pid)
{
    delete_connection(pid);
}

DaemonAction PS::ParmasanDaemon::action_for_message(pid_t pid, std::string_view message)
{
    const char* buffer = message.data();

    // Check if this pid is already registered
    if (m_connections.find(pid) == m_connections.end()) {
        // Make sure that this packet is initial packet
        char event_type = buffer[0];
        if (event_type != GeneralEventType::GENERAL_EVENT_INIT) {
            // Do not use ERROR here, since after `quit` command
            // tracer can still send messages.
            return DaemonActionCode::CONTINUE;
        }

        // Jump to the beginning of the next word
        while (*buffer != '\0' && *buffer != ' ')
            buffer++;

        while (*buffer == ' ')
            buffer++;

        // Read the message author (M = MAKE or T = TRACER)
        char message_author = buffer[0];

        switch (message_author) {
        case MessageAuthorType::MESSAGE_TYPE_TRACER:
            if (!create_tracer_connection(pid)) {
                return DaemonActionCode::ERROR;
            }
            return DaemonActionCode::CONTINUE;

        case MessageAuthorType::MESSAGE_TYPE_MAKE:
            create_make_connection(pid);
            return DaemonActionCode::CONTINUE;

        default:
            return DaemonActionCode::ERROR;
        }
    }

    auto* data = m_connections[pid].get();

    return data->handle_packet(buffer);
}

void PS::ParmasanDaemon::create_make_connection(pid_t pid)
{
    auto make_data = std::make_unique<MakeConnectionHandler>(pid);

    if (m_tracer && m_tracer->has_child_with_pid(pid)) {
        make_data->attach_to_tracer(m_tracer);
    } else {
        std::cerr << "Warning: dangling make process pid=" << pid << "\n";
    }

    m_connections.insert({pid, std::move(make_data)});
}

bool PS::ParmasanDaemon::create_tracer_connection(pid_t pid)
{
    if (m_tracer) {
        return false;
    }
    auto tracer_data = std::make_unique<TracerProcess>(pid);
    m_tracer = tracer_data.get();
    tracer_data->set_delegate(this);

    m_connections.insert({pid, std::move(tracer_data)});

    return true;
}

void PS::ParmasanDaemon::protocol_error()
{
    std::cerr << "Warning: Last message caused a protocol error\n";
}

void PS::ParmasanDaemon::delete_connection(pid_t pid)
{
    auto it = m_connections.find(pid);
    if (it == m_connections.end())
        return;

    auto connection = it->second.get();

    // Tell the make processes handlers that their tracer is no longer
    // available.
    if (m_tracer == connection) {
        for (auto& make_process : m_tracer->get_make_processes()) {
            auto make_pid = make_process->get_process_data()->id;

            auto make_it = m_connections.find(make_pid.pid);
            if (make_it == m_connections.end()) {
                continue;
            }

            auto make_connection = (MakeConnectionHandler*)make_it->second.get();

            // Make sure that the pid didn't get reused
            if (make_connection->get_make_process().get_process_data()->id == make_pid) {
                make_connection->attach_to_tracer(nullptr);
            }
        }

        m_tracer = nullptr;
    }

    m_connections.erase(it);
}

void PS::ParmasanDaemon::set_interactive_mode(PS::ParmasanInteractiveMode interactive_mode)
{
    m_interactive_mode = interactive_mode;
}

PS::ParmasanInteractiveMode PS::ParmasanDaemon::get_interactive_mode()
{
    return m_interactive_mode;
}

void PS::ParmasanDaemon::handle_race(PS::TracerProcess* tracer, const PS::Race& race)
{
    if (m_delegate) {
        m_delegate->handle_race(this, tracer, race);
    }
}

void PS::ParmasanDaemon::handle_access(PS::TracerProcess* tracer, const PS::AccessRecord& access,
                                       const PS::File& file)
{
    if (m_delegate) {
        m_delegate->handle_access(this, tracer, access, file);
    }
}

void PS::ParmasanDaemon::handle_termination(PS::TracerProcess* tracer)
{
    if (m_current_data_source) {
        m_current_data_source->close();
    }
}

void PS::ParmasanDaemon::set_delegate(PS::ParmasanDaemonDelegate* delegate)
{
    m_delegate = delegate;
}
