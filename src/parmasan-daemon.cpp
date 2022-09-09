
#include "parmasan-daemon.hpp"
#include "make-connection-data.hpp"
#include "shared/connection-state.hpp"
#include "tracer-connection-data.hpp"

void PS::ParmasanDaemon::handle_disconnection(DaemonConnection* connection) {
    DaemonConnectionData* data = connection->data.get();

    if (!data)
        return;

    if (data->m_state == CONNECTION_STATE_TRACER_PROCESS) {
        auto tracer_data = static_cast<TracerConnectionData*>(data);
        m_tracers.erase(tracer_data);
    }
}

void PS::ParmasanDaemon::handle_message(DaemonConnection* connection, size_t length) {
    DaemonConnectionData* data = connection->data.get();

    bool result = false;

    if (data) {
        result = data->handle_packet(m_buffer.data(), length);
    } else {
        result = read_init_packet(connection, length);
    }

    if (!result) {
        std::cerr << "Error: protocol violation from ";

        if (data && data->m_state == CONNECTION_STATE_TRACER_PROCESS) {
            std::cerr << "tracer process\n";
        } else if (data && data->m_state == CONNECTION_STATE_MAKE_PROCESS) {
            std::cerr << "make process\n";
        } else {
            std::cerr << "unknown process\n";
        }

        // Protocol violation
        connection->close();
    }
}

bool PS::ParmasanDaemon::read_init_packet(DaemonConnection* connection, size_t length) {
    BufferReader reader(m_buffer.data(), length);

    ConnectionState mode;
    if (!reader.read(&mode))
        return false;

    if (mode == CONNECTION_STATE_MAKE_PROCESS) {
        pid_t make_pid = 0;
        if (!reader.read(&make_pid))
            return false;

        auto make_data = std::make_unique<MakeConnectionData>(connection);

        TracerConnectionData* tracer = get_tracer_for_pid(make_pid);
        if (tracer) {
            make_data->attach_to_tracer(tracer);
            tracer->make_process_attached(make_pid, make_data.get());
        } else {
            std::cerr << "Warning: dangling make process pid=" << make_pid << "\n";
        }

        make_data->send_acknowledgement_packet();
        connection->data = std::move(make_data);
    } else if (mode == CONNECTION_STATE_TRACER_PROCESS) {
        auto tracer_data = std::make_unique<TracerConnectionData>(connection);
        m_tracers.insert(tracer_data.get());
        connection->data = std::move(tracer_data);
    } else {
        std::cerr << "Unrecognized mode: 0x" << std::hex << +mode << "\n";
        return false;
    }

    connection->data->m_state = mode;

    return true;
}

PS::TracerConnectionData* PS::ParmasanDaemon::get_tracer_for_pid(pid_t pid) {
    for (TracerConnectionData* tracer : m_tracers) {
        if (tracer->has_child_with_pid(pid))
            return tracer;
    }
    return nullptr;
}
