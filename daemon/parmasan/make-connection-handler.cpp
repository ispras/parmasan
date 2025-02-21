// SPDX-License-Identifier: MIT

#include "make-connection-handler.hpp"
#include "parmasan/make-process.hpp"

DaemonAction PS::MakeConnectionHandler::handle_packet(const char* buffer)
{
    if (!m_make_process) {
        return DaemonActionCode::DISCONNECT;
    }

    // Get the first character of the buffer, which is the event type.
    auto event_type = buffer[0];

    // Read the entire word from the buffer, but ignore it
    // because we already know what the event type is.

    while (*buffer != ' ' && *buffer != '\0')
        buffer++;

    switch (event_type) {
    case MAKE_EVENT_DEPENDENCY:
        if (m_make_process->read_dependency_event(buffer)) {
            return DaemonActionCode::CONTINUE;
        }
        return DaemonActionCode::ERROR;
    case MAKE_EVENT_TARGET_PID:
        if (m_make_process->read_target_pid_event(buffer)) {
            return DaemonActionCode::CONTINUE;
        }
        return DaemonActionCode::ERROR;
    case MAKE_EVENT_GOAL:
        if (m_make_process->read_goal_event(buffer)) {
            return DaemonActionCode::CONTINUE;
        }
        return DaemonActionCode::ERROR;
    case GENERAL_EVENT_INIT:
        // As it turned out, GNU make (and remake) have its own way
        // of handling makefile updates. When a makefile is updated,
        // the make process just re-executes itself without any kind
        // of shutdown. This means that the init event can be received
        // multiple times from the seemingly same process. The best way
        // of interpreting this is to pretend that the new make process
        // is a sub-make process. The only problem is - it's hard to know
        // what exact target have caused the make to re-execute. However,
        // it's impossible to have a race between two epochs of the same
        // makefile. Re-exec is a strong barrier. It's guaranteed that
        // there is nothing else running as a make child when it happens.
        // Thus, it should be fine to consider re-executed make as a
        // sibling, not a child. The parmasan will still be able to find
        // race conditions between re-executed make and its own parent
        // make processes.
        turn_into_sibling();

        return DaemonActionCode::CONTINUE;
    default:
        return DaemonActionCode::ERROR;
    }
}

void PS::MakeConnectionHandler::turn_into_sibling()
{
    // Turn ourselves into a sub-make of our parent.
    auto old_make_process = m_make_process;
    m_make_process = m_attached_tracer->create_make_process();
    m_attached_tracer->assign_make_process(m_pid, m_make_process);

    if (old_make_process) {
        m_make_process->set_parent_context(old_make_process->get_parent_context());
    }
}

void PS::MakeConnectionHandler::attach_to_tracer(PS::TracerProcess* tracer)
{
    if (!tracer) {
        m_attached_tracer = nullptr;
        m_make_process = nullptr;

        return;
    }

    m_attached_tracer = tracer;
    m_make_process = m_attached_tracer->create_make_process();
    m_attached_tracer->assign_make_process(m_pid, m_make_process);

    // If this make process is a sub-make, find the parent target

    auto process = m_attached_tracer->get_alive_process(m_pid);
    assert(process != nullptr && process->parent != nullptr);

    auto parent_make = process->parent->get_make_process();

    if (!parent_make) {
        // This is a top-level make
        return;
    }

    m_make_process->set_parent_context({.target = parent_make->get_target_for_process(process),
                                        .goal = parent_make->get_current_goal()});
}
