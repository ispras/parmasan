// SPDX-License-Identifier: MIT

#pragma once

#include <csignal>
#include <string_view>

namespace PS
{

class ParmasanInputDelegate;

class ParmasanDataSource
{
  public:
    virtual ~ParmasanDataSource() = default;
    virtual void disconnect_process(pid_t pid) = 0;

    void set_delegate(ParmasanInputDelegate* delegate)
    {
        m_delegate = delegate;
    }

    virtual bool loop() = 0;
    virtual void close() = 0;

  protected:
    ParmasanInputDelegate* m_delegate = nullptr;
};

class ParmasanInputDelegate
{
  public:
    virtual void process_connected(ParmasanDataSource* input, pid_t pid) = 0;
    virtual void process_message(ParmasanDataSource* input, pid_t pid,
                                 std::string_view message) = 0;
    virtual void process_disconnected(ParmasanDataSource* input, pid_t pid) = 0;
};

} // namespace PS
