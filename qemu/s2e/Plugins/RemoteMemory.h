/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Eurecom
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Jonas Zaddach <zaddach@eurecom.fr>
 *
 */

#ifndef S2E_PLUGINS_DEBUG_H
#define S2E_PLUGINS_DEBUG_H

#include <tr1/memory> //shared_ptr
#include <queue>

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/MemoryMonitor.h>

extern "C" {
#include <qemu-thread.h>
}

#include <s2e/cajunjson/reader.h>
#include <s2e/QemuSocket.h>

//namespace json
//{
//    class Object;
//}

namespace s2e {
namespace plugins {
    
class RemoteMemoryInterface
{
public:
    RemoteMemoryInterface(S2E* s2e, std::string sockAddress);
    virtual ~RemoteMemoryInterface();
    void writeMemory(S2EExecutionState*, uint32_t address, int size, uint64_t value);
    uint64_t readMemory(S2EExecutionState*, uint32_t address, int size);
    
    void parse(std::string& token);
    
private:
    static void * receiveThread(void *);
    void handleClientCommand(std::string cmd, std::tr1::shared_ptr<json::Object> params);
    
    S2E* m_s2e;
//    CharDriverState * m_chrdev;
//    std::stringstream m_receiveBuffer;
    QemuMutex m_mutex;
    QemuCond m_responseCond;
    QemuThread m_thread;
    std::queue<std::tr1::shared_ptr<json::Object> > m_interruptQueue;
    std::queue<std::tr1::shared_ptr<json::Object> > m_responseQueue;
    bool m_cancelThread;
    std::tr1::shared_ptr<s2e::QemuTcpSocket> m_socket;
    S2EExecutionState * m_state;
};

// class QemuCharDevice
// {
// public:
//     QemuCharDevice(const char * label, const char * filename);
//     void write(const char * buffer, int size);
//     
    


/**
 *  This is a plugin for aiding in debugging guest code.
 *  XXX: To be replaced by gdb.
 */
class RemoteMemory : public Plugin
{
    S2E_PLUGIN
public:
    RemoteMemory(S2E* s2e): Plugin(s2e) {}
    virtual ~RemoteMemory();

    void initialize();
    /**
     * Called whenever memory is accessed.
     * This function checks the arguments and then calls memoryAccessed() with parsed arguments.
     */
    klee::ref<klee::Expr> slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        bool isWrite,
        bool isIO);
private:
    enum MemoryAccessType {EMemoryAccessType_None, EMemoryAccessType_Read, EMemoryAccessType_Write, EMemoryAccessType_Execute};
    
    /**
     * slotMemoryAccess forwards the call to this function after the arguments have been parsed and checked.
     */
    uint64_t memoryAccessed(S2EExecutionState *, uint64_t address, int width, uint64_t value, MemoryAccessType type);
    
    /**
     * Checks if a command has been received. If so, returns true, otherwise returns false.
     */
//    bool receiveCommand(json::Object& command);
    /**
     * Blocks until a response has been received.
     */
//    void receiveResponse(json::Object& response);
    
    void slotTranslateInstructionStart(ExecutionSignal* signal, 
            S2EExecutionState* state,
            TranslationBlock* tb,
            uint64_t pc);
    void slotExecuteInstructionStart(S2EExecutionState* state, uint64_t pc);
    
    bool m_verbose;
//    MemoryMonitor * m_memoryMonitor;
//    std::tr1::shared_ptr<QemuTcpServerSocket> m_serverSocket;
//    std::tr1::shared_ptr<QemuTcpSocket> m_remoteSocket;
    std::tr1::shared_ptr<RemoteMemoryInterface> m_remoteInterface;
    
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
