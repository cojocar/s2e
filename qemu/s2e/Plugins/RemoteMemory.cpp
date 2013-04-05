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

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu_socket.h>
#include <hw/irq.h>

#include <qint.h>
#include <qstring.h>
#include <qdict.h>
#include <qjson.h>
#include <qemu-thread.h>
}

#include "RemoteMemory.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <s2e/cajunjson/reader.h>
#include <s2e/cajunjson/writer.h>

#include <iostream>
#include <sstream>
#include <iomanip>

namespace s2e {
namespace plugins {
    
S2E_DEFINE_PLUGIN(RemoteMemory, "Asks a remote program what the memory contents actually should be", "RemoteMemory", "Initializer");

void RemoteMemory::initialize()
{
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    
    m_verbose =
        cfg->getBool(getConfigKey() + ".verbose", false, &ok);
      
    std::string serverSocketAddress = cfg->getString(getConfigKey() + ".listen", ":5555", &ok);
    
    m_remoteInterface = std::tr1::shared_ptr<RemoteMemoryInterface>(new RemoteMemoryInterface(s2e(), serverSocketAddress)); 
        
    //Connect memory access monitoring
    s2e()->getCorePlugin()->onDataMemoryAccess.connect(
          sigc::mem_fun(*this, &RemoteMemory::slotMemoryAccess));
          
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
          sigc::mem_fun(*this, &RemoteMemory::slotTranslateInstructionStart));
    
    if (m_verbose)
        s2e()->getDebugStream() << "[RemoteMemory]: initialized" << '\n';
}

RemoteMemory::~RemoteMemory()
{
}

void RemoteMemory::slotTranslateInstructionStart(ExecutionSignal* signal, 
            S2EExecutionState* state,
            TranslationBlock* tb,
            uint64_t pc)
{
    signal->connect(sigc::mem_fun(*this, &RemoteMemory::slotExecuteInstructionStart));    
}

void RemoteMemory::slotExecuteInstructionStart(S2EExecutionState* state, uint64_t pc)
{
    //TODO: Check if IRQ has arrived, and inject it
}

klee::ref<klee::Expr> RemoteMemory::slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        bool isWrite,
        bool isIO)
{
    //Catch all the cases that we don't handle (symbolic values, IO addresses)
    if (!isa<klee::ConstantExpr>(virtaddr))
    {
        s2e()->getWarningsStream()
            << "[RemoteMemory]: Unexpected symbolic address ("
            << virtaddr->getKind() << ")" << '\n';
        return value;
    }
      
    if (isIO)
    {
        s2e()->getWarningsStream() << "[RemoteMemory]: Unexpected access to IO memory" << '\n';
//        return;
    }
    
    if (!isa<klee::ConstantExpr>(value))
    {
        s2e()->getWarningsStream()
            << "[RemoteMemory]: Unexpected symbolic value ("
            << value->getKind() << ")" << '\n';
        return value;
    }
    
    MemoryAccessType accessType = EMemoryAccessType_None;
    uint64_t addr = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
    uint64_t width = value->getWidth() / 8;

    if (isWrite)
        accessType = EMemoryAccessType_Write;
    else
        if (addr == state->getPc())
            accessType = EMemoryAccessType_Execute;
        else 
            accessType = EMemoryAccessType_Read;
            
    uint64_t rValue = memoryAccessed(state, addr, width, cast<klee::ConstantExpr>(value)->getZExtValue(), accessType);    
    
    if (rValue != cast<klee::ConstantExpr>(value)->getZExtValue())
    {
        s2e()->getDebugStream() << "[RemoteMemory]: Returning different value " << hexval(rValue) << "[" << width 
            << "] instead of " << hexval(cast<klee::ConstantExpr>(value)->getZExtValue()) << "[" << (value->getWidth() / 8) << "]" << '\n';
        return klee::ConstantExpr::create(rValue, width * 8);
    }
    else
    {
        return value;
    }
}

uint64_t RemoteMemory::memoryAccessed(S2EExecutionState * state, uint64_t address, int size, uint64_t value, MemoryAccessType type)
{
    assert(size == 1 || size == 2 || size == 4 || size == 8);
    
    if (m_verbose)
    {
        s2e()->getDebugStream() << hexval(address)
                                << "["  << size 
                                << "] accessed for " 
                                << (type == EMemoryAccessType_Read ? "read" : (type == EMemoryAccessType_Write ? "write"  : "execute"))
                                << " with value " << hexval(value)  << '\n';
                                
    }
    
    if (type == EMemoryAccessType_Execute || type == EMemoryAccessType_Read)
    {
        return m_remoteInterface->readMemory(state, address, size);
    }
    else
    {
        m_remoteInterface->writeMemory(state, address, size, value);
        return 0;
    }
}

static std::string intToHex(uint64_t val)
{
    std::stringstream ss;
    
    ss << "0x" << std::hex << val;
    return ss.str();
}

static uint64_t hexBufToInt(std::string str)
{
    uint64_t val = 0;
    std::stringstream ss;
    
    ss << str;
    ss >> std::hex >> val;

    return val;
}

    
    

RemoteMemoryInterface::RemoteMemoryInterface(S2E* s2e, std::string remoteSockAddress) 
    : m_s2e(s2e), 
      m_cancelThread(false), 
      m_socket(std::tr1::shared_ptr<QemuTcpSocket>(new QemuTcpSocket())),
      m_state(NULL)
{   
    qemu_mutex_init(&m_mutex);
    qemu_cond_init(&m_responseCond);
    
    QemuTcpServerSocket serverSock(remoteSockAddress.c_str());
    m_s2e->getMessagesStream() << "[RemoteMemory]: Waiting for connection on " << remoteSockAddress << '\n';
    serverSock.accept(*m_socket);
    
    qemu_thread_create(&m_thread, &RemoteMemoryInterface::receiveThread, this, 0);
}

void * RemoteMemoryInterface::receiveThread(void * opaque)
{
    RemoteMemoryInterface * rmi = static_cast<RemoteMemoryInterface *>(opaque);
    while (!rmi->m_cancelThread)
    {
        std::string token;
            
        getline(*rmi->m_socket, token, '\n');
        
        if (token.size() == 0 && !rmi->m_socket->isConnected())
        {
            //TODO: do something to gracefully shutdown qemu (i,.e. unblock main thread, return dummy value, shutdown vm)
            rmi->m_s2e->getWarningsStream() << "[RemoteMemory] Remote end disconnected, machine is dead" << '\n';
            break;
        }
        
//        rmi->m_s2e->getMessagesStream() << "[RemoteMemory] received json: '" << token << "'" << '\n'; 
        
        rmi->parse(token);
    }
    
    return NULL;
}

void RemoteMemoryInterface::parse(std::string& token)
{
    std::tr1::shared_ptr<json::Object> jsonObject = std::tr1::shared_ptr<json::Object>(new json::Object());

    std::istringstream tokenAsStream(token);
    
    try
    {
        json::Reader::Read(*jsonObject, tokenAsStream);
        
        if(jsonObject->Find("reply") != jsonObject->End())
        {
            //TODO: notify and pass object
            qemu_mutex_lock(&m_mutex);
            m_responseQueue.push(jsonObject);
            qemu_cond_signal(&m_responseCond);
            qemu_mutex_unlock(&m_mutex);
        }
        else
        {
            try
            {
                json::Object::iterator itrCmd = jsonObject->Find("cmd");
                if (itrCmd == jsonObject->End())
                {
                    m_s2e->getWarningsStream() << "[RemoteMemory] Received json object that was neither a cmd nor a reply: " << token << '\n';
                    return;
                }
                
                json::String& cmd = itrCmd->element;
                
                handleClientCommand(cmd, jsonObject);
            }
            catch (json::Exception& ex)
            {
                m_s2e->getWarningsStream() << "[RemoteMemory] JSON exception while handling a command from the client" << '\n';
            }
        }
    }
    catch (json::Exception& ex)
    {
        m_s2e->getWarningsStream() <<  "[RemoteMemory] Exception in JSON data: '" << token << "'" << '\n';
    }
}

void RemoteMemoryInterface::handleClientCommand(std::string cmd, std::tr1::shared_ptr<json::Object> params)
{
    qemu_mutex_lock(&m_mutex);
    m_interruptQueue.push(params);
    qemu_mutex_unlock(&m_mutex);
}

  
/**
 * Calls the remote helper to read a value from memory.
 */
uint64_t RemoteMemoryInterface::readMemory(S2EExecutionState * state, uint32_t address, int size)
{
     json::Object request;
     json::Object params;
     json::Object cpu_state;
     
     m_s2e->getMessagesStream() << "[RemoteMemory] reading memory from address " << hexval(address) << "[" << size << "]" << '\n';
     request.Insert(json::Object::Member("cmd", json::String("read")));
     
     //HACK: Instead of using the physical address switch here, this should be specified somehow ...
     klee::ref<klee::Expr> exprValue = state->readMemory(address, size << 3, S2EExecutionState::PhysicalAddress);
     
     if (exprValue.isNull())
     {
         m_s2e->getMessagesStream() << "[RemoteMemory] Failed to read old memory value at address " << hexval(address) << '\n';
     }
     else if (isa<klee::ConstantExpr>(exprValue))
     {
         params.Insert(json::Object::Member("old_value", json::String(intToHex(cast<klee::ConstantExpr>(exprValue)->getZExtValue()))));
     }
     else
     {
         m_s2e->getMessagesStream() << "[RemoteMemory] Old value of memory at 0x" << hexval(address) << " is symbolic (currently not supported)" << '\n';
     }
         
     
     params.Insert(json::Object::Member("address", json::String(intToHex(address))));
     params.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
     //Build cpu state
#ifdef TARGET_ARM
#define CPU_NB_REGS 16
#endif
     for (int i = 0; i < CPU_NB_REGS - 1; i++)
     {
         std::stringstream ss;
         
         ss << "r";
         ss << i;
         
         klee::ref<klee::Expr> exprReg = state->readCpuRegister(CPU_REG_OFFSET(i), CPU_REG_SIZE << 3);
         if (isa<klee::ConstantExpr>(exprReg))
         {
             cpu_state.Insert(json::Object::Member(ss.str(), json::String(intToHex(cast<klee::ConstantExpr>(exprReg)->getZExtValue()))));
         }
         else
         {
             m_s2e->getMessagesStream() << "[RemoteMemory] Register " << i << " is symbolic (currently not supported)" << '\n';
         }
     }
     
     cpu_state.Insert(json::Object::Member("pc", json::String(intToHex(state->getPc()))));
     
#ifdef TARGET_ARM
     //TODO: Fill CPSR register
     
//     cpsr.Insert(json::Object::Member("cf", json::Bool(
     
     cpu_state.Insert(json::Object::Member("cpsr", json::String(intToHex(state->getFlags()))));
#endif
     
     request.Insert(json::Object::Member("params", params));
     request.Insert(json::Object::Member("cpu_state", cpu_state));

     qemu_mutex_lock(&m_mutex);
     m_state = state;
     
     json::Writer::Write(request, *m_socket);
     m_socket->flush();

     qemu_cond_wait(&m_responseCond, &m_mutex);
     
     //TODO: There could be multiple responses, but we assume the first is the right
     std::tr1::shared_ptr<json::Object> response = m_responseQueue.front();
     m_responseQueue.pop();
     m_state = NULL;
     qemu_mutex_unlock(&m_mutex);
     
     //TODO: No checking if this is the right response, if there is an attribute 'value'
     json::String& strValue = (*response)["value"];
//     m_s2e->getMessagesStream() << "[RemoteMemory] Remote returned value " << strValue << '\n';
     return hexBufToInt(strValue);
}
  
/**
 * Calls the remote helper to write a value to memory.
 * This method returns immediatly, as there is not return value to wait for.
 */
void RemoteMemoryInterface::writeMemory(S2EExecutionState * state, uint32_t address, int size, uint64_t value)
{
}

RemoteMemoryInterface::~RemoteMemoryInterface()
{
    qemu_cond_destroy(&m_responseCond);
    qemu_mutex_destroy(&m_mutex);
}

} /* namespace plugins */
} /* namespace s2e */
