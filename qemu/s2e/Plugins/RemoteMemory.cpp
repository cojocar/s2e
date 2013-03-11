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
}

#include "RemoteMemory.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <s2e/cajunjson/reader.h>
#include <s2e/cajunjson/writer.h>

//#include <s2e/cajunjson/writer.h>
//#include <s2e/cajunjson/reader.h>

#include <iostream>
#include <sstream>

namespace s2e {
namespace plugins {
    
S2E_DEFINE_PLUGIN(RemoteMemory, "Asks a remote program what the memory contents actually should be", "RemoteMemory", "MemoryMonitor", "Initializer");

/*
static std::string toHexString(uint64_t val)
{
    std::stringstream ss;
    
    ss << "0x" << hexval(val;
    return ss.str();
}

static uint64_t parseHexString(std::string& str)
{
    std::stringstream ss;
    uint64_t result;
    
    if (str.find("0x") != 0)
        return 0; //TODO: Error
        
    ss << str.substr(2);
    ss >> result;
    
    return result;
}
*/
void RemoteMemory::initialize()
{
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    
    m_verbose =
        cfg->getBool(getConfigKey() + ".verbose", false, &ok);
      
    std::string serverSocketAddress = cfg->getString(getConfigKey() + ".listen", ":5555", &ok);
    
    m_remoteInterface = std::tr1::shared_ptr<RemoteMemoryInterface>(new RemoteMemoryInterface(s2e(), serverSocketAddress));
/*
    s2e()->getMessagesStream() << "[RemoteMemory]: Waiting for connection on r/w " << serverSocketAddress << '\n';
    
    
    m_serverSocket = std::tr1::shared_ptr<QemuTcpServerSocket>(new QemuTcpServerSocket(serverSocketAddress.c_str()));
    m_remoteSocket = std::tr1::shared_ptr<QemuTcpSocket>(new QemuTcpSocket());
    
    
    m_serverSocket->accept(*m_remoteSocket);
    
    s2e()->getDebugStream() << "[RemoteMemory]: Client connected from " << m_remoteSocket->getRemoteAddress()->toString() << " to r/w socket" << '\n';
  */  
        
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

static bool writeMemory(s2e::S2EExecutionState* state, uint64_t address,
        uint64_t width, uint64_t val)
    {
        std::cout << "Writing memory at address " << hexval(address) << ", width "  << width << ", value " << hexval(val) << '\n';
      switch (width)
      {
      case klee::Expr::Int8:
        return state->writeMemory8(address, static_cast<uint8_t>(val)); 
      case klee::Expr::Int16:
        return state->writeMemory16(address, static_cast<uint16_t>(val));
      case klee::Expr::Int32:
        return state->writeMemory32(address, static_cast<uint32_t>(val));
      case klee::Expr::Int64:
        return state->writeMemory64(address, val);
      default: 
          
    /*    s2e()->getWarningsStream() << '\n'; "Unknown width "  << width
            << " for write at address 0x" << hexval(address 
            << '\n'; */
        return false;
      }
    }

void RemoteMemory::slotMemoryAccess(S2EExecutionState *state,
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
        return;
    }
      
    if (isIO)
    {
        s2e()->getWarningsStream() << "[RemoteMemory]: Unexpected access to IO memory" << '\n';
        return;
    }
    
    if (!isa<klee::ConstantExpr>(value))
    {
        s2e()->getWarningsStream()
            << "[RemoteMemory]: Unexpected symbolic value ("
            << value->getKind() << ")" << '\n';
        return;
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
            
    uint64_t rValue = memoryAccessed(addr, width, cast<klee::ConstantExpr>(value)->getZExtValue(), accessType);    
    
    if (rValue != cast<klee::ConstantExpr>(value)->getZExtValue())
    {
        writeMemory(state, addr, width * 8, rValue);
    }
}

/**
 * Checks if a command has been received. If so, returns true, otherwise returns false.
 */
//bool RemoteMemory::receiveCommand(json::Object& command)
//{
//    return false;
//}

/**
 * Blocks until a response has been received.
 */

// void RemoteMemory::receiveResponse(json::Object& response)
// {
//     try
//     {
//         std::string responseString;
//         
//         getline(*m_remoteSocket, responseString);
//         std::cout << "Got response: " << responseString << '\n';
//         std::istringstream iResponseStream(responseString);
//         
//         json::Reader::Read(response, iResponseStream);
// 
//     }
//     catch (SocketException& ex)
//     {
//         std::cout << "EXCEPTION: " << ex.what() << " with error code " << strerror(ex.error_code()) << '\n';
//     }
//     if (response.Find("reply") != response.End())
//     {
//         return;
//     }
//     else
//     {
//         //TODO
//     }
// }
// 
//     template<class T>
//     struct TypeName
//     {
//         static std::string get()
//         {
//             char const * begin = 0;
//             char const * end = 0;
//             
//             begin = __FUNCTION__;
//             for(++begin; *begin && *(begin-1) != '<'; ++ begin);
//             for(end = begin; *end; ++ end);
//             for(; end > begin && *end != '>'; -- end);
//             
//             return std::string(begin, end - begin);
//         }
//     };
// 
//     class MessageValue
//     {
//     public:
//         virtual size_t getSize() = 0;
//         virtual char * getData() = 0;
//         virtual std::string const& getName() = 0; 
//         virtual std::string getTypeName() = 0;
//     };
//         
// 
//     template<typename Type>
//     class SimpleMessageValue : public MessageValue
//     {
//     public:
//         SimpleMessageValue(Type value, std::string name) : m_value(value), m_name(name) {}
//         SimpleMessageValue(char * data, std::string name) : m_value(0), m_name(name) {memcpy(&m_value, data, getSize());}
//         virtual size_t getSize() { return sizeof(Type); }
//         virtual char * getData() { return reinterpret_cast<char *>(&m_value); }
//         virtual std::string const& getName() {return m_name;}
//         virtual std::string getTypeName() {return TypeName<Type>::get();}
//         Type getValue() { return m_value;}
//     private:
//         Type m_value;    
//         std::string m_name;
//     };
// 
// 
// 
//     class Message
//     {
//     public:
//         Message(uint32_t command) : m_command(command) {}
//         uint32_t getCommand() {return m_command;}
//         size_t getSize() 
//         {
//             size_t size = 0;
//             
//             for (std::deque< std::shared_ptr<MessageValue> >::iterator itr = m_values.begin(); itr != m_values.end(); itr++)
//                 size += (*itr)->getSize();
//             
//             return size;
//         }
//         
//         void operator<<(std::shared_ptr<MessageValue> val) {m_values.push_back(val);}
//         void operator>>(std::shared_ptr<MessageValue> val) {val = *m_values.begin(); m_values.pop_front();}
//         
//         void output(std::ostream& stream)
//         {
//             uint32_t length = getSize();
//             
//             stream.write(reinterpret_cast<char *>(&m_command), sizeof(uint32_t));
//             stream.write(reinterpret_cast<char *>(&length), sizeof(uint32_t));
//             
//             for (std::deque< std::shared_ptr<MessageValue> >::iterator itr = m_values.begin(); itr != m_values.end(); itr++)
//                 stream.write((*itr)->getData(), (*itr)->getSize());
//         }
//         
//         virtual void input(std::istream& stream) = 0;
//             
//         
//     protected:
//         std::deque<std::shared_ptr<MessageValue> > m_values;
//         uint32_t m_command;
//     };
// 
//     class ReadMemoryMessage : public Message
//     {
//     public:
//         ReadMemoryMessage(uint32_t address, uint8_t width) : Message(1)
//         {
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(address, "address"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint8_t>(width, "width"));
//         }
//         
//         virtual void input(std::istream& stream)
//         {
//             uint32_t length;
//             uint32_t address;
//             uint8_t width;
//             
//             stream.read(reinterpret_cast<char *>(&length), sizeof(uint32_t));
//             m_values.erase(m_values.begin(), m_values.end());
//             stream.read(reinterpret_cast<char *>(&address), sizeof(uint32_t));
//             stream.read(reinterpret_cast<char *>(&width), sizeof(uint8_t));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(address, "address"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint8_t>(width, "width"));
//         }
//     };
//     
//     class ReadMemoryReply : public Message
//     {
//     public:
//         ReadMemoryReply() : Message(1000) {}
//         virtual void input(std::istream& stream)
//         {
//             uint32_t length;
//             uint32_t address;
//             uint8_t width;
//             uint32_t value;
//             
//             stream.read(reinterpret_cast<char *>(&length), sizeof(uint32_t));
//             m_values.erase(m_values.begin(), m_values.end());
//             stream.read(reinterpret_cast<char *>(&address), sizeof(uint32_t));
//             stream.read(reinterpret_cast<char *>(&width), sizeof(uint8_t));
//             stream.read(reinterpret_cast<char *>(&value), sizeof(uint32_t));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(address, "address"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint8_t>(width, "width"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(value, "value"));
//         }
//     };
//     
//     class WriteMemoryMessage : public Message
//     {
//     public:
//         WriteMemoryMessage(uint32_t address, uint8_t width, uint32_t value) : Message(1)
//         {
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(address, "address"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint8_t>(width, "width"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(value, "value"));
//         }
//         
//         virtual void input(std::istream& stream)
//         {
//             uint32_t length;
//             uint32_t address;
//             uint8_t width;
//             uint32_t value;
//             
//             stream.read(reinterpret_cast<char *>(&length), sizeof(uint32_t));
//             m_values.erase(m_values.begin(), m_values.end());
//             stream.read(reinterpret_cast<char *>(&address), sizeof(uint32_t));
//             stream.read(reinterpret_cast<char *>(&width), sizeof(uint8_t));
//             stream.read(reinterpret_cast<char *>(&value), sizeof(uint32_t));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(address, "address"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint8_t>(width, "width"));
//             *this << std::shared_ptr<MessageValue>(new SimpleMessageValue<uint32_t>(value, "value"));
//         }
//     };
//     
//     
//     void operator<<(QemuTcpSocket& sock, Message& msg) {msg.output(sock);}
//     void operator>>(QemuTcpSocket& sock, Message& msg) {msg.input(sock);}
//     
//     
//     
// 
uint64_t RemoteMemory::memoryAccessed(uint64_t address, int size, uint64_t value, MemoryAccessType type)
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
        return m_remoteInterface->readMemory(address, size);
    }
    else
    {
        m_remoteInterface->writeMemory(address, size, value);
        return 0;
    }
}
                                
//                                 
//     if (width > 64 || ((width / 8) * 8 != width))
//     {
//         std::cout << "[RemoteMemory]: Ungood memory width "  << width << '\n';
//         return 0;
//     }
//     
//     if (type == EMemoryAccessType_Execute || type == EMemoryAccessType_Read)
//     {
//         ReadMemoryMessage msg(static_cast<uint32_t>(address), static_cast<uint8_t>(width));
//         ReadMemoryReply reply;
//         
//         try
//         {
//             uint32_t response;
//             uint32_t length;
//             uint32_t rAddress;
//             uint8_t rWidth;
//             uint64_t rValue;
//             size_t read_length;
//             
//             *m_remoteSocket << msg;
//             m_remoteSocket->flush();
// 
//             read_length = 4;
//             m_remoteSocket->read(reinterpret_cast<char *>(&response), read_length);
//             read_length = 4;
//             m_remoteSocket->read(reinterpret_cast<char *>(&length), read_length);
//             read_length = 4;
//             m_remoteSocket->read(reinterpret_cast<char *>(&rAddress), read_length);
//             read_length = 1;
//             m_remoteSocket->read(reinterpret_cast<char *>(&rWidth), read_length);
//             read_length = rWidth;
//             m_remoteSocket->read(reinterpret_cast<char *>(&rValue), read_length);
//             std::cout << "Received response "  << response << " with length "  << length << '\n';
//             
//             return rValue;
//         }
//         catch (SocketException& ex)
//         {
//             s2e()->getWarningsStream() << "Socket exception in RemoteStateSynchronizer::memoryAccessed:"  << __LINE__ << ": " << ex.what() << " with error code " << ex.error_code() << '\n';
//         }
//  /*       
//         json::Object jsonDocument;
//         
//         jsonDocument.Insert(json::Object::Member("cmd", json::String("mem_read")));
//         jsonDocument.Insert(json::Object::Member("address", json::String(toHexString(address))));
//         jsonDocument.Insert(json::Object::Member("width", json::String(toHexString(width))));
//         
//         json::Writer::Write(jsonDocument, *m_remoteSocket);
//         
//         //TODO: Receive memory content from remote
//         receiveResponse(jsonDocument);
//         json::String& valueString = jsonDocument["value"];
//         std::string& stdValueString = valueString;
//         std::cout << "Received value " << stdValueString << " for address 0x" << hexval(address << '\n'; 
//         return parseHexString(valueString); */
//     }
//     else if (type == EMemoryAccessType_Write)
//     {
//         WriteMemoryMessage msg(static_cast<uint32_t>(address), static_cast<uint8_t>(width), static_cast<uint32_t>(value));
//         
//         try
//         {
//             *m_remoteSocket << msg;
//             m_remoteSocket->flush();
//         }
//         catch (SocketException& ex)
//         {
//             s2e()->getWarningsStream() << "Socket exception in RemoteStateSynchronizer::memoryAccessed:"  << __LINE__ << ": " << ex.what() << " with error code " << ex.error_code() << '\n';
//         }
//  /*       json::Object jsonDocument;
//         
//         jsonDocument.Insert(json::Object::Member("cmd", json::String("mem_write")));
//         jsonDocument.Insert(json::Object::Member("address", json::String(toHexString(address))));
//         jsonDocument.Insert(json::Object::Member("width", json::String(toHexString(width))));
//         jsonDocument.Insert(json::Object::Member("value", json::String(toHexString(width))));
//         
//         json::Writer::Write(jsonDocument, *m_remoteSocket); */
//         return value;
//     }
//     /* Should not be reached */ 
//     return 0;
//         
// }

extern "C" {
    static int remote_mem_can_receive(void * opaque)
    {
        //We can always receive arbitrary amounts
        return 255;
    }

    static void remote_mem_chr_receive(void * opaque, const uint8_t * buf, int size)
    {
        static_cast<RemoteMemoryInterface *>(opaque)->receive(buf, size);
    }

    static void remote_mem_chr_event(void * opaque, int event)
    {
    }
}

RemoteMemoryInterface::RemoteMemoryInterface(S2E* s2e, std::string remoteSockAddress) : m_s2e(s2e), m_chrdev(0)
{
    m_s2e->getMessagesStream() << "[RemoteMemory]: Waiting for connection on " << remoteSockAddress << '\n';
    
    qemu_mutex_init(&m_mutex);
    qemu_cond_init(&m_responseCond);
    
    if (remoteSockAddress.find(",server") == std::string::npos)
    {
        remoteSockAddress = remoteSockAddress + ",server";
    }
    
    this->m_chrdev = qemu_chr_new("mem_remote_if", remoteSockAddress.c_str(), NULL);
    
    if (!this->m_chrdev)
    {
        m_s2e->getWarningsStream() << "[RemoteMemory]: Qemu chardev creation failed" << '\n';
    }
    qemu_chr_add_handlers(this->m_chrdev, remote_mem_can_receive, remote_mem_chr_receive, remote_mem_chr_event, this);
    
//    QemuTcpServerSocket serverSock = QemuTcpServerSocket(remoteSockAddress.c_str());
//    this->m_sock = std::tr1::shared_ptr<QemuTcpSocket>(new QemuTcpSocket());
    
    
//    serverSock.accept(*m_sock);
    
//    s2e->getDebugStream() << "[RemoteMemory]: Client connected from " << m_sock->getRemoteAddress()->toString() << " to socket" << '\n';
}

void RemoteMemoryInterface::receive(const uint8_t * data, int len)
{
    m_s2e->getMessagesStream() << "[RemoteMemory] received data: '" << std::string(reinterpret_cast<const char *>(data), len) << "'" << '\n';
    m_receiveBuffer << std::string(reinterpret_cast<const char *>(data), len);
    parse();
}

void RemoteMemoryInterface::parse(void)
{
    while (m_receiveBuffer.str().find_first_of("\n") != std::string::npos)
    {
        std::string token;
        std::tr1::shared_ptr<json::Object> jsonObject = std::tr1::shared_ptr<json::Object>(new json::Object());
        
        getline(m_receiveBuffer, token, '\n');
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
                qemu_mutex_lock(&m_mutex);
                m_eventQueue.push(jsonObject);
                qemu_mutex_unlock(&m_mutex);
            }
        }
        catch (json::Exception& ex)
        {
            m_s2e->getWarningsStream() <<  "[RemoteMemory] Exception in JSON data: '" << token << "'" << '\n';
        }
            
//        std::istringstream iResponseStream(token);
//         
//         json::Reader::Read(response, iResponseStream);
//        QObject * obj= qobject_from_jsonf("%s", token.c_str());
//        if (obj && qobject_type(obj) == QTYPE_QDICT)
//        {
//            QDict * dict = qobject_to_qdict(obj);
//            
//            m_eventQueue.push_
//            reply = qdict_get_try_str(dict, "reply");
 //           
 //       }
        
        
//        qobject_decref(obj);
    }
}

static std::string intToHex(uint64_t val)
{
    std::stringstream ss;
    
    ss << "0x" << std::hex << val;
    return ss.str();
}

static uint64_t hexToInt(std::string str)
{
    std::stringstream ss;
    uint64_t val;
    
    ss << str.substr(2, std::string::npos);
    ss >> std::hex >> val;
    
    return val;
}
  
/**
 * Calls the remote helper to read a value from memory.
 */
uint64_t RemoteMemoryInterface::readMemory(uint32_t address, int size)
{
     json::Object request;
     
     m_s2e->getMessagesStream() << "[RemoteMemory] reading memory from address " << hexval(address) << "[" << size << "]" << '\n';
     request.Insert(json::Object::Member("cmd", json::String("read")));
     request.Insert(json::Object::Member("address", json::String(intToHex(address))));
     request.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
     std::ostringstream ss;
     json::Writer::Write(request, ss); 
     qemu_mutex_lock(&m_mutex);
     qemu_chr_fe_write(m_chrdev, reinterpret_cast<const uint8_t *>(ss.str().c_str()), ss.str().size());
     qemu_cond_wait(&m_responseCond, &m_mutex);
     
     //TODO: There could be multiple responses, but we assume the first is the right
     std::tr1::shared_ptr<json::Object> response = m_responseQueue.front();
     m_responseQueue.pop();
     qemu_mutex_unlock(&m_mutex);
     
     //TODO: No checking if this is the right response, if there is an attribute 'value'
     json::String& strValue = (*response)["value"];
     m_s2e->getMessagesStream() << "[RemoteMemory] Remote returned value " << strValue << '\n';
     return hexToInt(strValue);
}
  
/**
 * Calls the remote helper to write a value to memory.
 * This method returns immediatly, as there is not return value to wait for.
 */
void RemoteMemoryInterface::writeMemory(uint32_t address, int size, uint64_t value)
{
//     QDict * dict = qdict_new();
//     QString * str;
//     
//     qdict_put(dict, "cmd", qstring_from_str("write"));
//     qdict_put(dict, "address", qint_from_int(address));
//     qdict_put(dict, "size", qint_from_int(size));
//     qdict_put(dict, "value", qint_from_int(value));
//     
//     str = qobject_to_json(QOBJECT(dict));
//     try
//     {
//         *m_sock << qstring_get_str(str) << '\n';
//         m_sock->flush();
//     }
//     catch(SocketException& ex)
//     {
//         //TODO: Handle exception
//     }
    
//     QDECREF(dict);
//     QDECREF(str);
}

QDict * RemoteMemoryInterface::getReply()
{
    QDict * dict;
    QObject * obj;
    const char *reply;
    
//    try
//     {
         std::string responseString;
         
         //returns when reply is received
         while (true)
         {
//            getline(*m_sock, responseString);
            
            obj = qobject_from_jsonf("%s", responseString.c_str());
            if (obj && qobject_type(obj) == QTYPE_QDICT)
            {
                dict = qobject_to_qdict(obj);
                reply = qdict_get_try_str(dict, "reply");
                
                if (reply)
                {
                    return dict;
                }
                else
                {
                    //TODO: Queue object in to-handle queue
                }
            }
         }
//     }
//     catch (SocketException& ex)
//     {
//         m_s2e->getWarningsStream() << "EXCEPTION: " << ex.what() << " with error code " << strerror(ex.error_code()) << '\n';
//         return NULL;
//     }
}

// QDict * RemoteMemoryInterface::getEvent()
// {
//     
// }

RemoteMemoryInterface::~RemoteMemoryInterface()
{
    qemu_cond_destroy(&m_responseCond);
    qemu_mutex_destroy(&m_mutex);
    qemu_chr_delete(m_chrdev);
}

} /* namespace plugins */
} /* namespace s2e */