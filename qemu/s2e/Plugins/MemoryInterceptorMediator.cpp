/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
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
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "MemoryInterceptorMediator.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

    
/*
 * Example configuration:
 *      {
 *          RemoteMemory = {
 *              ranges = {
 *                  range1 = {
 *                      range_start = 0x400D3000,
 *                      range_end = 0x400D4000},
 *                      access_type = {"read", "io", "memory", "concrete_address", "concrete_value", "symbolic_value"}
 *                  },
 *                  range2 = {
 *                      range_start = 0x400E000,
 *                      range_end = 0x400DF000}
 *              },
 *              
 */

S2E_DEFINE_PLUGIN(MemoryInterceptorMediator, "Plugin to coordinate which onDataMemoryAccess events are forwarded to which interceptors", "MemoryInterceptorMediator");

MemoryInterceptor::MemoryInterceptor(S2E* s2e): Plugin(s2e) {}

void MemoryInterceptorMediator::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();
      bool ok;

    m_verbose =
          cfg->getBool(getConfigKey() + ".verbose", false, &ok) ? 1 : 0;
          
    std::vector<std::string> plugins_keys = cfg->getListKeys(getConfigKey() + ".interceptors", &ok);
    
    if (!ok)
    {
        s2e()->getWarningsStream() << "[MemoryInterceptorMediator] Error reading subkey .interceptors" << '\n';
        return;
    }
    
    for (std::vector<std::string>::iterator plugins_itr = plugins_keys.begin();
         plugins_itr != plugins_keys.end();
         plugins_itr++)
    {
        std::vector<std::string> ranges_keys = cfg->getListKeys(getConfigKey() + ".interceptors." + *plugins_itr, &ok);
        this->m_configuration[*plugins_itr] = std::vector< MemoryInterceptorConfiguration >();
        if (!ok)
        {
            s2e()->getWarningsStream() << "[MemoryInterceptorMediator] Error reading subkey .interceptors." << *plugins_itr << '\n';
            return;
        }
        
        for (std::vector<std::string>::iterator ranges_itr = ranges_keys.begin();
             ranges_itr != ranges_keys.end();
             ranges_itr++)
        {
            std::string interceptor_key = getConfigKey() + ".interceptors." + *plugins_itr + "." + *ranges_itr;
            
            if (!cfg->hasKey(interceptor_key + ".range_start") || 
                !cfg->hasKey(interceptor_key + ".range_end") || 
                !cfg->hasKey(interceptor_key + ".access_type"))
            {
                s2e()->getWarningsStream() << "[MemoryInterceptorMediator] Error: subkey .range_start, .range_end or .access_type for key "<< interceptor_key << " missing!" << '\n';
                return;
            }
            
            uint64_t start = cfg->getInt(interceptor_key + ".range_start");
            uint64_t end = cfg->getInt(interceptor_key + ".range_end");
            int priority = cfg->getInt(interceptor_key + ".priority");
            const std::vector< std::string > access_types = cfg->getStringList(interceptor_key + ".access_type", std::vector< std::string >(), &ok);
            int access_type = 0;
            for (std::vector< std::string >::const_iterator access_type_itr = access_types.begin();
                 access_type_itr != access_types.end();
                 access_type_itr++)
            {
                if (*access_type_itr == "read")
                    access_type |= ACCESS_TYPE_READ;
                else if (*access_type_itr == "write")
                    access_type |= ACCESS_TYPE_WRITE;
                else if (*access_type_itr == "execute")
                    access_type |= ACCESS_TYPE_EXECUTE;
                else if (*access_type_itr == "io")
                    access_type |= ACCESS_TYPE_IO;
                else if (*access_type_itr == "memory")
                    access_type |= ACCESS_TYPE_NON_IO;
                else if (*access_type_itr == "concrete_value")
                    access_type |= ACCESS_TYPE_CONRETE_VALUE;
                else if (*access_type_itr == "symbolic_value")
                    access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;
                else if (*access_type_itr == "concrete_address")
                    access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
                else if (*access_type_itr == "symbolic_address")
                    access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;
            }
            
            s2e()->getMessagesStream() << "[MemoryInterceptorMediator] Memory range " << hexval(start) << "-" << hexval(end) << " monitored by " << *plugins_itr 
                << " with priority " << priority << ", access_type " << hexval(access_type) << '\n';
            MemoryInterceptorConfiguration cfg = {/* .start = */ start, /* .end = */ end, /* .access_type = */ access_type, /* .priority = */ priority};
            this->m_configuration[*plugins_itr].push_back( cfg );
        }
    }
          
    s2e()->getCorePlugin()->onDataMemoryAccess.connect(
            sigc::mem_fun(*this, &MemoryInterceptorMediator::slotMemoryAccess));
}

static bool MemoryInterceptorConfiguration_priority_compare(std::pair< klee::ref< klee::Expr >, int > const& a, std::pair< klee::ref< klee::Expr >, int > const& b)
{
    return a.second > b.second;
}

klee::ref<klee::Expr> MemoryInterceptorMediator::slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        bool is_write,
        bool is_io)
{
    int access_type = 0;
    std::vector< std::pair< klee::ref< klee::Expr >, int > > results;
    bool is_concrete_address = false;
    uint64_t address = 0;
    
    if (is_write)
        access_type |= ACCESS_TYPE_WRITE;
    else
        access_type |= ACCESS_TYPE_READ;
    
    if (is_io)
        access_type |= ACCESS_TYPE_IO;
    else
        access_type |= ACCESS_TYPE_NON_IO;
    
    if (isa<klee::ConstantExpr>(virtaddr))
    {
        is_concrete_address = true;
        address = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
        access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
    }
    else
        access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;
    
    if (isa<klee::ConstantExpr>(value))
        access_type |= ACCESS_TYPE_CONRETE_VALUE;
    else
        access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;
    
    if (this->m_verbose)
    {
        s2e()->getDebugStream() << "[MemoryInterceptorMediator] slotMemoryAccess called with address " << hexval(address) 
            << (is_concrete_address ? " [concrete]" : " [symbolic]") << ", access_type " << hexval(access_type) << '\n';
    }
    
    for (std::vector< std::pair< MemoryInterceptor *, std::string > >::iterator listener_itr = this->m_listeners.begin();
         listener_itr != this->m_listeners.end();
         listener_itr++)
    {
        std::map< std::string, std::vector< MemoryInterceptorConfiguration > >::iterator conf_itr = this->m_configuration.find(listener_itr->second);
        
        if (conf_itr == this->m_configuration.end())
        {
            s2e()->getWarningsStream() << "[MemoryInterceptorMediator] Plugin " << listener_itr->second << " has been registered but is not specified in the configuration" << '\n';
            continue;
        }
        
        for (std::vector< MemoryInterceptorConfiguration >::iterator ranges_itr = conf_itr->second.begin();
            ranges_itr != conf_itr->second.end();
            ranges_itr++)
        {
            if ((ranges_itr->access_type & access_type) == access_type)
            {
                if (is_concrete_address && ranges_itr->start <= address && address <= ranges_itr->end)
                {
                    if (this->m_verbose)
                    {
                        s2e()->getDebugStream() << "[MemoryInterceptorMediator] calling subordinate plugin " << listener_itr->second << '\n';
                    }
                    results.push_back(std::make_pair(listener_itr->first->slotMemoryAccess(state, virtaddr, hostaddr, value, access_type), ranges_itr->priority));
                }
                else if (!is_concrete_address)
                {
                    results.push_back(std::make_pair(listener_itr->first->slotMemoryAccess(state, virtaddr, hostaddr, value, access_type), ranges_itr->priority));
                }
            }
        }
    }
   
    std::sort(results.begin(), results.end(), MemoryInterceptorConfiguration_priority_compare);
    
    for (std::vector< std::pair< klee::ref< klee::Expr >, int > >::iterator itr = results.begin();
         itr != results.end();
         itr++)
    {
        if (!itr->first.isNull())
        {
            return itr->first;
        }
    }
   
    return klee::ref< klee::Expr >(); 
}

void MemoryInterceptorMediator::addInterceptor(MemoryInterceptor * listener)
{
    std::string name = listener->getPluginInfo()->name;
    
    if (this->m_configuration.find(name) == this->m_configuration.end())
    {
        s2e()->getWarningsStream() << "[MemoryInterceptorMediator] A listener has been added that is not specified in the configuration" << '\n';
    }
    else
    {
        s2e()->getDebugStream() << "[MemoryInterceptorMediator] Registering new memory access listener \"" << name << '\n';
        this->m_listeners.push_back(std::make_pair(listener, name));
    }
}

} // namespace plugins
} // namespace s2e
