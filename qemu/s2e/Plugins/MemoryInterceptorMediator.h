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

#ifndef S2E_PLUGINS_EXAMPLE_H
#define S2E_PLUGINS_EXAMPLE_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
    
typedef sigc::functor_base<klee::ref< klee::Expr >, s2e::S2EExecutionState *, klee::ref< klee::Expr >, klee::ref< klee::Expr >, klee::ref< klee::Expr >, int, fsigc::nil, fsigc::nil>* MemoryAccessListener;

enum AccessType
{
    ACCESS_TYPE_READ = 0x1,
    ACCESS_TYPE_WRITE = 0x2,
    ACCESS_TYPE_EXECUTE = 0x4,
    ACCESS_TYPE_CONRETE_VALUE = 0x8,
    ACCESS_TYPE_SYMBOLIC_VALUE = 0x10,
    ACCESS_TYPE_CONCRETE_ADDRESS = 0x20,
    ACCESS_TYPE_SYMBOLIC_ADDRESS = 0x40,
    ACCESS_TYPE_NON_IO = 0x80,
    ACCESS_TYPE_IO = 0x100
};

struct MemoryInterceptorConfiguration
{
    uint64_t start;
    uint64_t end;
    int access_type;
    int priority;
};

//struct MemoryAccessListener {
//  klee::ref<klee::Expr> operator()(S2EExecutionState *state,
//        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
//        klee::ref<klee::Expr> hostaddr /* hostAddress */,
//        klee::ref<klee::Expr> value /* value */, int access_type) const;
//};

//klee::ref<klee::Expr> (*MemoryAccessListener)(S2EExecutionState *state,
//        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
//        klee::ref<klee::Expr> hostaddr /* hostAddress */,
//        klee::ref<klee::Expr> value /* value */,
//        bool isWrite,
//        bool isIO);

class MemoryInterceptor : public Plugin
{
    friend class MemoryInterceptorMediator;
public:
    MemoryInterceptor(S2E* s2e);
private:
    virtual klee::ref<klee::Expr> slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        int access_type) = 0;
};

class MemoryInterceptorMediator : public Plugin
{
    S2E_PLUGIN
public:
    MemoryInterceptorMediator(S2E* s2e): Plugin(s2e) {}
    klee::ref<klee::Expr> slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        bool isWrite,
        bool isIO);
    void initialize();
    void addInterceptor(MemoryInterceptor * listener);

private:
    std::vector< std::pair< MemoryInterceptor *, std::string > > m_listeners;
    std::map< std::string, std::vector< MemoryInterceptorConfiguration > > m_configuration;
    bool m_verbose;
}; 

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
