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
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#ifndef S2E_PLUGINS_MEMORY_MONITOR_H
#define S2E_PLUGINS_MEMORY_MONITOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <map>

namespace s2e {
namespace plugins {

inline static std::pair<uint64_t, uint64_t> make_range(uint64_t x, uint64_t y)
{
    return x < y ? std::make_pair(x, y) : std::make_pair(y, x);
}

struct range_less
{
    bool operator()(const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b)
    {
        return a.second < b.first;
    }
};
    

class MemoryMonitor : public Plugin
{
    S2E_PLUGIN
public:
    typedef enum
        {
          EMemoryRead = 0x1,
          EMemoryWrite = 0x2,
          EMemoryExecute = 0x4,
          EMemorySymbolic = 0x8,
          EMemoryConcrete = 0x10,
          EMemoryIO = 0x20,
          EMemoryNotIO = 0x40
        } MemoryAccessType;

    typedef sigc::signal<void, S2EExecutionState*,
        uint64_t /* address */,
        klee::ref<klee::Expr> /* value */,
        int /*type*/ > MemoryAccessSignal;
    typedef sigc::functor_base<void, s2e::S2EExecutionState *, unsigned long, klee::ref<klee::Expr>, int, sigc::nil, sigc::nil, sigc::nil> * MemoryAccessHandlerPtr;
//    typedef sigc::slot<void, S2EExecutionState *, uint64_t, klee::ref<klee::Expr>, MemoryAccessType> MemoryAccessSlot;


    class MemoryWatch
    {
    public:
      MemoryWatch(uint64_t start,
          uint64_t size,
          int type,
          MemoryAccessHandlerPtr handler);
      int type;
      uint64_t start;
      uint64_t size;
      MemoryAccessSignal signal;
    };

    MemoryMonitor(S2E* s2e);
    ~MemoryMonitor();

    void initialize();
    klee::ref<klee::Expr> slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */,
        bool isWrite,
        bool isIO);
    void addWatch(uint64_t start,
        uint64_t length,
        int type,
        MemoryAccessHandlerPtr handler);
    void removeWatch(uint64_t start, uint64_t length);

private:
    std::multimap<std::pair<uint64_t, uint64_t>, MemoryWatch, range_less> watches;
    int m_verbose;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
