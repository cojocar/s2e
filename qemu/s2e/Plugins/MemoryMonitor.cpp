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

#include "MemoryMonitor.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

#define nullptr (0)

namespace s2e
{
  namespace plugins
  {

    S2E_DEFINE_PLUGIN(MemoryMonitor,
        "Plugin for monitoring memory regions with less performance impact", "",
        );

    MemoryMonitor::MemoryWatch::MemoryWatch(uint64_t start, uint64_t size,
        int type, MemoryAccessHandlerPtr handler) :
        type(type), start(start), size(size)
    {
      signal.connect(handler);
    }

    void
    MemoryMonitor::initialize()
    {
      ConfigFile *cfg = s2e()->getConfig();
      bool ok;

      m_verbose =
          cfg->getBool(getConfigKey() + ".verbose", false, &ok);
          
      

      s2e()->getCorePlugin()->onDataMemoryAccess.connect(
          sigc::mem_fun(*this, &MemoryMonitor::slotMemoryAccess));

      if (m_verbose)
          s2e()->getDebugStream() << "[MemoryMonitor]: initialized" << '\n';
    }

    MemoryMonitor::MemoryMonitor(S2E* s2e) :
        Plugin(s2e)
    {
//      for (uint64_t i = 0; i < PAGE_DIRECTORY_SIZE; i++)
//      {
//        pageDirectory[i] = nullptr;
//      }

    }

    MemoryMonitor::~MemoryMonitor()
    {
//      for (uint64_t i = 0; i < PAGE_DIRECTORY_SIZE; i++)
//      {
//        if (pageDirectory[i])
//        {
//          delete pageDirectory[i];
//          pageDirectory[i] = nullptr;
//        }
//      }
    }

    klee::ref<klee::Expr>
    MemoryMonitor::slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */, bool isWrite, bool isIO)
    {
      if (!isa<klee::ConstantExpr>(virtaddr))
      {
        s2e()->getWarningsStream()
            << "[MemoryMonitor]: Address is not constant ("
            << virtaddr->getKind() << ")" << '\n';
        return value;
      }
      uint64_t addr = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
      uint64_t size = value->getWidth() / 8;

      int access = (isWrite ? EMemoryWrite : EMemoryRead) | 
                   (state->getPc() == addr ? EMemoryExecute : 0) |
                   (isIO ? EMemoryIO : EMemoryNotIO) | 
                   (isa<klee::ConstantExpr>(value) ? EMemoryConcrete : EMemorySymbolic);
                   
      s2e()->getDebugStream() << "[MemoryMonitor] Memory access at " << hexval(addr) << "[" << size << "] " << (isWrite ? "write" : "read") << '\n';
      //TODO: End of address range (addr + width) should be checked too, but for now we assume
      //that it will be on the same page
//      std::vector<MemoryWatch> * watches = pageDirectory[addr
//          / MEMORY_MONITOR_GRANULARITY];
      for (std::map<std::pair<uint64_t, uint64_t>, MemoryWatch>::iterator itr = this->watches.find(std::make_pair(addr, addr));
           itr != this->watches.end(); 
           itr++)
      {
          if ((access & itr->second.type) == access)
          {
              if (m_verbose > 0)
                s2e()->getDebugStream()
                    << "[MemoryMonitor]: Found watch (start=" 
                    << hexval(itr->second.start) << ",sizeq=" << hexval(itr->second.size)
                    << ",type=" << hexval(itr->second.type)
                    << ") when address " << hexval(addr) << "["
                    << size << "] access type 0x" 
                    << hexval(access) << " was hit" << '\n';

              itr->second.signal.emit(state, addr, value, access);
          }
      }
      
      return value;

    }

    void
    MemoryMonitor::addWatch(uint64_t start, uint64_t size,
        int type, MemoryAccessHandlerPtr handler)
    {
      assert(size <= 8);
      
      this->watches.insert(std::make_pair(make_range(start, start + size), MemoryWatch(start, size, type, handler))); 
    }

    void
    MemoryMonitor::removeWatch(uint64_t start, uint64_t size)
    {
        assert(size <= 8);
      
        for (std::map<std::pair<uint64_t, uint64_t>, MemoryWatch>::iterator itr = this->watches.find(std::make_pair(start, start));
            itr != this->watches.end(); 
            itr++)
        {
            if (itr->second.start == start && itr->second.size == size)
            {
                this->watches.erase(itr);
                return;
            }
        }
        
        s2e()->getWarningsStream()
              << "[MemoryMonitor]: No memory watch on address " 
              << hexval(start) << " altough one should be removed" << '\n';
    }

  } // namespace plugins
} // namespace s2e
