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

extern "C"
{
#include "config.h"
#include "qemu-common.h"
}

#include "ArmFunctionMonitor.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

/**
 * WARNING: If you use this plugin together with the RemoteMemory plugin, know what you are doing!
 *          This plugin inspects memory contents of QEMU to find instructions, it will fail if instructions
 *          are inserted via the onDataAccess hook!
 */

namespace s2e
{
  namespace plugins
  {

    S2E_DEFINE_PLUGIN(ARMFunctionMonitor,
        "Function calls/returns monitoring plugin for ARM architecture", "", );

    void
    ARMFunctionMonitor::initialize()
    {
        m_verbose = false;
      s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
          sigc::mem_fun(*this, &ARMFunctionMonitor::slotTranslateBlockEnd));
      s2e()->getCorePlugin()->onTranslateBlockStart.connect(
          sigc::mem_fun(*this, &ARMFunctionMonitor::slotTranslateBlockStart));
//    s2e()->getCorePlugin()->onTranslateJumpStart.connect(
//            sigc::mem_fun(*this, &FunctionMonitor::slotTranslateJumpStart));

//    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("Interceptor"));
    }

////XXX: Implement onmoduleunload to automatically clear all call signals
//FunctionMonitor::CallSignal* FunctionMonitor::getCallSignal(
//        S2EExecutionState *state,
//        uint64_t eip, uint64_t cr3)
//{
//    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
//
//    return plgState->getCallSignal(eip, cr3);
//}
    void
    ARMFunctionMonitor::callFunction(S2EExecutionState *state, uint64_t pc,
        uint64_t function_address)
    {
        uint32_t return_address = pc + 4;
        if (state->getFlags() & 0x20)
        {
            klee::ref<klee::Expr> expr = state->readMemory(pc, klee::Expr::Int16, s2e::S2EExecutionState::PhysicalAddress);

            if (!isa<klee::ConstantExpr>(expr))
            { 
                s2e()->getWarningsStream()
                    << "[ARMFunctionMonitor]: Found symbolic instruction at address 0x"
                    << hexval(pc) << '\n';
                return;
            }
            uint32_t opcode = static_cast<uint32_t>(cast<klee::ConstantExpr>(expr)->getZExtValue());

            if ((opcode & 0xFF80) == 0x4780) //BLX<c> register
                return_address = pc + 2;
            pc |= 1;
        }

        m_returns.insert(std::make_pair(return_address, function_address));

        //TODO: Call subordinate plugins
      s2e()->getDebugStream()
          << "[ARMFunctionMonitor]: Detected function call at " 
          << hexval(pc) << " to " << hexval(function_address) << ", return to " << hexval(return_address) << " in ARM code."
          << '\n';

    }

    void
    ARMFunctionMonitor::callFunctionIndirect(S2EExecutionState *state,
        uint64_t pc, int reg)
    {
      uint32_t address;
      uint32_t offset = 0;

      switch (reg)
      {
      case 0:
        offset = CPU_OFFSET(regs[0]);
        break;
      case 1:
        offset = CPU_OFFSET(regs[1]);
        break;
      case 2:
        offset = CPU_OFFSET(regs[2]);
        break;
      case 3:
        offset = CPU_OFFSET(regs[3]);
        break;
      case 4:
        offset = CPU_OFFSET(regs[4]);
        break;
      case 5:
        offset = CPU_OFFSET(regs[5]);
        break;
      case 6:
        offset = CPU_OFFSET(regs[6]);
        break;
      case 7:
        offset = CPU_OFFSET(regs[7]);
        break;
      case 8:
        offset = CPU_OFFSET(regs[8]);
        break;
      case 9:
        offset = CPU_OFFSET(regs[9]);
        break;
      case 10:
        offset = CPU_OFFSET(regs[10]);
        break;
      case 11:
        offset = CPU_OFFSET(regs[11]);
        break;
      case 12:
        offset = CPU_OFFSET(regs[12]);
        break;
      case 13:
        offset = CPU_OFFSET(regs[13]);
        break;
      case 14:
        offset = CPU_OFFSET(regs[14]);
        break;
      case 15:
        offset = CPU_OFFSET(regs[15]);
        break;
      default:
        s2e()->getWarningsStream() << "[ARMFunctionMonitor]: Unknown register "
            << reg << '\n';
        break;
      }

      if (!state->readCpuRegisterConcrete(offset, &address, sizeof(address)))
      {
        s2e()->getWarningsStream()
            << "[ARMFunctionMonitor]: Found symbolic register value at address "
            << hexval(pc)  << '\n';
        return;
      }

      callFunction(state, pc, address);
    }

    void
    ARMFunctionMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
        S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
        bool is_static_target, uint64_t static_target_pc)
    {
      klee::ref<klee::Expr> expr = state->readMemory(
          pc - ((tb->instruction_set == INSTRUCTION_SET_THUMB) ? 0 : 0),
          klee::Expr::Int32, s2e::S2EExecutionState::PhysicalAddress);

      if (!isa<klee::ConstantExpr>(expr))
      {
        s2e()->getWarningsStream()
            << "[ARMFunctionMonitor]: Found symbolic instruction at address 0x"
            << hexval(pc) << '\n';
        return;
      }

      uint32_t opcode =
          static_cast<uint32_t>(cast<klee::ConstantExpr>(expr)->getZExtValue());

      if (tb->instruction_set == INSTRUCTION_SET_ARM)
      {
        if (((opcode & 0x0F000000) == 0x0B000000) //BL<c> immediate
        || ((opcode & 0xFE000000) == 0xFA000000)) //BLX immediate
        {
//          uint32_t dest_address = ((opcode & 0x800000) ? 0xFC000000 : 0x0) | ((opcode & 0xFFFFFF) << 2);
//          dest_address += pc + 8; //relative address to absolute address
          signal->connect(
              sigc::bind(
                  sigc::mem_fun(*this, &ARMFunctionMonitor::callFunction),
                  static_target_pc));
        }
        else if ((opcode & 0x0FF000F0) == 0x01200030) //BLX<c> register
        {
          uint32_t reg = opcode & 0xf;
          signal->connect(
              sigc::bind(
                  sigc::mem_fun(*this,
                      &ARMFunctionMonitor::callFunctionIndirect), reg));
        }

      }
      else if (tb->instruction_set == INSTRUCTION_SET_THUMB)
      {
        if (((opcode & 0xF800F800) == 0xF800F000) || ((opcode & 0xF800F800) == 0xF800E800)) //BL<c> immediate, BLX<c> immediate
        {
//            uint32_t offset = ((opcode & (1 << 10)) and 0xFFC00000) | ((opcode & 0x03FF0000) >> 15) | ((opcode & 0x7FF) << 17);
            uint32_t h = (opcode >> (11 + 16)) & 0x3;
//            uint32_t target_address  = (pc + offset + 4) | 1;
            uint32_t target_address = static_target_pc | 1;

            if (h == 0b01)
            {
                target_address &= 0xFFFFFFFC;
            }


/*          uint32_t s = (opcode >> (10 + 16)) & 1;
          uint32_t j1 = (opcode >> 13) & 1;
          uint32_t j2 = (opcode >> 11) & 1;
          uint32_t i1 = !(j1 ^ s) & 1;
          uint32_t i2 = !(j2 ^ s) & 1;
          uint32_t imm10 = (opcode >> 16) & 0x3FF;
          uint32_t imm11 = opcode & 0x7FF;

            uint32_t offset = (s ? 0xFE000000 : 0) | (s << 24) | (
          uint32_t target_address = (s ? 0xFE000000 : 0) | (s << 24)
              | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
          target_address += pc + 0x8;
*/
          signal->connect(
              sigc::bind(
                  sigc::mem_fun(*this, &ARMFunctionMonitor::callFunction),
                  target_address));

        }
//        else if ((opcode & 0xF800F800) == 0xF800E800) //BLX<c> immediate
//        {
//            uint32_t offset = ((opcode & (1 << 26)) ? 0xFFC00000 : 0) | ((opcode & 0x03FF0000) >> 4) | ((opcode & 0x7FF) << 1);
//            uint32_t target_address = (pc + offset + 4) & 0xFFFFFFFC;
/*          uint32_t s = (opcode >> 10) & 1;
          uint32_t j1 = (opcode >> (13 + 16)) & 1;
          uint32_t j2 = (opcode >> (11 + 16)) & 1;
          uint32_t i1 = !(j1 ^ s) & 1;
          uint32_t i2 = !(j2 ^ s) & 1;
          uint32_t imm10h = opcode & 0x3FF;
          uint32_t imm10l = (opcode >> 16) & 0x7FF;

          uint32_t target_address = (s ? 0xFE000000 : 0) | (s << 24)
              | (i1 << 23) | (i2 << 22) | (imm10h << 12) | (imm10l << 2);
          target_address += pc + 0xe;
*/
//          signal->connect(
//              sigc::bind(
//                  sigc::mem_fun(*this, &ARMFunctionMonitor::callFunction),
//                  target_address));
//        }
        else if ((opcode & 0x0000FF80) == 0x4780) //BLX<c> register
        {
          uint32_t reg = (opcode >> 3) & 0xf;

          signal->connect(
              sigc::bind(
                  sigc::mem_fun(*this,
                      &ARMFunctionMonitor::callFunctionIndirect), reg));
        }
      }
    }

    void
    ARMFunctionMonitor::slotTranslateBlockStart(ExecutionSignal *signal,
        S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
    {
      /* We intercept all call and ret translation blocks */
//    if (tb->s2e_tb_type == TB_CALL || tb->s2e_tb_type == TB_CALL_IND)
//    {a
        std::map< uint32_t, uint32_t >::iterator itr = m_returns.find(pc);

        if (itr != m_returns.end())
        {
            
            signal->connect(sigc::bind(sigc::mem_fun(*this, &ARMFunctionMonitor::functionReturn), itr->second));
            //TODO: recursive functions?
            m_returns.erase(itr);
        }
        if (m_verbose)
        {
            s2e()->getDebugStream()
                << "[ARMFunctionMonitor]: Found beginning of TB at pc " 
                << hexval(pc) << '\n';
        }

//        signal->connect(sigc::mem_fun(*this,
//                            &ARMFunctionMonitor::slotCall));
//    }
    }

    void ARMFunctionMonitor::functionReturn(S2EExecutionState * state, uint64_t pc, uint32_t function)
    {
        s2e()->getDebugStream() << "[ARMFunctionMonitor] Function return of function " << hexval(function) << " to " << hexval(pc) << " found" << '\n';

    }

//void FunctionMonitor::slotTranslateJumpStart(ExecutionSignal *signal,
//                                             S2EExecutionState *state,
//                                             TranslationBlock *,
//                                             uint64_t, int jump_type)
//{
////    if(jump_type == JT_RET || jump_type == JT_LRET) {
////        signal->connect(sigc::mem_fun(*this,
////                            &FunctionMonitor::slotRet));
////    }
//}

    void
    ARMFunctionMonitor::slotCall(S2EExecutionState *state, uint64_t pc)
    {
//    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

//    return plgState->slotCall(state, pc);
    }

////See notes for slotRet to see how to use this function.
//void FunctionMonitor::eraseSp(S2EExecutionState *state, uint64_t pc)
//{
//    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
//
//    return plgState->slotRet(state, pc, false);
//}
//
//
//
//void FunctionMonitor::slotRet(S2EExecutionState *state, uint64_t pc)
//{
//    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
//
//    return plgState->slotRet(state, pc, true);
//}
//
//
//void FunctionMonitor::slotTraceCall(S2EExecutionState *state, FunctionMonitorState *fns)
//{
//    static int f = 0;
//
//    FunctionMonitor::ReturnSignal returnSignal;
//    returnSignal.connect(sigc::bind(sigc::mem_fun(*this, &FunctionMonitor::slotTraceRet), f));
//    fns->registerReturnSignal(state, returnSignal);
//
//    s2e()->getMessagesStream(state) << "Calling function " << f
//                << " at " << hexval(state->getPc()) << '\n';
//    ++f;
//}

//void FunctionMonitor::slotTraceRet(S2EExecutionState *state, int f)
//{
////    s2e()->getMessagesStream(state) << "Returning from function "
////                << f << '\n';
//}
//
//
//FunctionMonitorState::FunctionMonitorState()
//{
//
//}
//
//FunctionMonitorState::~FunctionMonitorState()
//{
//
//}
//
//FunctionMonitorState* FunctionMonitorState::clone() const
//{
//    FunctionMonitorState *ret = new FunctionMonitorState(*this);
////    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << std::hex << ret << '\n';
////    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
//    return ret;
//}
//
//PluginState *FunctionMonitorState::factory(Plugin *p, S2EExecutionState *s)
//{
//    FunctionMonitorState *ret = new FunctionMonitorState();
//    ret->m_plugin = static_cast<ARMFunctionMonitor*>(p);
//    return ret;
//}
//
//FunctionMonitor::CallSignal* FunctionMonitorState::getCallSignal(
//        uint64_t eip, uint64_t cr3)
//{
//    std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
//            range = m_callDescriptors.equal_range(eip);
//
//    for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
//        if(it->second.cr3 == cr3)
//            return &it->second.signal;
//    }
//
//    CallDescriptor descriptor = { cr3, FunctionMonitor::CallSignal() };
//    CallDescriptorsMap::iterator it =
//            m_newCallDescriptors.insert(std::make_pair(eip, descriptor));
//    return &it->second.signal;
//}
//
//
//void FunctionMonitorState::slotCall(S2EExecutionState *state, uint64_t pc)
//{
//    target_ulong cr3 = state->getPid();
//    target_ulong eip = state->getPc();
//
//    if (!m_newCallDescriptors.empty()) {
//        m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
//        m_newCallDescriptors.clear();
//    }
//
//    /* Issue signals attached to all calls (eip==-1 means catch-all) */
//    if (!m_callDescriptors.empty()) {
//        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
//                range = m_callDescriptors.equal_range((uint64_t)-1);
//        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
//            CallDescriptor cd = (*it).second;
//            if (m_plugin->m_monitor) {
//                cr3 = m_plugin->m_monitor->getPid(state, pc);
//            }
//            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
//                cd.signal.emit(state, this);
//            }
//        }
//        if (!m_newCallDescriptors.empty()) {
//            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
//            m_newCallDescriptors.clear();
//        }
//    }
//
//    /* Issue signals attached to specific calls */
//    if (!m_callDescriptors.empty()) {
//        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
//                range;
//
//        range = m_callDescriptors.equal_range(eip);
//        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
//            CallDescriptor cd = (*it).second;
//            if (m_plugin->m_monitor) {
//                cr3 = m_plugin->m_monitor->getPid(state, pc);
//            }
//            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
//                cd.signal.emit(state, this);
//            }
//        }
//        if (!m_newCallDescriptors.empty()) {
//            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
//            m_newCallDescriptors.clear();
//        }
//    }
//}
//
///**
// *  A call handler can invoke this function to register a return handler.
// *  XXX: We assume that the passed execution state corresponds to the state in which
// *  this instance of FunctionMonitorState is used.
// */
//void FunctionMonitorState::registerReturnSignal(S2EExecutionState *state, FunctionMonitor::ReturnSignal &sig)
//{
//    if(sig.empty()) {
//        return;
//    }
//
//    uint32_t esp;
//
//    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]),
//                                             &esp, sizeof(target_ulong));
//    if(!ok) {
//        m_plugin->s2e()->getWarningsStream(state)
//            << "Function call with symbolic ESP!" << '\n'
//            << "  EIP=" << hexval(state->getPc()) << " CR3=" << hexval(state->getPid()) << '\n';
//        return;
//    }
//
//    uint64_t pid = state->getPid();
//    if (m_plugin->m_monitor) {
//        pid = m_plugin->m_monitor->getPid(state, state->getPc());
//    }
//    ReturnDescriptor descriptor = {pid, sig };
//    m_returnDescriptors.insert(std::make_pair(esp, descriptor));
//}
//
///**
// *  When emitSignal is false, this function simply removes all the return descriptors
// * for the current stack pointer. This can be used when a return handler manually changes the
// * program counter and/or wants to exit to the cpu loop and avoid being called again.
// *
// *  Note: all the return handlers will be erased if emitSignal is false, not just the one
// * that issued the call. Also note that it not possible to return from the handler normally
// * whenever this function is called from within a return handler.
// */
//void FunctionMonitorState::slotRet(S2EExecutionState *state, uint64_t pc, bool emitSignal)
//{
//    target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), 8*sizeof(target_ulong));
//
//    target_ulong esp;
//    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]),
//                                             &esp, sizeof(target_ulong));
//    if(!ok) {
//        target_ulong eip = state->readCpuState(CPU_OFFSET(eip),
//                                               8*sizeof(target_ulong));
//        m_plugin->s2e()->getWarningsStream(state)
//            << "Function return with symbolic ESP!" << '\n'
//            << "  EIP=" << hexval(eip) << " CR3=" << hexval(cr3) << '\n';
//        return;
//    }
//
//    if (m_returnDescriptors.empty()) {
//        return;
//    }
//
//    //m_plugin->s2e()->getDebugStream() << "ESP AT RETURN 0x" << std::hex << esp <<
//    //        " plgstate=0x" << this << " EmitSignal=" << emitSignal <<  '\n';
//
//    bool finished = true;
//    do {
//        finished = true;
//        std::pair<ReturnDescriptorsMap::iterator, ReturnDescriptorsMap::iterator>
//                range = m_returnDescriptors.equal_range(esp);
//        for(ReturnDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
//            if (m_plugin->m_monitor) {
//                cr3 = m_plugin->m_monitor->getPid(state, pc);
//            }
//
//            if(it->second.cr3 == cr3) {
//                if (emitSignal) {
//                    it->second.signal.emit(state);
//                }
//                m_returnDescriptors.erase(it);
//                finished = false;
//                break;
//            }
//        }
//    } while(!finished);
//}

  }// namespace plugins
} // namespace s2e
