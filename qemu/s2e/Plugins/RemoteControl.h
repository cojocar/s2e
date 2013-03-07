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

#ifndef S2E_PLUGINS_REMOTECONTROL_H
#define S2E_PLUGINS_REMOTECONTROL_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

namespace s2e {
namespace plugins {

  class RemoteControl;

  class RemoteControlInvoker {
  private:
      RemoteControl *m_remoteControlPlugin;
      S2E* s2e;

  public:
      static const char className[];
      static Lunar<RemoteControlInvoker>::RegType methods[];

      RemoteControlInvoker(RemoteControl *plg);
      RemoteControlInvoker(lua_State *lua);
      ~RemoteControlInvoker();

  public:
      int listInjections(lua_State *L);
      int listStates(lua_State* L);
      int setForkMode(lua_State* L);
      int killState(lua_State * lua);
      int injectConstant(lua_State * lua);
      int injectConstantIncrementor(lua_State * lua);
      int injectSymbolic(lua_State * lua);
      int injectSymbolicRefresher(lua_State * lua);
      int removeInjector(lua_State * lua);
  private:
      S2EExecutionState * getExecutionState(int id);
      void setError(lua_State *lua, std::string msg);

  };

class RemoteControl : public Plugin
{
    S2E_PLUGIN

    friend class RemoteControlInvoker;
public:
    RemoteControl(S2E* s2e);

    void initialize();
    void slotInitialize(S2EExecutionState *state);
    void slotTranslateBlockStart(ExecutionSignal*, S2EExecutionState *state, 
        TranslationBlock *tb, uint64_t pc);
    void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);
    void slotExecuteStateFork(S2EExecutionState* state, const std::vector<S2EExecutionState*>& newStates,
        const std::vector<klee::ref<klee::Expr> >& newConditions);

    typedef enum { MONITOR_DISABLED, MONITOR_NOTIFY, MONITOR_BREAK} ForkMonitorMode;

    void monitorStateFork(ForkMonitorMode mode);

private:
    sigc::connection * m_forkSignalConnection;
    bool m_breakOnFork;
    Initializer* m_initializer;
    bool m_traceBlockTranslation;
    bool m_traceBlockExecution;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_REMOTECONTROL_H
