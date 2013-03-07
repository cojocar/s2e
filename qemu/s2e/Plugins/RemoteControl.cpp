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
 * @author Jonas Zaddach <zaddach@eurecom.fr>
 *
 */

#include "s2e/Plugins/Initializer.h"
#include "s2e/Plugins/RemoteControl.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/MemInjector2.h>

extern "C"
{
#include <qdict.h>
#include <qint.h>
#include <qstring.h>
#include <qlist.h>
#include <qbool.h>
#include <qjson.h>

#include <monitor.h>
#include <sysemu.h>
}

#include <iostream>
#include <sstream>

extern s2e::S2E* g_s2e;

namespace s2e
{
    namespace plugins
    {

        S2E_DEFINE_PLUGIN(
                RemoteControl,
                "Plugin to control S2E over a network connection during execution",
                "", );

        const char RemoteControlInvoker::className[] = "RemoteControlInvoker";
        Lunar<RemoteControlInvoker>::RegType RemoteControlInvoker::methods[] =
            { LUNAR_DECLARE_METHOD(RemoteControlInvoker, listInjections),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, listStates),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, setForkMode),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, injectConstant),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, injectConstantIncrementor),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, injectSymbolic),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, injectSymbolicRefresher),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, removeInjector),
              LUNAR_DECLARE_METHOD(RemoteControlInvoker, killState),
              { 0, 0 }
            };

        RemoteControlInvoker::RemoteControlInvoker(lua_State * lua)
        {
            g_s2e->getDebugStream()
                    << "[RemoteControl]: RemoteControlInvoker::RemoteControlInvoker invoked"
                    << '\n';
            m_remoteControlPlugin =
                    static_cast<RemoteControl *>(g_s2e->getPlugin(
                            "RemoteControl"));

            if (m_remoteControlPlugin == 0)
            {
                g_s2e->getWarningsStream()
                        << "[RemoteControl]: RemoteControl plugin not found. Aborting"
                        << '\n';
            }
        }

        RemoteControlInvoker::~RemoteControlInvoker()
        {

        }

        int
        RemoteControlInvoker::listInjections(lua_State * lua)
        {
            MemInjector2 * memInjector =
                    static_cast<MemInjector2 *>(g_s2e->getPlugin("MemInjector2"));

            if (memInjector == 0)
            {
                g_s2e->getWarningsStream()
                        << "[RemoteControl]: MemInjector2 plugin not found. Aborting"
                        << '\n';
                return 0;
            }

            QDict * dict = qdict_new();
            QList * list = qlist_new();

            foreach(const MemInjector2::Injector injector, memInjector->listInjectors())
            {
                QDict * injDict = qdict_new();

                qdict_put(injDict, "address", qint_from_int(injector.address));
                qdict_put(injDict, "width", qint_from_int(injector.width));
                qdict_put(injDict, "state", qint_from_int(injector.state_id));
                qdict_put(injDict, "active", qbool_from_int(1));

                switch (injector.type)
                {
                case MemInjector2::INJ_CONSTANT:
                    qdict_put(injDict, "type", qstring_from_str("constant"));
                    qdict_put(injDict, "value", qint_from_int(injector.aux));
                    break;
                case MemInjector2::INJ_INCREMENTOR:
                    qdict_put(injDict, "type",
                            qstring_from_str("constant_incrementor"));
                    qdict_put(injDict, "max_value",
                            qint_from_int(injector.aux));
                    break;
                case MemInjector2::INJ_SYMBOLIC:
                    qdict_put(injDict, "type", qstring_from_str("symbolic"));
                    break;
                case MemInjector2::INJ_SREFRESHER:
                    qdict_put(injDict, "type",
                            qstring_from_str("symbolic_refresher"));
                    qdict_put(injDict, "max_refresh",
                            qint_from_int(injector.aux));
                    break;
                }

                qlist_append(list, injDict);
            }

            foreach(const MemInjector2::Injector injector, memInjector->listQueuedInjectors())
            {
                QDict * injDict = qdict_new();

                qdict_put(injDict, "address", qint_from_int(injector.address));
                qdict_put(injDict, "width", qint_from_int(injector.width));
                qdict_put(injDict, "state", qint_from_int(injector.state_id));
                qdict_put(injDict, "active", qbool_from_int(0));

                switch (injector.type)
                {
                case MemInjector2::INJ_CONSTANT:
                    qdict_put(injDict, "type", qstring_from_str("constant"));
                    qdict_put(injDict, "value", qint_from_int(injector.aux));
                    break;
                case MemInjector2::INJ_INCREMENTOR:
                    qdict_put(injDict, "type",
                            qstring_from_str("constant_incrementor"));
                    qdict_put(injDict, "max_value",
                            qint_from_int(injector.aux));
                    break;
                case MemInjector2::INJ_SYMBOLIC:
                    qdict_put(injDict, "type", qstring_from_str("symbolic"));
                    break;
                case MemInjector2::INJ_SREFRESHER:
                    qdict_put(injDict, "type",
                            qstring_from_str("symbolic_refresher"));
                    qdict_put(injDict, "max_refresh",
                            qint_from_int(injector.aux));
                    break;
                }

                qlist_append(list, injDict);
            }

            qdict_put(dict, "injections", list);
            QString * json = qobject_to_json(QOBJECT(dict));

            lua_pushstring(lua, qstring_get_str(json));
            lua_setglobal(lua, "returnvalue");

            QDECREF(json);
            QDECREF(dict);
            return 0;
        }

        int
        RemoteControlInvoker::listStates(lua_State* lua)
        {
            g_s2e->getDebugStream()
                    << "[RemoteControl]: RemoteControlInvoker::listStates invoked"
                    << '\n';

            QDict * dict = qdict_new();
            QList * list = qlist_new();

            foreach(klee::ExecutionState * kleeState, g_s2e->getExecutor()->getStates())
            {
                S2EExecutionState * s2eState =
                        static_cast<S2EExecutionState *>(kleeState);
                QDict * stateDict = qdict_new();

                qdict_put(stateDict, "id", qint_from_int(s2eState->getID()));
                qdict_put(stateDict, "pc", qint_from_int(s2eState->getPc()));
                qdict_put(stateDict, "sp", qint_from_int(s2eState->getSp()));
                qdict_put(stateDict, "active",
                        qbool_from_int(s2eState->isActive()));
                qdict_put(stateDict, "concrete",
                        qbool_from_int(s2eState->isRunningConcrete()));
                qdict_put(stateDict, "forking_enabled",
                        qbool_from_int(s2eState->isForkingEnabled()));

                qlist_append(list, stateDict);
            }

            qdict_put(dict, "states", list);
            QString * json = qobject_to_json(QOBJECT(dict));

            lua_pushstring(lua, qstring_get_str(json));
            lua_setglobal(lua, "returnvalue");

            QDECREF(json);
            QDECREF(dict);

            return 0;
        }

        S2EExecutionState *
        RemoteControlInvoker::getExecutionState(int id)
        {
            const std::set<klee::ExecutionState*>& states =
                    g_s2e->getExecutor()->getStates();

            for (std::set<klee::ExecutionState*>::iterator itr = states.begin();
                    itr != states.end(); itr++)
            {
                if (static_cast<S2EExecutionState *>(*itr)->getID() == id)
                    return static_cast<S2EExecutionState *>(*itr);

            }

            return 0;
        }

        int
        RemoteControlInvoker::killState(lua_State * lua)
        {
            int stateId = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);

            S2EExecutionState * state = getExecutionState(stateId);

            g_s2e->getExecutor()->terminateStateEarly(*state,
                    "user terminated state");

            return 0;
        }

        void
        RemoteControlInvoker::setError(lua_State *lua, std::string msg)
        {
            QDict * dict = qdict_new();
            qdict_put(dict, "error", qstring_from_str(msg.c_str()));
            QString * json = qobject_to_json(QOBJECT(dict));

            lua_pushstring(lua, qstring_get_str(json));
            lua_setglobal(lua, "returnvalue");

            QDECREF(dict);
            QDECREF(json);
        }

        int
        RemoteControlInvoker::injectConstant(lua_State * lua)
        {
            int state = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);
            uint32_t width = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t value = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t address = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);

            MemInjector2 * plg = static_cast<MemInjector2 *>(g_s2e->getPlugin(
                    "MemInjector2"));

            if (!plg)
            {
                setError(lua, "MemInjector2 plugin not found");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: MemInjector2 plugin not found"
                        << '\n';
                return 0;
            }

            g_s2e->getDebugStream()
                    << "[RemoteControlInvoker]: calling addConstantInjector("
                    << hexval(address) << ", " << hexval(value)
                    << ", "  << width << ", "  << state
                    << ")" << '\n';
            plg->addConstantInjector(address, value, width, state);

            return 0;
        }

        int
        RemoteControlInvoker::injectConstantIncrementor(lua_State * lua)
        {
            int state = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);
            uint32_t width = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t max_value = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t address = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);

            MemInjector2 * plg = static_cast<MemInjector2 *>(g_s2e->getPlugin(
                    "MemInjector2"));

            if (!plg)
            {
                setError(lua, "MemInjector2 plugin not found");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: MemInjector2 plugin not found"
                        << '\n';
                return 0;
            }

            g_s2e->getDebugStream()
                    << "[RemoteControlInvoker]: calling addConstantIncrementor("
                    << hexval(address) << ", " << hexval(max_value)
                    << ", "  << width << ", "  << state
                    << ")" << '\n';
            plg->addConstantIncrementor(address, max_value, width, state);

            return 0;
        }

        int
        RemoteControlInvoker::injectSymbolic(lua_State * lua)
        {
            int state = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);
            uint32_t width = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t address = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);

            MemInjector2 * plg = static_cast<MemInjector2 *>(g_s2e->getPlugin(
                    "MemInjector2"));

            if (!plg)
            {
                setError(lua, "MemInjector2 plugin not found");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: MemInjector2 plugin not found"
                        << '\n';
                return 0;
            }

            g_s2e->getDebugStream()
                    << "[RemoteControlInvoker]: calling addSymbolicInjector("
                    << hexval(address) << ", "  << width << ", "
                     << state << ")" << '\n';
            plg->addSymbolicInjector(address, width, state);

            return 0;
        }

        int
        RemoteControlInvoker::injectSymbolicRefresher(lua_State * lua)
        {
            int state = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);
            uint32_t width = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t max_refreshs = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);
            uint32_t address = static_cast<uint32_t>(lua_tointeger(lua,
                    lua_gettop(lua)));
            lua_pop(lua, 1);

            MemInjector2 * plg = static_cast<MemInjector2 *>(g_s2e->getPlugin(
                    "MemInjector2"));

            if (!plg)
            {
                setError(lua, "MemInjector2 plugin not found");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: MemInjector2 plugin not found"
                        << '\n';
                return 0;
            }

            g_s2e->getDebugStream()
                    << "[RemoteControlInvoker]: calling addConstantInjector("
                    << hexval(address) << ", " << hexval(max_refreshs)
                    << ", "  << width << ", "  << state
                    << ")" << '\n';
            plg->addSymbolicRefresher(address, max_refreshs, width, state);

            return 0;
        }

        int RemoteControlInvoker::removeInjector(lua_State * lua)
        {
            int address = lua_tointeger(lua, lua_gettop(lua));
            lua_pop(lua, 1);

            MemInjector2 * plg = static_cast<MemInjector2 *>(g_s2e->getPlugin(
                                "MemInjector2"));

                        if (!plg)
                        {
                            setError(lua, "MemInjector2 plugin not found");
                            g_s2e->getWarningsStream()
                                    << "[RemoteControlInvoker]: MemInjector2 plugin not found"
                                    << '\n';
                            return 0;
                        }

            plg->removeInjector(address);

            return 0;
        }

        int
        RemoteControlInvoker::setForkMode(lua_State * lua)
        {
            RemoteControl * plg = static_cast<RemoteControl *>(g_s2e->getPlugin(
                    "RemoteControl"));

            if (!plg)
            {
                setError(lua, "RemoteControl plugin not found");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: Plugin RemoteControl not found."
                        << '\n';
                return 0;
            }

            RemoteControl::ForkMonitorMode mode;

            std::string strMode = std::string(
                    lua_tostring(lua, lua_gettop(lua)));
            std::transform(strMode.begin(), strMode.end(), strMode.begin(),
                    ::tolower);
            lua_pop(lua, 1);

            g_s2e->getDebugStream() << "[RemoteControlInvoker]: setForkMode("
                    << strMode << ") called" << '\n';

            if (strMode == std::string("disabled"))
                mode = RemoteControl::MONITOR_DISABLED;
            else if (strMode == std::string("notify"))
                mode = RemoteControl::MONITOR_NOTIFY;
            else if (strMode == std::string("break"))
                mode = RemoteControl::MONITOR_BREAK;
            else
            {
                setError(lua, "Unknown monitor mode");
                g_s2e->getWarningsStream()
                        << "[RemoteControlInvoker]: Unknown monitor mode '"
                        << strMode << "'" << '\n';
                return 0;
            }

            plg->monitorStateFork(mode);

            return 0;
        }

        RemoteControl::RemoteControl(S2E* s2e) :
                Plugin(s2e), m_forkSignalConnection(0), m_breakOnFork(false)
        {

        }

        void
        RemoteControl::initialize()
        {
            m_traceBlockTranslation = s2e()->getConfig()->getBool(
                    getConfigKey() + ".traceBlockTranslation");
            m_traceBlockExecution = s2e()->getConfig()->getBool(
                    getConfigKey() + ".traceBlockExecution");

            s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                    sigc::mem_fun(*this,
                            &RemoteControl::slotTranslateBlockStart));

            Lunar<RemoteControlInvoker>::Register(
                    s2e()->getConfig()->getState());
            s2e()->getWarningsStream() << "RemoteControl::initialize invoked"
                    << '\n';
        }

        void
        RemoteControl::slotInitialize(S2EExecutionState* state)
        {
        }

        void
        RemoteControl::slotTranslateBlockStart(ExecutionSignal *signal,
                S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
        {
            if (m_traceBlockTranslation)
                std::cout << "Translating block at " << hexval(pc)
                         << '\n';
            if (m_traceBlockExecution)
                signal->connect(
                        sigc::mem_fun(*this,
                                &RemoteControl::slotExecuteBlockStart));
        }

        void
        RemoteControl::slotExecuteBlockStart(S2EExecutionState *state,
                uint64_t pc)
        {
//    std::cout << "Executing block at " << hexval(pc)  << '\n';
        }

        typedef enum
        {
            MONITOR_DISABLED, MONITOR_NOTIFY, MONITOR_BREAK
        } ForkMonitorMode;

        void
        RemoteControl::monitorStateFork(ForkMonitorMode mode)
        {
            switch (mode)
            {
            case MONITOR_DISABLED:
                if (m_forkSignalConnection)
                {
                    m_forkSignalConnection->disconnect();
                    delete m_forkSignalConnection;
                }
                break;
            case MONITOR_NOTIFY:
            case MONITOR_BREAK:
                if (!m_forkSignalConnection)
                {
                    m_forkSignalConnection =
                            new sigc::connection(
                                    s2e()->getCorePlugin()->onStateFork.connect(
                                            sigc::mem_fun(
                                                    *this,
                                                    &RemoteControl::slotExecuteStateFork)));
                }
                m_breakOnFork = (mode == MONITOR_BREAK);
                break;
            }
        }

        void
        RemoteControl::slotExecuteStateFork(S2EExecutionState* state,
                const std::vector<S2EExecutionState*>& newStates,
                const std::vector<klee::ref<klee::Expr> >& newConditions)
        {
            //if messages are enabled
            if (true)
            {
                QDict * data = qdict_new();
                qdict_put(data, "source", qstring_from_str("s2e"));
                qdict_put(data, "type", qstring_from_str("state_fork"));
                qdict_put(data, "old_state", qint_from_int(state->getID()));
                QList * states = qlist_new();

                std::vector<S2EExecutionState*>::const_iterator itrState =
                        newStates.begin();
                std::vector<klee::ref<klee::Expr> >::const_iterator itrCond =
                        newConditions.begin();

                while ((itrState != newStates.end())
                        || (itrCond != newConditions.end()))
                {
                    QDict * state = qdict_new();
                    qdict_put(state, "id",
                            qint_from_int((int) (*itrState)->getID()));

                    std::string str;
                    llvm::raw_string_ostream ss(str);
                    (*itrCond)->print(ss);

                    qdict_put(state, "new_condition",
                            qstring_from_str(str.c_str()));
                    qlist_append(states, state);

                    itrState++;
                    itrCond++;
                }

                qdict_put(data, "new_states", states);
                monitor_protocol_event(QEVENT_DEBUG, QOBJECT(data));
                QDECREF(data);
            }

            if (m_breakOnFork)
            {
                s2e()->getWarningsStream()
                        << "[RemoteControl]: State fork - causing CPU debug interrupt"
                        << '\n';
                //TODO: cause debug interrupt in a good way here
                vm_stop(RUN_STATE_DEBUG);
//    cpu_interrupt(env, CPU_INTERRUPT_DEBUG);
            }

        }

    } // namespace plugins
} // namespace s2e
