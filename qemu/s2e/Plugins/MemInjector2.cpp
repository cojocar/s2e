extern "C"
{
#include "hw/hw.h"
#include "hw/pci.h"
#include "hw/isa.h"
}

#include "MemInjector2.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include <s2e/S2E.h>
#include <s2e/S2EDeviceState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "llvm/Support/CommandLine.h"

#define MAX_SYMBOLIC_REFRESHER_COUNT 50

namespace s2e
{
  namespace plugins
  {

    S2E_DEFINE_PLUGIN(MemInjector2, "Inject constants, incrementing values and symbolic values into memory",
        "MemInjector2", "Initializer", "MemoryMonitor");

#define OUTPUT(arg) if(verbose){s2e()->getMessagesStream() << "[MemInjector2]: " << arg;}
#define OUTPUT_STATE(state, arg) (if(verbose) s2e()->getMessagesStream() << "[MemInjector2 (State: " << dec << state->getID() << "]: " << arg)

    MemInjector2::Injector::Injector(uint64_t address, uint64_t width, uint64_t aux, InjectorType type, int state_id)
    : address(address),
      width(width),
      aux(aux),
      type(type),
      state_id(state_id)
    {

    }

    MemInjector2::Injector::Injector(const MemInjector2::Injector& other)
    : address(other.address),
      width(other.width),
      aux(other.aux),
      type(other.type),
      state_id(other.state_id)
    {

    }

    MemInjector2::Injector::Injector()
    : address(0),
      width(0),
      aux(0),
      type(INJ_CONSTANT),
      state_id(0)
    {

    }

    MemInjector2::MemInjector2(S2E* s2e) :
        Plugin(s2e),
        initialized(false)
    {
    }

    void
    MemInjector2::initialize()
    {
      ConfigFile *cfg = s2e()->getConfig();
      bool ok;
      std::vector<std::vector<int64_t> > configData;

      klee::ref<klee::Expr> expr;

      Initializer* m_initializer = (Initializer *) s2e()->getPlugin("Initializer");
      assert(m_initializer);

      verbose = cfg->getBool(getConfigKey() + ".verbose", false, &ok);

      readConfigPair(getConfigKey() + ".memRangesConstant", configData);
      for (std::vector<std::vector<int64_t> >::iterator itr =
          configData.begin(); itr != configData.end(); itr++)
      {
        if (itr->size() < 2)
          continue;

        if (itr->size() == 2)
          itr->push_back(32);

        if (itr->size() == 3)
          itr->push_back(-1);

        addConstantInjector(itr->at(0), itr->at(1), itr->at(2), itr->at(3));
      }

      configData.erase(configData.begin(), configData.end());
      readConfigPair(getConfigKey() + ".memRangesConstantIncrementors",
          configData);
      for (std::vector<std::vector<int64_t> >::iterator itr =
          configData.begin(); itr != configData.end(); itr++)
      {
        if (itr->size() < 2)
          continue;

        if (itr->size() == 2)
          itr->push_back(32);

        if (itr->size() == 3)
          itr->push_back(-1);

        addConstantIncrementor(itr->at(0), itr->at(1), itr->at(2), itr->at(3));
      }

      configData.erase(configData.begin(), configData.end());
      readConfigPair(getConfigKey() + ".memRangesSymbolic", configData);
      for (std::vector<std::vector<int64_t> >::iterator itr =
          configData.begin(); itr != configData.end(); itr++)
      {
        if (itr->size() < 2)
          continue;

        if (itr->size() == 1)
          itr->push_back(32);

        if (itr->size() == 2)
          itr->push_back(-1);

        addSymbolicInjector(itr->at(0), itr->at(1), itr->at(2));
      }

      configData.erase(configData.begin(), configData.end());
      readConfigPair(getConfigKey() + ".memRangesSymbolicRefreshers",
          configData);
      for (std::vector<std::vector<int64_t> >::iterator itr =
          configData.begin(); itr != configData.end(); itr++)
      {
        if (itr->size() < 2)
          continue;

        if (itr->size() == 2)
          itr->push_back(32);

        if (itr->size() == 3)
          itr->push_back(-1);

        addSymbolicRefresher(itr->at(0), itr->at(1), itr->at(2), itr->at(3));
      }

      m_initializer->onInitialize.connect(
          sigc::mem_fun(*this, &MemInjector2::slotInitialize));
      s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &MemInjector2::slotStateSwitch));
    }

    void
    MemInjector2::removeInjector(uint64_t address)
    {
        Injector injector;
        //TODO: what to do about restoring the original value?

        MemoryMonitor* m_memoryMonitor = (MemoryMonitor *) s2e()->getPlugin("MemoryMonitor");
        assert(m_memoryMonitor);

        do
        {
            std::map<uint64_t, Injector>::iterator itr = constantInjectors.find(
                    address);
            if (itr != constantInjectors.end())
            {
                injector = itr->second;
                constantInjectors.erase(itr);
                break;
            }

            itr = incrementingInjectors.find(address);
            if (itr != incrementingInjectors.end())
            {
                injector = itr->second;
                incrementingInjectors.erase(itr);
                break;
            }

            itr = symbolicInjectors.find(address);
            if (itr != symbolicInjectors.end())
            {
                injector = itr->second;
                symbolicInjectors.erase(itr);
                break;
            }

            itr = symbolicRefresherInjectors.find(address);
            if (itr != symbolicRefresherInjectors.end())
            {
                injector = itr->second;
                symbolicRefresherInjectors.erase(itr);
                break;
            }

            for (std::vector<Injector>::iterator itr = queuedInjections.begin();
                 itr != queuedInjections.end();
                 itr++)
            {
                if (itr->address == address)
                {
                    queuedInjections.erase(itr);
                    return; //no hook needs to be removed, as not hooked yet
                }

            }

            //the address wasn't found
            //TODO: Error message
            return;

        }
        while (false);

        m_memoryMonitor->removeWatch(injector.address, injector.width);
    }

    const std::vector<MemInjector2::Injector>
    MemInjector2::listInjectors()
    {
      std::vector<Injector> injectors;

      for (std::map<uint64_t, Injector>::iterator itr =
          constantInjectors.begin(); itr != constantInjectors.end(); itr++)
      {
        injectors.push_back(itr->second);
      }

      for (std::map<uint64_t, Injector>::iterator itr =
          incrementingInjectors.begin(); itr != incrementingInjectors.end();
          itr++)
      {
        injectors.push_back(itr->second);
      }

      for (std::map<uint64_t, Injector>::iterator itr =
          symbolicInjectors.begin(); itr != symbolicInjectors.end(); itr++)
      {
        injectors.push_back(itr->second);
      }

      for (std::map<uint64_t, Injector>::iterator itr =
          symbolicRefresherInjectors.begin();
          itr != symbolicRefresherInjectors.end(); itr++)
      {
        injectors.push_back(itr->second);
      }

      return injectors;
    }

    const std::vector<MemInjector2::Injector> MemInjector2::listQueuedInjectors()
    {
      return queuedInjections;
    }

    bool
    MemInjector2::writeMemory(S2EExecutionState* state, uint64_t address,
        uint64_t val, uint64_t width)
    {
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
        s2e()->getWarningsStream() << "Unknown width " << width
            << " for write at address " << hexval(address) 
            << '\n';
        return false;
      }
    }

    void
    MemInjector2::addConstantInjector(uint64_t address, uint64_t value,
        uint64_t width, int state_id)
    {
      if (!initialized)
        queuedInjections.push_back(Injector(address, width, value, INJ_CONSTANT, state_id));
      else
        doAddConstantInjector(address, value, width, state_id);
    }

    void
    MemInjector2::addConstantIncrementor(uint64_t address, uint64_t max_value,
        uint64_t width, int state_id)
    {
      if (!initialized)
        queuedInjections.push_back(Injector(address, width, max_value, INJ_INCREMENTOR, state_id));
      else
        doAddConstantIncrementor(address, width, max_value, state_id);

    }

    void
    MemInjector2::addSymbolicInjector(uint64_t address, uint64_t width,
        int state_id)
    {
      if (!initialized)
        queuedInjections.push_back(Injector(address, width, 0, INJ_SYMBOLIC, state_id));
      else
        doAddSymbolicInjector(address, width, state_id);
    }

    void
    MemInjector2::addSymbolicRefresher(uint64_t address, uint64_t refresh_count,
        uint64_t width, int state_id)
    {
      if (!initialized)
        queuedInjections.push_back(Injector(address, width, refresh_count, INJ_SREFRESHER, state_id));
      else
        doAddSymbolicRefresher(address, refresh_count, width, state_id);
    }

    void
    MemInjector2::doAddConstantInjector(uint64_t address, uint64_t value,
        uint64_t width, int state_id)
    {
        assert((s2e()->getExecutor()->getStatesCount() > 0) && "No states!");
        assert(currentState && currentState->isActive() && "current state is not valid");

      MemoryMonitor* plg = static_cast<MemoryMonitor*>(s2e()->getPlugin(
          "MemoryMonitor"));
      if (!plg)
      {
        s2e()->getWarningsStream()
            << "[MemInjector2]: Plugin MemoryMonitor not found" << '\n';
        return;
      }
      plg->addWatch(
          address,
          width,
          MemoryMonitor::EMemoryRead | MemoryMonitor::EMemoryIO | MemoryMonitor::EMemoryNotIO 
            | MemoryMonitor::EMemoryConcrete | MemoryMonitor::EMemorySymbolic,
          sigc::mem_fun(*this, &MemInjector2::slotMemoryAccessConstant));


      constantInjectors.insert(std::make_pair(address, Injector(address, width, value, INJ_CONSTANT, state_id)));
      injectValues(currentState);
    }

    void
    MemInjector2::doAddConstantIncrementor(uint64_t address, uint64_t max_value,
        uint64_t width, int state_id)
    {
        assert((s2e()->getExecutor()->getStatesCount() > 0) && "No states!");
        assert(currentState && currentState->isActive() && "current state is not valid");

      MemoryMonitor* plg = static_cast<MemoryMonitor*>(s2e()->getPlugin(
          "MemoryMonitor"));
      if (!plg)
      {
        s2e()->getWarningsStream()
            << "[MemInjector2]: Plugin MemoryMonitor not found" << '\n';
        return;
      }

      plg->addWatch(
          address,
          width,
          MemoryMonitor::EMemoryRead | MemoryMonitor::EMemoryWrite | MemoryMonitor::EMemoryConcrete | 
            MemoryMonitor::EMemorySymbolic | MemoryMonitor::EMemoryIO | MemoryMonitor::EMemoryNotIO,
          sigc::mem_fun(*this,
              &MemInjector2::slotMemoryAccessConstantIncrementor));

      //check wraparound value; if bigger than variable width truncate to variable width
      max_value = std::min(max_value, static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF >> (64 - width)));

      for (std::set<klee::ExecutionState*>::iterator itr =
          s2e()->getExecutor()->getStates().begin();
          itr != s2e()->getExecutor()->getStates().end(); itr++)
      {
        S2EExecutionState * state = static_cast<S2EExecutionState *>(*itr);
        DECLARE_PLUGINSTATE(MemInjectorState2, state);

        if (state_id != -1 && state->getID() != state_id)
          continue;

        plgState->constantIncrementorValue[address] = 0;
      }

      incrementingInjectors.insert(std::make_pair(address, Injector(address, width, max_value, INJ_INCREMENTOR, state_id )));
      injectValues(currentState);
    }

    void
    MemInjector2::doAddSymbolicInjector(uint64_t address, uint64_t width,
        int state_id)
    {
        assert((s2e()->getExecutor()->getStatesCount() > 0) && "No states!");
        assert(currentState && currentState->isActive() && "current state is not valid");

      for (std::set<klee::ExecutionState*>::iterator itr =
          s2e()->getExecutor()->getStates().begin();
          itr != s2e()->getExecutor()->getStates().end(); itr++)
      {
        S2EExecutionState * state = static_cast<S2EExecutionState *>(*itr);

        if (state_id != -1 && state->getID() != state_id)
          continue;
        DECLARE_PLUGINSTATE(MemInjectorState2, state);

        plgState->symbolicInject[address] = true;
      }

      symbolicInjectors.insert(std::make_pair(address, Injector(address, width, 0, INJ_SYMBOLIC, state_id)));
      injectValues(currentState);
    }

    void
    MemInjector2::doAddSymbolicRefresher(uint64_t address,
        uint64_t refresh_count, uint64_t width, int state_id)
    {
        assert((s2e()->getExecutor()->getStatesCount() > 0) && "No states!");
        assert(currentState && currentState->isActive() && "current state is not valid");

        if (verbose)
            s2e()->getDebugStream() << "[MemInjector2]: doAddSymbolicRefresher("
            << hexval(address) << ", " << refresh_count
            << ", "  << width << ", " 
            << state_id << ") called" << '\n';


      MemoryMonitor* m_memoryMonitor = (MemoryMonitor *) s2e()->getPlugin("MemoryMonitor");
            assert(m_memoryMonitor);

      m_memoryMonitor->addWatch(
          address,
          width,
          MemoryMonitor::EMemoryRead | MemoryMonitor::EMemoryWrite | MemoryMonitor::EMemoryConcrete | 
            MemoryMonitor::EMemorySymbolic | MemoryMonitor::EMemoryIO | MemoryMonitor::EMemoryNotIO,
          sigc::mem_fun(*this,
              &MemInjector2::slotMemoryAccessSymbolicRefresher));

      for (std::set<klee::ExecutionState*>::iterator itr =
          s2e()->getExecutor()->getStates().begin();
          itr != s2e()->getExecutor()->getStates().end(); itr++)
      {
        S2EExecutionState * state = static_cast<S2EExecutionState *>(*itr);
        DECLARE_PLUGINSTATE(MemInjectorState2, state);

        if (state_id != -1 && state->getID() != state_id)
          continue;

        std::stringstream ss;

        ss << "0x" << std::hex << address << "_0";
        klee::ref<klee::Expr> expr = state->createSymbolicValue(ss.str(), width);

        plgState->symbolicRefreshersSaved[address] = std::make_pair(0, expr);
      }

      symbolicRefresherInjectors.insert(std::make_pair(address, Injector(address, width, refresh_count, INJ_SREFRESHER, state_id)));
      injectValues(currentState);

    }

    /**
     * Called once upon first instruction execution in the virtual machine.
     */
    void
    MemInjector2::slotInitialize(S2EExecutionState *state)
    {
        currentState = state;
      s2e()->getWarningsStream() << "[MemInjector2]: MemInjector2::slotInitialize called" << '\n';

      for (std::vector<Injector>::iterator itr = queuedInjections.begin();
          itr != queuedInjections.end(); itr++)
      {
        switch (itr->type)
        {
        case INJ_CONSTANT:
          doAddConstantInjector(itr->address, itr->aux, itr->width,
              itr->state_id);
          break;
        case INJ_INCREMENTOR:
          doAddConstantIncrementor(itr->address, itr->aux, itr->width,
              itr->state_id);
          break;
        case INJ_SYMBOLIC:
          doAddSymbolicInjector(itr->address, itr->width, itr->state_id);
          break;
        case INJ_SREFRESHER:
          doAddSymbolicRefresher(itr->address, itr->aux, itr->width,
              itr->state_id);
          break;
        }
      }

      queuedInjections.erase(queuedInjections.begin(), queuedInjections.end());
      initialized = true;

    }

    void
    MemInjector2::slotMemoryAccessConstant(S2EExecutionState *state,
        uint64_t address, klee::ref<klee::Expr> value,
        int type)
    {
      if (verbose)
        s2e()->getDebugStream() << "[MemInjector2]: Memory accessed at "
            << hexval(address) << '\n';

      if (type & MemoryMonitor::EMemoryWrite)
      {
        //Constant was overwritten
        std::map<uint64_t, Injector>::iterator itr = constantInjectors.find(
            address);
        if (itr != constantInjectors.end())
        {
          if (verbose)
            s2e()->getDebugStream()
                << "[MemInjector2]: Refreshing constant at *"
                << hexval(itr->first) << "[" << itr->second.width
                << "] = " << hexval(itr->second.aux)
                << " because it was overwritten" << '\n';

          if (!writeMemory(state, address, itr->second.aux, itr->second.width))
          {
            s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
                << hexval(address) << " failed!" << '\n';
          }
          return;
        }
      }

    }

    void
    MemInjector2::slotMemoryAccessConstantIncrementor(S2EExecutionState *state,
        uint64_t address, klee::ref<klee::Expr> value,
        int type)
    {
      //Get the plugin state for the current path
      DECLARE_PLUGINSTATE(MemInjectorState2, state);

      if (verbose)
        s2e()->getDebugStream() << "[MemInjector2]: Memory accessed at "
            << hexval(address) << '\n';

      std::map<uint64_t, uint64_t>::iterator itr =
          plgState->constantIncrementorValue.find(address);
      std::map<uint64_t, Injector>::iterator configItr =
          incrementingInjectors.find(address);

      if (itr != plgState->constantIncrementorValue.end()
          && configItr != incrementingInjectors.end())
      {
        if (type & MemoryMonitor::EMemoryRead)
        {
          //increment counter value in pluginState
          itr->second = (itr->second + 1) % configItr->second.aux;
        }
        if (verbose)
          s2e()->getDebugStream()
              << "[MemInjector2]: Refreshing constant incrementor at *"
              << hexval(itr->first) << "[" 
              << configItr->second.width << "] = " << hexval(itr->second) << '\n';

        if (!writeMemory(state, address, itr->second, configItr->second.width))
        {
          s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
              << hexval(address) << " failed!" << '\n';
        }
      }
      else
      {
        s2e()->getWarningsStream()
            << "[MemInjector2]: Constant incrementor at address "
            << hexval(address)
            << " is not initialized in plugin state or configuration!"
            << '\n';
      }
    }
    void
    MemInjector2::slotMemoryAccessSymbolicRefresher(S2EExecutionState *state,
        uint64_t address, klee::ref<klee::Expr> value,
        int type)
    {
      //Get the plugin state for the current path
      DECLARE_PLUGINSTATE(MemInjectorState2, state);

      if (verbose)
        s2e()->getDebugStream() << "[MemInjector2]: Memory accessed as "
            << hexval(type) << " at " << hexval(address)
            << '\n';

      if (type & MemoryMonitor::EMemoryWrite)
      {
        s2e()->getDebugStream() << "[MemInjector2]: Memory written to at "
            << hexval(address) << '\n';
        //Symbolic was overwritten, so just restore it
        std::map<uint64_t, std::pair<uint32_t, klee::ref<klee::Expr> > >::iterator itr =
            plgState->symbolicRefreshersSaved.find(address);
        std::map<uint64_t, Injector>::iterator configItr =
                    symbolicRefresherInjectors.find(address);

        if (itr != plgState->symbolicRefreshersSaved.end()
                && configItr != symbolicRefresherInjectors.end())
        {
            if (itr->second.first > configItr->second.aux)
            {
                if (verbose)
                    s2e()->getDebugStream()
                    << "[MemInjector2]: maximum number of refreshes has been exceeded ("
                    << itr->second.first << " > " << configItr->second.aux
                    << "), doing nothing" << '\n';
                //maximum number of refreshs has been reached, just ignore writes
                return;
            }

          state->writeMemory(address, itr->second.second);
          if (verbose)
            s2e()->getDebugStream()
                << "[MemInjector2]: Restoring symbolic refresher at address "
                << hexval(itr->first)
                << " after it has been overwritten" << '\n';
        }
        else
        {
          s2e()->getWarningsStream()
              << "[MemInjector2]: Either symbolic refresher configuration or state data "
                  "for address " << hexval(address) << " not found" << '\n';
        }
      }
      else if (type & MemoryMonitor::EMemoryRead)
      {
        std::map<uint64_t, std::pair<uint32_t, klee::ref<klee::Expr> > >::iterator itr =
            plgState->symbolicRefreshersSaved.find(address);
        std::map<uint64_t, Injector>::iterator configItr =
            symbolicRefresherInjectors.find(address);

        if (itr != plgState->symbolicRefreshersSaved.end()
            && configItr != symbolicRefresherInjectors.end())
        {
          if (itr->second.first > configItr->second.aux)
          {
            //maximum number of refreshes has been exceeded, don't bother
            return;
          }
          else
          {
            //create new symbolic value and plant it
            std::stringstream ss;

            itr->second.first++;
            ss << "0x" << std::hex << itr->first << "_" << itr->second.first;
            klee::ref<klee::Expr> expr = state->createSymbolicValue(ss.str(),
                configItr->second.width);
            state->writeMemory(address, expr);

            itr->second.second = expr;

            if (verbose)
              s2e()->getDebugStream()
                  << "[MemInjector2]: Refreshing symbolic refresher at address "
                  << hexval(itr->first) << " after read" << '\n';
          }
        }
        else
        {
          s2e()->getWarningsStream()
              << "[MemInjector2]: Either symbolic refresher configuration or state data "
                  "for address " << hexval(address) << " not found" << '\n';
        }
      }
    }

    void
    MemInjector2::injectValues(S2EExecutionState* state)
    {
        typedef std::pair<uint64_t, Injector> pair_type;

      foreach (const pair_type pair, constantInjectors)
      {
        if (pair.second.state_id == -1
            || pair.second.state_id == state->getID())
        {
            assert(state->isActive() && "trying to inject into inactive state");

          if (!writeMemory(state, pair.second.address, pair.second.aux, pair.second.width))
          {
            s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
                << hexval(pair.second.address) << " in state "
                << state->getID() << " failed!" << '\n';

            //TODO: handle error
          }
        }
      }

      foreach (const pair_type pair, incrementingInjectors)
      {
          if (pair.second.state_id == -1
                  || pair.second.state_id == state->getID())
          {
              assert(state->isActive() && "trying to inject into inactive state");

              DECLARE_PLUGINSTATE(MemInjectorState2, state);

              if (!writeMemory(state, pair.second.address, plgState->constantIncrementorValue[pair.second.address], pair.second.width))
              {
                  s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
                          << hexval(pair.second.address) << " in state "
                          << state->getID() << " failed!" << '\n';

                  //TODO: handle error
              }
          }
      }

      foreach(const pair_type pair, symbolicInjectors)
      {
          if (pair.second.state_id == -1
                  || pair.second.state_id == state->getID())
          {
              assert(state->isActive() && "trying to inject into inactive state");
              DECLARE_PLUGINSTATE(MemInjectorState2, state);

              if (plgState->symbolicInject[pair.second.address] == true)
              {
                  std::stringstream ss;

                  ss << "0x" << std::hex << pair.second.address;
                  klee::ref<klee::Expr> expr = state->createSymbolicValue(ss.str(), pair.second.width);

                  if (!state->writeMemory(pair.second.address, expr))
                  {
                      s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
                              << hexval(pair.second.address) << " in state "
                              << state->getID() << " failed!" << '\n';
                  }
                  if (verbose)
                      s2e()->getDebugStream()
                      << "[MemInjector2]: Planting symbolic value at address "
                      << hexval(pair.second.address) << " in state "
                      << state->getID() << '\n';
                  plgState->symbolicInject[pair.second.address] = false;
              }
          }
      }

      foreach(const pair_type pair, symbolicRefresherInjectors)
      {
          if (pair.second.state_id == -1
                  || pair.second.state_id == state->getID())
          {
              assert(state->isActive() && "trying to inject into inactive state");
              DECLARE_PLUGINSTATE(MemInjectorState2, state);

              //if max number of refreshs has been reached
              if (plgState->symbolicRefreshersSaved[pair.second.address].first > pair.second.aux)
                  continue;

              if (!state->writeMemory(pair.second.address, plgState->symbolicRefreshersSaved[pair.second.address].second))
              {
                  s2e()->getWarningsStream() << "[MemInjector2]: Write to address "
                          << hexval(pair.second.address) << " in state "
                          << state->getID() << " failed!" << '\n';
              }

              if (verbose)
                  s2e()->getDebugStream()
                  << "[MemInjector2]: Planting symbolic refresher at address "
                  << hexval(pair.second.address) << " in state "
                  << state->getID() << '\n';
          }

      }




    }

    void
    MemInjector2::slotStateSwitch(S2EExecutionState* oldState,
        S2EExecutionState* curState)
    {
        s2e()->getDebugStream()
                                              << "[MemInjector2]: switching from state " 
                                              << oldState->getID() <<  " to "  << curState->getID()
                                              << '\n';
      injectValues(curState);

      currentState = curState;
    }

  void
  MemInjector2::slotExecuteFork(S2EExecutionState* state,
      const std::vector<S2EExecutionState*>& newStates,
      const std::vector<klee::ref<klee::Expr> >& newConditions)
  {
    for (std::vector<S2EExecutionState*>::const_iterator itr =
        newStates.begin(); itr != newStates.end(); itr++)
    {
      if ((*itr)->getID() != state->getID())
      {

        //TODO: Add code to add
      }
    }

  }

  void
  MemInjector2::readConfigPair(string key,
      std::vector<std::vector<int64_t> > &container)
  {
    ConfigFile *cfg = s2e()->getConfig();

    for (int x = 1; x < cfg->getListSize(key) + 1; x++)
    {
      stringstream ss;
      ConfigFile::integer_list list;
      bool ok;

      ss << key << "[" << x << "]";
      list = cfg->getIntegerList(ss.str(), ConfigFile::integer_list(), &ok);

      if (list.size() == 0)
        continue;

      std::vector < int64_t > line;
      for (size_t i = 0; i < list.size() && i < 4; i++)
      {
        line.push_back(list[i]);
      }

      container.push_back(line);
    }
  }

//////////////////////////////////////////////////////////////
//Holds per-state information.
//////////////////////////////////////////////////////////////
  MemInjectorState2::MemInjectorState2()
  {
  }
  MemInjectorState2::~MemInjectorState2()
  {
  }
  MemInjectorState2*
  MemInjectorState2::clone() const
  {
    return new MemInjectorState2(*this);
  }
  PluginState *
  MemInjectorState2::factory(Plugin *p, S2EExecutionState *s)
  {
    return new MemInjectorState2();
  }

} // namespace plugins
} // namespace s2e
