/**
 * @author Jonas Zaddach <zaddach@eurecom.fr>
 * Based on the MemInjector plugin by Luka.
 *
 * This plugin is used to inject values into the guest memory space.
 * There are four different modes of operation:
 * <ul>
 *   <li>In constant mode, a constant is planted in memory upon startup and refreshed every time
 *      it is overwritten. An example configuration for this mode would be
 *
 *      <code>.memRangesConstant = { {address, value, width} }</code>
 *
 *      <b>address</b> is the virtual memory address where the value is planted.
 *      <b>value</b> is the value that will be written to that address.
 *      <b>width</b> is the size of the value to write in bits, e.g. 32 for a 4-byte integer.
 *      <b>state_id</b>The id of the state in which the value should be inserted, or -1 for every state.
 *          The state id must exist at the point of injection.
 *   </li>
 *   <li>In constant incrementor mode, a constant is planted in memory upon startup. When it is
 *       overwritten, the previous value is restored. When the constant is read, its value is increased
 *       by 1 up to the maximum value, where it wraps around.
 *
 *       <code>.memRangesConstantIncrementors = { {address, max_incrementor_value, width} }</code>
 *
 *      <b>address</b> is the virtual memory address where the value is planted.
 *      <b>max_incrementor_value</b> the value where the incrementor wraps around, e.g. 3 if 0, 1 and 2 are valid incrementor values.
 *        This value is truncated to the variable length if a too large value for a variable type is given.
 *      <b>width</b> is the size of the value to write in bits, e.g. 32 for a 4-byte integer.
 *      <b>state_id</b>The id of the state in which the value should be inserted, or -1 for every state.
 *          The state id must exist at the point of injection.
 *  </li>
 *  <li>In symbolic mode, a symbolic value is planted upon startup. It is not refreshed upon write,
 *    and will always stay the same during several reads.
 *
 *    <code>.memRangesSymbolic = { {address, 0, width} }</code>
 *
 *    <b>address</b> is the virtual memory address where the value is planted.
 *    <b>0</b> currently unused, has to be 0.
 *    <b>width</b> is the size of the value to write in bits, e.g. 32 for a 4-byte integer.
 *    <b>state_id</b>The id of the state in which the value should be inserted, or -1 for every state.
 *          The state id must exist at the point of injection.
 *  </li>
 *  <li>In symbolic refresher mode, a symbolic value is planted upon startup. If the value is overwritten,
 *      the previous value is restored. If the value is read, the symbolic value is overwritten with a new
 *      without constraints; the read value will keep existing in its new location.
 *      If the maximum number of refreshs has been reached, the memory is not touched any more by the plugin
 *      (neither on write nor on read of the guest).
 *      <code>.memRangesConstantIncrementors = {{address, number_of_refreshs, width}}</code>
 *
 *      <b>address</b> is the virtual memory address where the value is planted.
 *      <b>number_of_refreshs</b> is the number of times that a new symbolic value will be planted because the existing one has been read.
 *      <b>width</b> is the size of the value to write in bits, e.g. 32 for a 4-byte integer.
 *      <b>state_id</b>The id of the state in which the value should be inserted, or -1 for every state.
 *          The state id must exist at the point of injection.
 *  </li>
 */

#ifndef S2E_PLUGINS_MEMINJECTOR2_H
#define S2E_PLUGINS_MEMINJECTOR2_H

#include <tr1/memory>
#include <vector>

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/MemoryMonitor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>

#include "Initializer.h"

using std::map;
using std::vector;
using std::tr1::shared_ptr;

namespace s2e {
namespace plugins {
  
class MemInjector2 : public Plugin
{
	S2E_PLUGIN

public:
        enum InjectorType
        {
          INJ_CONSTANT,
          INJ_INCREMENTOR,
          INJ_SYMBOLIC,
          INJ_SREFRESHER
        };

        struct Injector
        {
            uint64_t address; 
            uint64_t width; 
            uint64_t aux; 
            InjectorType type; 
            int state_id;

            Injector(uint64_t address, uint64_t width, uint64_t aux, InjectorType type, int state_id);
            Injector(const Injector& other);
            Injector();

//            Injector& operator=(Injector&);
        };

	MemInjector2(S2E* s2e);
	void initialize();

        void addConstantInjector(uint64_t address, uint64_t value, uint64_t width = 32, int state_id = -1);
        void addConstantIncrementor(uint64_t address, uint64_t max_value, uint64_t width = 32, int state_id = -1);
        void addSymbolicInjector(uint64_t address, uint64_t width = 32, int state_id = -1);
        void addSymbolicRefresher(uint64_t address, uint64_t refresh_count, uint64_t width = 32, int state_id = -1);

        void removeInjector(uint64_t address);

        const std::vector<Injector> listInjectors();
        const std::vector<Injector> listQueuedInjectors();


private:
	bool verbose;
	bool initialized;
	
//	Initializer *m_initializer;
//	MemoryMonitor *m_memoryMonitor;

	std::vector<Injector> queuedInjections;
	S2EExecutionState * currentState;

	void doAddConstantInjector(uint64_t address, uint64_t value, uint64_t width, int state_id);
	void doAddConstantIncrementor(uint64_t address, uint64_t max_value, uint64_t width, int state_id);
        void doAddSymbolicInjector(uint64_t address, uint64_t width, int state_id);
        void doAddSymbolicRefresher(uint64_t address, uint64_t refresh_count, uint64_t width, int state_id);

        void injectValues(S2EExecutionState* state);

        std::map<uint64_t, Injector> constantInjectors;
        std::map<uint64_t, Injector> incrementingInjectors;
        std::map<uint64_t, Injector> symbolicInjectors;
        std::map<uint64_t, Injector> symbolicRefresherInjectors;

	void slotMemoryAccessConstant(S2EExecutionState *state,
	    uint64_t address,
	    klee::ref<klee::Expr> value,
	    int type);
	void slotMemoryAccessSymbolicRefresher(S2EExecutionState *state,
	            uint64_t address,
	            klee::ref<klee::Expr> value,
	            int type);
	void slotMemoryAccessConstantIncrementor(S2EExecutionState *state,
	                    uint64_t address,
	                    klee::ref<klee::Expr> value,
	                    int type);
	void slotExecuteFork(S2EExecutionState* state, const std::vector<S2EExecutionState*>& newStates,
	        const std::vector<klee::ref<klee::Expr> >& newConditions);

	void slotStateSwitch(S2EExecutionState* oldState, S2EExecutionState* curState);

	void slotInitialize(S2EExecutionState *state);
	bool writeMemory(S2EExecutionState* state, uint64_t address, uint64_t val, uint64_t width);

	void readConfigPair(string key, std::vector<std::vector<int64_t> > &container);
};

class MemInjectorState2: public PluginState
{
private:
	map<uint64_t, uint64_t> constantIncrementorValue;
	map<uint64_t, std::pair< uint32_t, klee::ref<klee::Expr> > > symbolicRefreshersSaved;
	map<uint64_t, bool> symbolicInject;

public:
	MemInjectorState2();
	virtual ~MemInjectorState2();
	static PluginState *factory(Plugin *p, S2EExecutionState *s);
	virtual MemInjectorState2* clone() const;

	friend class MemInjector2;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MEMINJECTOR2_H

