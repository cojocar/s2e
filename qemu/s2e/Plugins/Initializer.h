#ifndef S2E_PLUGINS_INITIALIZER_H
#define S2E_PLUGINS_INITIALIZER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

using namespace std;

namespace s2e {
namespace plugins {

class Initializer : public Plugin
{
	S2E_PLUGIN

public:
	Initializer(S2E* s2e): Plugin(s2e) {}
	void initialize();

	/** Signal emited when first instruction is executed */
	sigc::signal<void, S2EExecutionState * >
			   onInitialize;

private:
	sigc::connection connExecuteInstr;

	void slotTranslateInstr(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_INITIALIZER_H

