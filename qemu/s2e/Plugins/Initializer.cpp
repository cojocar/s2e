#include "Initializer.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Initializer, "Plugin which fires a signal on the execution of the first instruction. It's fired only once for initialization purposes", "Initializer",
						);

#define OUTPUT(arg) (s2e()->getMessagesStream() << "[Initializer]: " << arg)

void Initializer::initialize()
{
	connExecuteInstr = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &Initializer::slotTranslateInstr));
}

void Initializer::slotTranslateInstr(ExecutionSignal *signal, 
                                    S2EExecutionState *state,
                                    TranslationBlock *tb,
                                    uint64_t pc)
{    
	onInitialize.emit(state);
	connExecuteInstr.disconnect();
}

} // namespace plugins
} // namespace s2e
