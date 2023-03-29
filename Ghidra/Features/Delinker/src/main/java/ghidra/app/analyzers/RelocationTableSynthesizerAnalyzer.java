/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.analyzers;

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.RelocationTableSynthesizer;
import ghidra.program.model.reloc.RelocationTableSynthesizerObserver;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RelocationTableSynthesizerAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Relocation table synthesizer";
	private final static String DESCRIPTION =
		"Synthesize a relocation table for this program";

	public RelocationTableSynthesizerAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(false);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setPrototype();
	}

	public static RelocationTableSynthesizer getSynthesizer(Program program) {
		List<RelocationTableSynthesizer> synthesizers =
			ClassSearcher.getInstances(RelocationTableSynthesizer.class);
		for (RelocationTableSynthesizer synthesizer : synthesizers) {
			if (synthesizer.canAnalyze(program)) {
				return synthesizer;
			}
		}

		return null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();
		RelocationTableSynthesizer synthesizer = getSynthesizer(program);
		RelocationTableSynthesizerObserver observer = new RelocationTableSynthesizerSynthesizer(program, set, log);

		for (Function function : functionManager.getFunctions(set, true)) {
			monitor.setMessage("Relocation table rebuilder: " + function.getName(true));
			monitor.checkCancelled();

			try {
				synthesizer.processFunction(function, observer);
			}
			catch (MemoryAccessException e) {
				log.appendException(e);
			}
		}

		for (Data data : listing.getDefinedData(set, true)) {
			monitor.setMessage(
				"Relocation table rebuilder: " + data.getAddressString(true, true));
			monitor.checkCancelled();

			try {
				processData(synthesizer, data, observer);
			}
			catch (MemoryAccessException e) {
				log.appendException(e);
			}
		}

		observer.finished();

		return true;
	}

	private static void processData(RelocationTableSynthesizer synthesizer, Data parent,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		if (parent.isPointer()) {
			byte bytes[] = parent.getBytes();
			synthesizer.processPointer(parent, bytes, observer);
		}
		else if (parent.isArray() && parent.getNumComponents() >= 1) {
			Data data = parent.getComponent(0);

			if (data.isPointer() || data.isArray() || data.isStructure()) {
				for (int i = 0; i < parent.getNumComponents(); i++) {
					processData(synthesizer, parent.getComponent(i), observer);
				}
			}
		}
		else if (parent.isStructure()) {
			for (int i = 0; i < parent.getNumComponents(); i++) {
				processData(synthesizer, parent.getComponent(i), observer);
			}
		}
	}

	@Override
	public boolean canAnalyze(Program program) {
		return getSynthesizer(program) != null;
	}
}
