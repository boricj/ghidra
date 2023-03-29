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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.reloc.RelocationTableSynthesizerObserver;

public class RelocationTableSynthesizerSynthesizer implements RelocationTableSynthesizerObserver {
	private Program program;
	private MessageLog log;

	private Map<Address, Relocation> originalRelocations = new HashMap<>();
	private Map<Address, Relocation> newRelocations = new HashMap<>();

	public RelocationTableSynthesizerSynthesizer(Program program, AddressSetView set, MessageLog log) {
		this.program = program;
		this.log = log;

		for (Relocation relocation : (Iterable<Relocation>) () -> program.getRelocationTable()
				.getRelocations(set)) {
			originalRelocations.put(relocation.getAddress(), relocation);
		}
	}

	@Override
	public MessageLog getLog() {
		return log;
	}

	@Override
	public void observe(Relocation relocation) {
		newRelocations.put(relocation.getAddress(), relocation);
	}

	@Override
	public void finished() {
		RelocationTable relocTable = program.getRelocationTable();

		SortedSet<Address> addresses = new TreeSet<>(originalRelocations.keySet());
		addresses.addAll(newRelocations.keySet());

		for (Address addr : addresses) {
			Relocation originalRelocation = originalRelocations.getOrDefault(addr, null);
			Relocation newRelocation = newRelocations.getOrDefault(addr, null);

			if (newRelocation == null && originalRelocation != null) {
				relocTable.remove(originalRelocation);
			}
			else if (newRelocation != null && originalRelocation == null &&
					!newRelocation.equals(originalRelocation)) {
				relocTable.add(newRelocation.getAddress(), Relocation.Status.APPLIED,
						newRelocation.getType(), newRelocation.getValues(),
						newRelocation.getBytes(), newRelocation.getSymbolName());
			}
		}
	}
}
