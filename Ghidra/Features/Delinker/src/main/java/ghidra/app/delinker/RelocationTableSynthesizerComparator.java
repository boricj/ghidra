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
import ghidra.program.model.reloc.RelocationTableSynthesizerObserver;

public class RelocationTableSynthesizerComparator implements RelocationTableSynthesizerObserver {
	private MessageLog log;

	private Map<Address, Relocation> recovered = new HashMap<>();
	private Map<Address, Relocation> unrecovered = new HashMap<>();
	private Map<Address, Relocation> notMatchingExisting = new HashMap<>();
	private Map<Address, Relocation> notMatchingAny = new HashMap<>();

	public RelocationTableSynthesizerComparator(Program program, AddressSetView set, MessageLog log) {
		this.log = log;

		for (Relocation relocation : (Iterable<Relocation>) () -> program.getRelocationTable()
				.getRelocations(set)) {
			this.unrecovered.put(relocation.getAddress(), relocation);
		}
	}

	@Override
	public MessageLog getLog() {
		return log;
	}

	@Override
	public void observe(Relocation relocation) {
		Address addr = relocation.getAddress();
		if (recovered.containsKey(addr)) {
			return;
		}

		Relocation candidate = unrecovered.getOrDefault(addr, null);
		if (candidate != null) {
			if (compareRelocations(relocation, candidate)) {
				recovered.put(addr, relocation);
				unrecovered.remove(addr);
				notMatchingExisting.remove(addr);
			}
			else {
				notMatchingExisting.put(addr, relocation);
			}
		}
		else {
			notMatchingAny.put(addr, relocation);
		}
	}

	@Override
	public void finished() {
		SortedSet<Address> addresses = new TreeSet<>(recovered.keySet());
		addresses.addAll(unrecovered.keySet());
		addresses.addAll(notMatchingAny.keySet());
		addresses.addAll(notMatchingExisting.keySet());

		for (Address addr : addresses) {
			if (notMatchingExisting.containsKey(addr)) {
				log.appendMsg(addr.toString(),
					"Reconstructed relocation does not match existing relocation at this address");
			}
			else if (notMatchingAny.containsKey(addr)) {
				log.appendMsg(addr.toString(),
					"Reconstructed relocation for non-existing relocation at this address");
			}
			else if (unrecovered.containsKey(addr)) {
				log.appendMsg(addr.toString(),
					"No reconstructed relocation for existing relocation at this address");
			}
		}
	}

	private static boolean compareRelocations(Relocation r1, Relocation r2) {
		if (r1.getType() == r2.getType() &&
			Arrays.equals(r1.getBytes(), r2.getBytes()) &&
			r1.getSymbolName().equals(r2.getSymbolName())) {
			return true;
		}

		return false;
	}
}
