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
package ghidra.feature.vt.api.correlator.program;

import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class ExactMatchMemoryBlockProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {

	static final String DESC =
		"Compares memory block bytes. It reports back any source memory blocks found in the destination program.";

	public static final String EXACT_MATCH = "Exact Memory Block Bytes Match";
	public static final String MINIMUM_BYTES_MATCHED = "Match minimum size";
	public static final int MINIMUM_BYTES_MATCHED_DEFAULT = 10;
	public static final String MINIMUM_THRESHOLD_MATCHED = "Match minimum threshold";
	public static final double MINIMUM_THRESHOLD_MATCHED_DEFAULT = 0.75;
	public static final String MINIMUM_ENTROPY = "Minimum entropy of section";
	public static final double MINIMUM_ENTROPY_DEFAULT = 0.10;
	public static final String SKIP_RELOCATION_BYTES = "Skip relocation bytes";
	public static final boolean SKIP_RELOCATION_BYTES_DEFAULT = true;

	@Override
	public int getPriority() {
		return 20;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new MemoryBlockMatchProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, EXACT_MATCH);
	}

	@Override
	public String getName() {
		return EXACT_MATCH;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(EXACT_MATCH);
		options.setInt(MINIMUM_BYTES_MATCHED, MINIMUM_BYTES_MATCHED_DEFAULT);
		options.setDouble(MINIMUM_THRESHOLD_MATCHED, MINIMUM_THRESHOLD_MATCHED_DEFAULT);
		options.setDouble(MINIMUM_ENTROPY, MINIMUM_ENTROPY_DEFAULT);
		options.setBoolean(SKIP_RELOCATION_BYTES, SKIP_RELOCATION_BYTES_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return DESC;
	}
}
