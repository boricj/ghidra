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

import java.util.List;

import ghidra.app.plugin.match.MatchMemoryBlock;
import ghidra.app.plugin.match.MatchedMemoryBlock;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockMatchProgramCorrelator extends VTAbstractProgramCorrelator {
	private final String name;

	public MemoryBlockMatchProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options, String name) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
				destinationAddressSet, options);
		this.name = name;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		int minimumMatchSize = getOptions().getInt(ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_BYTES_MATCHED,
				ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_BYTES_MATCHED_DEFAULT);
		double minimumMatchThreshold = getOptions().getDouble(
				ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_THRESHOLD_MATCHED,
				ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_THRESHOLD_MATCHED_DEFAULT);
		double minimumEntropy = getOptions().getDouble(ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_ENTROPY,
				ExactMatchMemoryBlockProgramCorrelatorFactory.MINIMUM_ENTROPY_DEFAULT);
		boolean skipRelocationBytes = getOptions().getBoolean(
				ExactMatchMemoryBlockProgramCorrelatorFactory.SKIP_RELOCATION_BYTES,
				ExactMatchMemoryBlockProgramCorrelatorFactory.SKIP_RELOCATION_BYTES_DEFAULT);

		List<MatchedMemoryBlock> matchedDataList = MatchMemoryBlock.matchMemoryBlock(getSourceProgram(),
				getSourceAddressSet(), getDestinationProgram(),
				getDestinationAddressSet(), minimumMatchSize, minimumMatchThreshold, minimumEntropy,
				skipRelocationBytes, monitor);

		monitor.initialize(matchedDataList.size());
		monitor.setMessage("Finally, adding " + matchedDataList.size() + " match objects...");
		final int skipAmount = 1000;
		int count = 0;
		for (MatchedMemoryBlock matchedData : matchedDataList) {
			++count;
			if (count % skipAmount == 0) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.incrementProgress(skipAmount);
			}
			VTMatchInfo matchInfo = generateMatchFromMatchedMemoryBlock(matchSet, matchedData);
			matchSet.addMatch(matchInfo);
		}
	}

	private VTMatchInfo generateMatchFromMatchedMemoryBlock(VTMatchSet matchSet, MatchedMemoryBlock matchedData) {
		MemoryBlock aMemoryBlock = matchedData.getAMemoryBlock();
		Address sourceAddress = aMemoryBlock.getStart();
		Address destinationAddress = matchedData.getBDataAddress();

		VTScore similarity = new VTScore(((float) matchedData.getMatchSize()) / aMemoryBlock.getSize());
		VTScore confidence = new VTScore(20.0f * matchedData.getMemoryBlockEntropy() - 10.0f);

		int sourceLength = (int) aMemoryBlock.getSize();

		VTMatchInfo matchInfo = new VTMatchInfo(matchSet);

		matchInfo.setSimilarityScore(similarity);
		matchInfo.setConfidenceScore(confidence);
		matchInfo.setSourceLength(sourceLength);
		matchInfo.setSourceAddress(sourceAddress);
		matchInfo.setDestinationLength(matchedData.getMatchSize());
		matchInfo.setDestinationAddress(destinationAddress);
		matchInfo.setTag(null);
		matchInfo.setAssociationType(VTAssociationType.MEMORY_BLOCK);

		return matchInfo;
	}

	@Override
	public String getName() {
		return name;
	}
}
