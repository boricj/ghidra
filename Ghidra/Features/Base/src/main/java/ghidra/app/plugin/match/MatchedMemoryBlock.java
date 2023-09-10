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
package ghidra.app.plugin.match;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class MatchedMemoryBlock {
	private final Program aProg;
	private final Program bProg;
	private final MemoryBlock aMemoryBlock;
	private final Address bAddr;
	private final int comparedBytes;
	private final int matchSize;
	private final double memoryBlockEntropy;

	MatchedMemoryBlock(Program aProg, Program bProg, MemoryBlock aMemoryBlock, Address bAddr, int comparedBytes,
			int matchSize, double memoryBlockEntropy) {
		this.aProg = aProg;
		this.bProg = bProg;
		this.aMemoryBlock = aMemoryBlock;
		this.bAddr = bAddr;
		this.comparedBytes = comparedBytes;
		this.matchSize = matchSize;
		this.memoryBlockEntropy = memoryBlockEntropy;
	}

	public Program getAProgram() {
		return aProg;
	}

	public Program getBProgram() {
		return bProg;
	}

	public MemoryBlock getAMemoryBlock() {
		return aMemoryBlock;
	}

	public Address getBDataAddress() {
		return bAddr;
	}

	public int getComparedBytes() {
		return comparedBytes;
	}

	public int getMatchSize() {
		return matchSize;
	}

	public double getMemoryBlockEntropy() {
		return memoryBlockEntropy;
	}
}
