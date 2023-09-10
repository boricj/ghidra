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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MatchMemoryBlock {
	private static class MemoryBlockFragment {
		private final int offset;
		private final byte[] bytes;

		public MemoryBlockFragment(MemoryBlock memoryBlock, int offset, int size)
				throws MemoryAccessException, AddressOutOfBoundsException {
			this.offset = offset;
			this.bytes = new byte[size];

			memoryBlock.getBytes(memoryBlock.getStart().add(offset), bytes);
		}

		public int mismatch(byte[] target, int i) {
			int mismatchedIndex = Arrays.mismatch(bytes, 0, bytes.length, target, i + offset, i + offset + bytes.length);
			return mismatchedIndex + (mismatchedIndex != -1 ? offset : 0);
		}
	}

	private MatchMemoryBlock() {
		// non-instantiable
	}

	// Finds one-to-many matches in functions from addressSet A and Address Set B
	public static List<MatchedMemoryBlock> matchMemoryBlock(Program aProgram, AddressSetView setA,
			Program bProgram, AddressSetView setB, int minimumMatchSize, double minimumMatchThreshold,
			double minimumEntropy, boolean skipRelocationBytes, TaskMonitor monitor) throws CancelledException {
		setA = removeUninitializedBlocks(aProgram, setA);
		setB = removeUninitializedBlocks(bProgram, setB);

		MemoryBlock[] aMemoryBlocks = aProgram.getMemory().getBlocks();
		MemoryBlock[] bMemoryBlocks = bProgram.getMemory().getBlocks();

		List<MatchedMemoryBlock> result = new ArrayList<>();

		for (MemoryBlock aMemoryBlock : aMemoryBlocks) {
			if (aMemoryBlock.getSize() < minimumMatchSize) {
				continue;
			}

			AddressSetView aMemoryBlockSet = aProgram.getAddressFactory().getAddressSet(aMemoryBlock.getStart(), aMemoryBlock.getEnd());
			if (!setA.contains(aMemoryBlockSet)) {
				continue;
			}

			Iterator<Relocation> aRelocations;
			if (skipRelocationBytes) {
				aRelocations = aProgram.getRelocationTable().getRelocations(aMemoryBlockSet);
			} else {
				aRelocations = Collections.emptyIterator();
			}

			try {
				List<MemoryBlockFragment> aFragments = buildMemoryBlockFragments(aMemoryBlock, aRelocations);
				double aMemoryBlockEntropy = computeEntropyOf(aFragments, (int) aMemoryBlock.getSize());
				if (aMemoryBlockEntropy < minimumEntropy) {
					continue;
				}

				for (MemoryBlock bMemoryBlock : bMemoryBlocks) {
					if (aMemoryBlock.getSize() > bMemoryBlock.getSize()) {
						continue;
					}

					AddressSetView bMemoryBlockSet = setB.intersectRange(bMemoryBlock.getStart(), bMemoryBlock.getEnd());

					for (AddressRange bRange : bMemoryBlockSet.getAddressRanges()) {
						if (bRange.getLength() < aMemoryBlock.getSize()) {
							continue;
						}

						byte bBytes[] = new byte[(int) bRange.getLength()];
						bMemoryBlock.getBytes(bRange.getMinAddress(), bBytes);

						result.addAll(matchMemoryBlockFragments(aProgram, bProgram, aMemoryBlock, aFragments,
								(int) aMemoryBlock.getSize(), bRange.getMinAddress(), bBytes, minimumMatchSize,
								minimumMatchThreshold, aMemoryBlockEntropy));
					}
				}
			}
			catch (MemoryAccessException e) {
				// Ignored
			}
		}

		return result;
	}

	private static double computeEntropyOf(List<MemoryBlockFragment> fragments, int length) {
		int[] histo = new int[256];
		for (MemoryBlockFragment fragment : fragments) {
			for (byte byte_: fragment.bytes) {
				++histo[128 + byte_];
			}
		}

		double sum = 0;
		double logtwo = Math.log(2.0);
		for(int i = 0; i < 256; ++i) {
			if (histo[i] > 0) {
				double prob = ((double) histo[i]) / length;
				sum += -prob * (Math.log(prob) / logtwo);
			}
		}

		return sum / 8;
	}

	private static List<MemoryBlockFragment> buildMemoryBlockFragments(MemoryBlock memoryBlock,
			Iterator<Relocation> relocations) throws MemoryAccessException {
		List<MemoryBlockFragment> fragments = new ArrayList<>();
		int memoryBlockSize = (int) memoryBlock.getSize();
		int offset = 0;

		while (relocations.hasNext()) {
			Relocation relocation = relocations.next();
			int relocationOffset = (int) relocation.getAddress().subtract(memoryBlock.getStart());
			int relocationSize = relocation.getBytes().length;

			fragments.add(new MemoryBlockFragment(memoryBlock, offset, relocationOffset - offset));

			offset += relocationOffset - offset;
			offset += relocationSize;
		}

		if (offset != memoryBlockSize) {
			fragments.add(new MemoryBlockFragment(memoryBlock, offset, memoryBlockSize - offset));
		}

		return fragments;
	}

	private static List<MatchedMemoryBlock> matchMemoryBlockFragments(Program aProgram, Program bProgram,
			MemoryBlock aMemoryBlock, List<MemoryBlockFragment> aFragments, int aSize, Address bAddress,
			byte[] bBytes, int minimumMatchSize, double minimumMatchThreshold, double memoryBlockEntropy) {
		List<MatchedMemoryBlock> matches = new ArrayList<>();
		int comparedBytes = aFragments.stream().mapToInt(f -> f.bytes.length).sum();

		for (int offset = 0; offset <= bBytes.length - aSize; offset++) {
			int mismatchedIndex = -1;
			for (MemoryBlockFragment aFragment : aFragments) {
				mismatchedIndex = aFragment.mismatch(bBytes, offset);
				if (mismatchedIndex != -1) {
					break;
				}
			}

			if (mismatchedIndex == -1) {
				mismatchedIndex = aSize;
			}

			double threshold = ((double) mismatchedIndex) / aSize;

			if (mismatchedIndex >= minimumMatchSize && threshold > minimumMatchThreshold) {
				matches.add(new MatchedMemoryBlock(aProgram, bProgram, aMemoryBlock, bAddress.add(offset),
						comparedBytes, mismatchedIndex, memoryBlockEntropy));
			}
		}

		return matches;
	}

	private static AddressSetView removeUninitializedBlocks(Program program, AddressSetView addrSet) {
		return addrSet.intersect(program.getMemory().getLoadedAndInitializedAddressSet());
	}
}
