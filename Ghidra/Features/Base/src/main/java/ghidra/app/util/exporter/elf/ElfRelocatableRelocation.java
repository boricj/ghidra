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
package ghidra.app.util.exporter.elf;

import java.io.IOException;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;

public final class ElfRelocatableRelocation {
	private final ElfRelocatableSection elfRelocatableSection;
	private final ElfRelocatableSymbol elfRelocatableSymbol;
	private final int relocationType;
	private final int relocationOffset;

	public ElfRelocatableRelocation(ElfRelocatableSection elfRelocatableSection,
			ElfRelocatableSymbol elfRelocatableSymbol, int relocationType, int relocationOffset) {
		this.elfRelocatableSection = elfRelocatableSection;
		this.elfRelocatableSymbol = elfRelocatableSymbol;
		this.relocationType = relocationType;
		this.relocationOffset = relocationOffset;
	}

	public ElfRelocation emitRelocation(ElfRelocationTable relocationTable) throws IOException {
		ElfHeader elfHeader = elfRelocatableSection.getElfHeader();
		int symbolIdx = elfRelocatableSymbol.getSymbolIndex();
		int relocationIdx = relocationTable.getRelocationCount();
		boolean withAddend = relocationTable.hasAddendRelocations();

		long r_offset = relocationOffset;
		long r_info = elfHeader.is32Bit()
				? relocationType + (symbolIdx << 8)
				: relocationType + ((long) symbolIdx << 32);
		// FIXME: ELF relocation addend not handled.
		long r_addend = 0;

		return ElfRelocation.createElfRelocation(elfHeader, relocationIdx, withAddend, r_offset,
			r_info, r_addend);
	}
}
