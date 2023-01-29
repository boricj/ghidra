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
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSymbol;

public interface ElfRelocatableSymbol extends Comparable<ElfRelocatableSymbol> {
	public ElfHeader getElfHeader();

	public ElfRelocatableSection getRelocatableSection();

	public ElfRelocatableSymbolTable getRelocatableSymbolTable();

	public byte getBinding();

	public int getSymbolIndex();
	public void setSymbolIndex(int index);

	public default int getSectionIndex() {
		ElfRelocatableSection relocatableSection = getRelocatableSection();
		if (relocatableSection == null) {
			return 0;
		}

		ElfHeader elf = getElfHeader();
		String memoryBlockName = relocatableSection.getName();
		List<ElfSectionHeader> sections = Arrays.asList(elf.getSections());

		int sectionIdx = sections.indexOf(elf.getSection(memoryBlockName));
		if (sectionIdx > Short.MAX_VALUE - 1) {
			throw new RuntimeException(
				"Too many sections for ELF relocatable object exporter!");
		}

		return sectionIdx;
	}

	public int getRank();

	public ElfSymbol emitSymbol() throws IOException;
}
