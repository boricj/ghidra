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
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;

public final class ElfRelocatableSymbolSection implements ElfRelocatableSymbol {
	private ElfHeader elfHeader;
	private ElfRelocatableSection elfRelocatableSection;
	private ElfRelocatableSymbolTable elfRelocatableSymbolTable;
	private int symbolIndex = -1;

	public ElfRelocatableSymbolSection(ElfHeader elfHeader, ElfRelocatableSection elfRelocatableSection, ElfRelocatableSymbolTable elfRelocatableSymbolTable) {
		this.elfHeader = elfHeader;
		this.elfRelocatableSection = elfRelocatableSection;
		this.elfRelocatableSymbolTable = elfRelocatableSymbolTable;
	}

	@Override
	public ElfHeader getElfHeader() {
		return elfHeader;
	}

	@Override
	public ElfRelocatableSection getRelocatableSection() {
		return elfRelocatableSection;
	}

	@Override
	public ElfRelocatableSymbolTable getRelocatableSymbolTable() {
		return elfRelocatableSymbolTable;
	}

	@Override
	public byte getBinding() {
		return ElfSymbol.STB_LOCAL;
	}

	@Override
	public int getSymbolIndex() {
		return symbolIndex;
	}

	@Override
	public void setSymbolIndex(int index) {
		symbolIndex = index;
	}

	@Override
	public int getRank() {
		return 2;
	}

	@Override
	public ElfSymbol emitSymbol() throws IOException {
		ElfSymbolTable symbolTable = elfRelocatableSymbolTable.getSymbolTable();

		String name = elfRelocatableSection.getName();
		int symbolIdx = symbolTable.getSymbols().length;

		return ElfSymbol.createDefinedSymbol(elfHeader, symbolTable, name, 0, 0, 0,
			ElfSymbol.STT_SECTION, ElfSymbol.STB_LOCAL, ElfSymbol.STV_DEFAULT,
			(short) getSectionIndex(), symbolIdx);
	}

	@Override
	public int compareTo(ElfRelocatableSymbol other) {
		if (getRank() != other.getRank()) {
			return getRank() - other.getRank();
		}

		return getSectionIndex() - other.getSectionIndex();
	}
}
