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
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;

public final class ElfRelocatableSymbolFile implements ElfRelocatableSymbol {
	private ElfHeader elfHeader;
	private ElfRelocatableSymbolTable elfRelocatableSymbolTable;
	private String fileName;
	private int symbolIndex = -1;

	public ElfRelocatableSymbolFile(ElfHeader elfHeader,
			ElfRelocatableSymbolTable elfRelocatableSymbolTable, String fileName) {
		this.elfHeader = elfHeader;
		this.elfRelocatableSymbolTable = elfRelocatableSymbolTable;
		this.fileName = fileName;
	}

	@Override
	public ElfHeader getElfHeader() {
		return elfHeader;
	}

	@Override
	public ElfRelocatableSection getRelocatableSection() {
		return null;
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
		return 1;
	}

	@Override
	public ElfSymbol emitSymbol() throws IOException {
		ElfStringTable stringTable = elfRelocatableSymbolTable.getStringTable();
		ElfSymbolTable symbolTable = elfRelocatableSymbolTable.getSymbolTable();

		int nameIdx = stringTable.add(fileName);
		int symbolIdx = symbolTable.getSymbols().length;

		return ElfSymbol.createDefinedSymbol(elfHeader, symbolTable, fileName, nameIdx,
			0, 0, ElfSymbol.STT_FILE, ElfSymbol.STB_LOCAL, ElfSymbol.STV_DEFAULT,
			ElfSectionHeaderConstants.SHN_ABS,
			symbolIdx);
	}

	@Override
	public int compareTo(ElfRelocatableSymbol other) {
		if (getRank() != other.getRank()) {
			return getRank() - other.getRank();
		}

		return 0;
	}
}
