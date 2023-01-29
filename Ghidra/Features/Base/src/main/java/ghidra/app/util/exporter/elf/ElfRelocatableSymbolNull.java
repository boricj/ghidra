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

public final class ElfRelocatableSymbolNull implements ElfRelocatableSymbol {
	private final ElfHeader elfHeader;
	private ElfRelocatableSymbolTable elfRelocatableSymbolTable;
	private int symbolIndex = -1;

	public ElfRelocatableSymbolNull(ElfHeader elfHeader, ElfRelocatableSymbolTable elfRelocatableSymbolTable) {
		this.elfHeader = elfHeader;
		this.elfRelocatableSymbolTable = elfRelocatableSymbolTable;
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
		return 0;
	}

	@Override
	public ElfSymbol emitSymbol() throws IOException {
		ElfStringTable stringTable = elfRelocatableSymbolTable.getStringTable();

		stringTable.add("");

		return ElfSymbol.createNullSymbol(elfHeader);
	}

	@Override
	public int compareTo(ElfRelocatableSymbol other) {
		return getRank() - other.getRank();
	}
}
