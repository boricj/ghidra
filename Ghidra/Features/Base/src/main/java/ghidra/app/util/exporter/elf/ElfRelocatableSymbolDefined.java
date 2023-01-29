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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public final class ElfRelocatableSymbolDefined implements ElfRelocatableSymbol {
	private ElfHeader elfHeader;
	private ElfRelocatableSection elfRelocatableSection;
	private ElfRelocatableSymbolTable elfRelocatableSymbolTable;
	private Symbol symbol;
	private int symbolIndex = -1;

	private byte type = ElfSymbol.STT_NOTYPE;
	private byte binding;
	private int offset;
	private int size = 0;

	public ElfRelocatableSymbolDefined(ElfHeader elfHeader,
			ElfRelocatableSection elfRelocatableSection,
			ElfRelocatableSymbolTable elfRelocatableSymbolTable, Symbol symbol, byte binding) {
		this.elfHeader = elfHeader;
		this.elfRelocatableSymbolTable = elfRelocatableSymbolTable;
		this.elfRelocatableSection = elfRelocatableSection;
		this.symbol = symbol;
		this.binding = binding;
		this.offset = elfRelocatableSection.computeAddressOffset(symbol.getAddress());

		Object obj = symbol.getObject();
		if (obj instanceof CodeUnit) {
			CodeUnit codeUnit = (CodeUnit) obj;

			this.type = ElfSymbol.STT_OBJECT;
			this.size = codeUnit.getLength();
		}
		else if (obj instanceof Function) {
			Function function = (Function) obj;

			this.type = ElfSymbol.STT_FUNC;
			this.size = (int) function.getBody().getNumAddresses();
		}
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
		return binding;
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
		return 3;
	}

	@Override
	public ElfSymbol emitSymbol() throws IOException {
		ElfStringTable stringTable = elfRelocatableSymbolTable.getStringTable();
		ElfSymbolTable symbolTable = elfRelocatableSymbolTable.getSymbolTable();

		String name = symbol.getName(true);
		int nameIdx = stringTable.add(name);
		int symbolIdx = symbolTable.getSymbols().length;

		return ElfSymbol.createDefinedSymbol(elfHeader, symbolTable, name, nameIdx,
			offset, size, type, binding, ElfSymbol.STV_DEFAULT, (short) getSectionIndex(),
			symbolIdx);
	}

	@Override
	public int compareTo(ElfRelocatableSymbol other) {
		if (getRank() != other.getRank()) {
			return getRank() - other.getRank();
		}

		ElfRelocatableSymbolDefined symDefined = (ElfRelocatableSymbolDefined) other;

		if (binding != symDefined.binding) {
			return binding - symDefined.binding;
		}

		return symbol.getAddress().compareTo(symDefined.symbol.getAddress());
	}
}
