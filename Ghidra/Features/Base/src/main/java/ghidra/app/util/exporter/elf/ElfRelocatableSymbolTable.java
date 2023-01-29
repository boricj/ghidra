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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.ByteArrayMutableByteProvider;
import ghidra.app.util.bin.MutableByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.DataConverter;

public class ElfRelocatableSymbolTable {
	private ElfHeader elfHeader;
	private String fileName;
	private Program program;
	private MessageLog log;
	private Map<String, ElfRelocatableSymbol> sectionSymbols = new HashMap<>();
	private Map<String, ElfRelocatableSymbol> definedSymbols = new HashMap<>();
	private Map<String, ElfRelocatableSymbol> externalSymbols = new HashMap<>();

	private ElfStringTable stringTable;
	private ElfSymbolTable symbolTable;

	public ElfRelocatableSymbolTable(Program program, String fileName, ElfHeader elfHeader, MessageLog log) throws IOException {
		this.elfHeader = elfHeader;
		this.fileName = fileName;
		this.program = program;
		this.log = log;
	}

	private ElfStringTable createStringTable() throws IOException {
		MutableByteProvider strtabProvider = new ByteArrayMutableByteProvider();
		ElfSectionHeader strtab =
			elfHeader.createSectionHeader(ElfSectionHeaderConstants.dot_strtab,
				ElfSectionHeaderConstants.SHT_STRTAB, 0,
				null, 0, 1, 0, strtabProvider);
		return elfHeader.getStringTable(strtab);
	}

	private ElfSymbolTable createSymbolTable(ElfStringTable stringTable, int firstGlobalIndex) throws IOException {
		MutableByteProvider symtabProvider = new ByteArrayMutableByteProvider();
		ElfSectionHeader strtab = (ElfSectionHeader) stringTable.getFileSection();
		ElfSectionHeader symtab =
			elfHeader.createSectionHeader(ElfSectionHeaderConstants.dot_symtab,
				ElfSectionHeaderConstants.SHT_SYMTAB, 0,
				strtab, firstGlobalIndex, program.getDefaultPointerSize(), elfHeader.is32Bit() ? 16 : 24,
				symtabProvider);
		return elfHeader.getSymbolTable(symtab);
	}

	public ElfStringTable getStringTable() {
		return stringTable;
	}

	public ElfSymbolTable getSymbolTable() {
		return symbolTable;
	}

	public void processSection(ElfRelocatableSection section) {
		AddressSetView sectionSet = section.getAddressSet();

		if (!section.isSectionTruncated()) {
			ElfRelocatableSymbol elfRelocatableSymbol =
				new ElfRelocatableSymbolSection(elfHeader, section, this);

			sectionSymbols.put(section.getName(), elfRelocatableSymbol);
		}

		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			if (sectionSet.contains(symbol.getAddress())) {
				byte binding = symbol.isDynamic() ? ElfSymbol.STB_LOCAL : ElfSymbol.STB_GLOBAL; 
				ElfRelocatableSymbol elfRelocatableSymbol = new ElfRelocatableSymbolDefined(
					elfHeader, section, this, symbol, binding);

				definedSymbols.put(symbol.getName(true), elfRelocatableSymbol);
			}
		}
	}

	public void processSectionExternalSymbols(ElfRelocatableSection section) {
		String msg;
		AddressSetView sectionSet = section.getAddressSet();

		for (Relocation relocation : (Iterable<Relocation>)() -> program.getRelocationTable().getRelocations(sectionSet)) {
			String symbolName = relocation.getSymbolName();
			Address address = relocation.getAddress();

			if (definedSymbols.containsKey(symbolName) || externalSymbols.containsKey(symbolName)) {
				continue;
			}
			else {
				SymbolIterator symbols = program.getSymbolTable().getSymbols(symbolName);
				if (!symbols.hasNext()) {
					msg = String.format("Couldn't find symbol %s for relocation at %s", symbolName, address.toString(false, true));
					log.appendMsg(section.getName(), msg);

					continue;
				}

				Symbol symbol = symbols.next();
				externalSymbols.put(symbolName, new ElfRelocatableSymbolExternal(elfHeader, this, symbol));
			}
		}
	}

	public void synthetize() throws IOException {
		List<ElfRelocatableSymbol> symbols = new ArrayList<>();
		symbols.add(new ElfRelocatableSymbolNull(elfHeader, this));
		symbols.add(new ElfRelocatableSymbolFile(elfHeader, this, fileName));
		symbols.addAll(sectionSymbols.values());
		symbols.addAll(definedSymbols.values());
		symbols.addAll(externalSymbols.values());
		symbols.sort((ElfRelocatableSymbol s1, ElfRelocatableSymbol s2) -> s1.compareTo(s2));

		int counter = 0;
		int firstGlobalIndex = symbols.size();
		for (ElfRelocatableSymbol symbol : symbols) {
			symbol.setSymbolIndex(counter++);

			if (firstGlobalIndex == symbols.size() && symbol.getBinding() != ElfSymbol.STB_LOCAL) {
				firstGlobalIndex = counter;
			}
		}

		stringTable = createStringTable();
		symbolTable = createSymbolTable(stringTable, firstGlobalIndex);

		for (ElfRelocatableSymbol symbol : symbols) {
			symbolTable.addSymbol(symbol.emitSymbol());
		}

		MutableByteProvider data = (MutableByteProvider) symbolTable.getFileSection().getByteProvider();
		data.writeBytes(0, symbolTable.toBytes(DataConverter.getInstance(elfHeader.isBigEndian())));
	}

	public ElfRelocatableSymbol getSymbol(String symbolName) {
		ElfRelocatableSymbol symbol = definedSymbols.getOrDefault(symbolName, null);
		if (symbol == null) {
			symbol = externalSymbols.getOrDefault(symbolName, null);
		}
		if (symbol == null) {
			symbol = sectionSymbols.getOrDefault(symbolName, null);
		}

		return symbol;
	}
}
