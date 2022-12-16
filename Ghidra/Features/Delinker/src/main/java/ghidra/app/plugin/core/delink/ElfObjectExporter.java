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
package ghidra.app.plugin.core.delink;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

import org.jgrapht.nio.ExportException;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates
 * an Binary representation of the program.
 */
public class ElfObjectExporter extends Exporter {

	public ElfObjectExporter() {
		super("ELF relocatable object", "o", null);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {
		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;
		DataConverter dc = getDataConverter(program);

		Memory memory = program.getMemory();
		if (addrSet == null) {
			addrSet = memory;
		}

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			raf.setLength(0);

			ElfHeader elfHeader = assemble(program, dc, addrSet);
			write(elfHeader, raf, dc);
		}
		catch (MemoryAccessException e) {
			throw new ExportException(e);
		}

		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return EMPTY_OPTIONS;
	}

	@Override
	public void setOptions(List<Option> options) {
	}

	private static ElfHeader assemble(Program program, DataConverter dc, AddressSetView addrSet) throws MemoryAccessException, IOException {
		byte e_ident_class = getElfClass(program);
		byte e_ident_data = getElfData(dc);
		byte e_ident_version = ElfConstants.EV_CURRENT;
		byte e_ident_osabi = ElfConstants.ELFOSABI_NONE;
		byte e_ident_abiversion = 0x0;
		short e_type = ElfConstants.ET_REL;
		short e_machine = getElfMachine(program);
		int e_version = 0;
		long e_entry = 0x0;
		int e_flags = 0x0;

		try {
			ElfHeader elfHeader = new ElfHeader(e_ident_class, e_ident_data, e_ident_version, e_ident_osabi, e_ident_abiversion, e_type, e_machine, e_version, e_entry, e_flags);
			ElfSectionHeader elfSectionStringTable = elfHeader.getSection(".shstrtab");

			ElfStringTable elfStringTable = elfHeader.addStringTable(".strtab", elfSectionStringTable.getData().length);
			appendASCIIZ(elfSectionStringTable, ".strtab");

			ElfSymbolTable elfSymbolTable = elfHeader.addSymbolTable(".symtab", ElfSectionHeaderConstants.SHT_SYMTAB, elfSectionStringTable.getData().length, elfStringTable);
			appendASCIIZ(elfSectionStringTable, ".symtab");

			for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
				processMemoryBlock(elfHeader, program, addrSet, memoryBlock);
			}

			elfHeader.getSection(".symtab").setData(elfSymbolTable.toBytes(dc));

			return elfHeader;
		}
		catch (ElfException e) {
			throw new ExportException(e);
		}
	}

	private static void processMemoryBlock(ElfHeader elfHeader, Program program, AddressSetView addrSet, MemoryBlock memoryBlock) throws MemoryAccessException, IOException {
		AddressSet fullMemoryBlockSet = new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd());
		AddressSet memoryBlockSet = fullMemoryBlockSet.intersect(addrSet);
		if (memoryBlockSet.isEmpty()) {
			return;
		}

		ElfSectionHeader elfSectionStringTable = elfHeader.getSection(".shstrtab");

		String sectionName = memoryBlock.getName();
		int sh_name = elfSectionStringTable.getData().length;
		ElfSectionHeader elfSectionHeader = elfHeader.addSection(memoryBlock.getName(), sh_name);

		appendASCIIZ(elfSectionStringTable, sectionName);

		byte[] bytes = new byte[(int)memoryBlockSet.getNumAddresses()];
		int offset = 0;

		for (AddressRange range : memoryBlockSet.getAddressRanges()) {
			processMemoryBlockRange(elfHeader, program, range, memoryBlock, bytes, offset);

			offset += (int)range.getLength();
		}

		if (memoryBlock.isInitialized()) {
			elfSectionHeader.setData(bytes);
		}
		else {
			elfSectionHeader.setSize(bytes.length);
		}
	}

	private static void processMemoryBlockRange(ElfHeader elfHeader, Program program, AddressRange range, MemoryBlock memoryBlock, byte[] bytes, int offset) throws MemoryAccessException, IOException {
		AddressSet rangeSet = new AddressSet(range);

		// Grab memory slice from range and add it to section data.
		int length = (int)range.getLength();
		if (memoryBlock.isInitialized()) {
			memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
		}
		offset += length;

		// Add all symbols within range.
		for (Symbol symbol : program.getSymbolTable().getSymbols(rangeSet, SymbolType.FUNCTION, true)) {
			processSymbol(elfHeader, symbol);
		}
		for (Symbol symbol : program.getSymbolTable().getSymbols(rangeSet, SymbolType.LABEL, true)) {
			processSymbol(elfHeader, symbol);	
		}

		// Add and apply all relocations within range.
		Iterator<Relocation> relocations = program.getRelocationTable().getRelocations(rangeSet);
		while (relocations.hasNext()) {
			Relocation relocation = relocations.next();

			processRelocation(elfHeader, range, relocation, bytes, offset);
		}
	}

	private static void processSymbol(ElfHeader elfHeader, Symbol symbol) throws IOException {
		ElfSymbolTable elfSymbolTable = elfHeader.getSymbolTables()[0];
		ElfSectionHeader elfStringTable = elfHeader.getSection(".strtab");

		String symbolName = symbol.getName();
		int nameOffset = elfStringTable.getData().length;
		long symbolAddress = symbol.getAddress().getOffset();
		int symbolIndex = elfSymbolTable.getSymbolCount();

		appendASCIIZ(elfStringTable, symbolName);

		ElfSymbol elfSymbol = ElfSymbol.createGlobalFunctionSymbol(elfHeader, nameOffset, symbolName, symbolAddress, symbolIndex, elfSymbolTable);
		elfSymbolTable.addSymbol(elfSymbol);
	}

	private static void processRelocation(ElfHeader elfHeader, AddressRange range, Relocation relocation, byte[] bytes, int rangeOffset) {
		byte[] relocationPatch = relocation.getBytes();
		int patchOffset = (int) relocation.getAddress().subtract(range.getMinAddress());
		System.arraycopy(relocationPatch, 0, bytes, patchOffset + rangeOffset, relocationPatch.length);
	}

	private static void write(ElfHeader elfHeader, RandomAccessFile raf, DataConverter dc) throws IOException {
		elfHeader.setSectionHeaderOffset(elfHeader.e_ehsize());
		elfHeader.write(raf, dc);
		long offset = elfHeader.e_ehsize() + elfHeader.getSections().length * elfHeader.e_shentsize();

		// Write section header table.
		for (ElfSectionHeader elfSectionHeader : elfHeader.getSections()) {
			elfSectionHeader.setOffset(offset);

			if (elfSectionHeader.getType() != ElfSectionHeaderConstants.SHT_NOBITS) {
				offset += elfSectionHeader.getSize();
			}

			elfSectionHeader.write(raf, dc);
		}

		// Write sections.
		for (ElfSectionHeader elfSectionHeader : elfHeader.getSections()) {
			if (elfSectionHeader.getType() != ElfSectionHeaderConstants.SHT_NOBITS) {
				raf.write(elfSectionHeader.getData());
			}
		}
	}

	private static byte getElfClass(Program program) {
		int pointerSize = program.getDefaultPointerSize();

		if (pointerSize == 4) {
			return ElfConstants.ELF_CLASS_32;
		}
		else if (pointerSize == 8) {
			return ElfConstants.ELF_CLASS_64;
		}

		throw new NotYetImplementedException("Unknown pointer size " + Integer.toString(pointerSize));
	}

	private static byte getElfData(DataConverter dc) {
		return dc.isBigEndian() ? ElfConstants.ELF_DATA_BE : ElfConstants.ELF_DATA_LE;
	}

	private static short getElfMachine(Program program) {
		Processor processor = program.getLanguage().getProcessor();

		if (processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"))) {
			return ElfConstants.EM_MIPS;
		}

		throw new NotYetImplementedException("Unknown processor " + processor);
	}

	private static DataConverter getDataConverter(Program program) {
		return DataConverter.getInstance(program.getMemory().isBigEndian());
	}
	
	private static void appendASCIIZ(ElfSectionHeader section, String str) throws IOException {
		byte[] bytes = section.getData();
		byte[] encodedStr = StandardCharsets.UTF_8.encode(str).array();
		byte[] newBytes = new byte[bytes.length + encodedStr.length + 1];
		System.arraycopy(bytes, 0, newBytes, 0, bytes.length);
		System.arraycopy(encodedStr, 0, newBytes, bytes.length, encodedStr.length);
		section.setData(newBytes);
	}
}
