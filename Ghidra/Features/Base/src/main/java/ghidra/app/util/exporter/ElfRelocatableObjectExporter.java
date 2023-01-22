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
package ghidra.app.util.exporter;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.jgrapht.nio.ExportException;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayMutableProvider;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MutableByteProvider;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfFile;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;
import ghidra.app.util.bin.format.elf.ElfSection;
import ghidra.app.util.bin.format.elf.ElfSectionConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates an ELF relocatable object from the
 * program.
 */
public class ElfRelocatableObjectExporter extends Exporter {

	public ElfRelocatableObjectExporter() {
		super("ELF relocatable object", "o", null);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws IOException, ExporterException {
		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;

		Memory memory = program.getMemory();
		if (fileSet == null) {
			fileSet = memory;
		}

		// FIXME: Expose program address set.
		AddressSetView programSet = memory;

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			raf.setLength(0);

			ElfRelocatableObject relocatableObject =
				new ElfRelocatableObject(program, programSet, fileSet, taskMonitor, log);

			ElfFile elf = relocatableObject.synthetize();

			taskMonitor.setMessage("Writing out ELF relocatable object file...");
			write(elf, raf, relocatableObject.dc);
		}
		catch (Exception e) {
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

	protected static class ElfRelocatableObject {
		private final String MSG_ANALYZING_MEMORY_BLOCK = "Analyzing memory block %s...";
		private final String MSG_SYNTHETIZING_SECTION = "Synthetizing section %s...";
		private final String MSG_SYNTHETIZING_SYMBOL_TABLE = "Synthetizing symbol table...";
		private final String MSG_SYNTHETIZING_RELOCATION_SECTION =
			"Synthetizing relocation section for section %s...";
		private final String MSG_SYNTHETIZING_SECTION_NAME_STRING_TABLE =
			"Synthetizing section name string table...";

		private final String LOG_UNNAMMED_SYMBOL = "%s: symbol %s hasn't been given a name";

		private Program program;
		private DataConverter dc;
		private SymbolTable symbolTable;
		private RelocationTable relocationTable;
		private AddressSetView programSet;
		private AddressSetView fileSet;
		private TaskMonitor taskMonitor;
		private MessageLog log;

		private Map<Symbol, Integer> internalSymbols = new HashMap<>();
		private Set<Symbol> externalSymbols = new HashSet<>();

		private List<ElfRelocatableSection> sections = new ArrayList<>();

		protected class ElfRelocatableSection {
			private MemoryBlock memoryBlock;
			private AddressSetView sectionSet;

			private Set<Symbol> internalSymbols = new HashSet<>();
			private Set<Symbol> externalSymbols = new HashSet<>();
			private List<Relocation> relocations = new ArrayList<>();

			private Map<Relocation, Symbol> internalToInternal = new HashMap<>();
			private Map<Relocation, Symbol> internalToExternal = new HashMap<>();
			private Map<Relocation, Symbol> externalToInternal = new HashMap<>();

			public ElfRelocatableSection(MemoryBlock memoryBlock, AddressSetView sectionSet)
					throws CancelledException {
				this.memoryBlock = memoryBlock;
				this.sectionSet = sectionSet;

				for (Symbol symbol : symbolTable.getAllSymbols(true)) {
					taskMonitor.checkCanceled();

					String symbolName = symbol.getName();
					Address symbolAddress = symbol.getAddress();

					if (sectionSet.contains(symbolAddress)) {
						if (symbolName.startsWith("DAT_")) {
							warnUnnamedSymbol(memoryBlock.getName(), symbol);
						}

						internalSymbols.add(symbol);

						for (Relocation relocation : (Iterable<Relocation>) () -> relocationTable
								.getRelocations(fileSet)) {
							if (symbolName.equals(relocation.getSymbolName())) {
								Address relocationAddress = relocation.getAddress();

								if (sectionSet.contains(relocationAddress)) {
									internalToInternal.put(relocation, symbol);
								}
								else if (programSet.contains(relocationAddress)) {
									externalToInternal.put(relocation, symbol);
								}
							}
						}
					}
					else if (fileSet.contains(symbolAddress)) {
						for (Relocation relocation : (Iterable<Relocation>) () -> relocationTable
								.getRelocations(fileSet)) {
							if (symbolName.equals(relocation.getSymbolName())) {
								if (sectionSet.contains(relocation.getAddress())) {
									internalToExternal.put(relocation, symbol);
								}
							}
						}
					}
				}

				for (Symbol symbol : internalToExternal.values()) {
					externalSymbols.add(symbol);

					if (symbol.getName().startsWith("DAT_")) {
						warnUnnamedSymbol("external", symbol);
					}
				}

				relocations.addAll(internalToInternal.keySet());
				relocations.addAll(internalToExternal.keySet());
			}

			public int computeOffsetOfSymbol(Symbol symbol) {
				Address symbolAddress = symbol.getAddress();
				int offset = 0;

				for (AddressRange range : sectionSet.getAddressRanges()) {
					if (!range.contains(symbolAddress)) {
						offset += range.getLength();
					}
					else {
						offset += symbolAddress.subtract(range.getMinAddress());
						break;
					}
				}

				return offset;
			}

			public ElfSection createElfSection(ElfFile elf)
					throws IOException, MemoryAccessException, CancelledException {
				// Build section data.
				byte[] bytes = new byte[(int) sectionSet.getNumAddresses()];

				int offset = 0;
				for (AddressRange range : sectionSet.getAddressRanges()) {
					taskMonitor.checkCanceled();

					// Grab memory slices from range and add it to section data.
					int length = (int) range.getLength();
					if (memoryBlock.isInitialized()) {
						memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
					}

					// Unapply relocations.
					for (Relocation relocation : relocations) {
						if (!range.contains(relocation.getAddress())) {
							continue;
						}

						byte[] relocationPatch = relocation.getBytes();
						int patchOffset =
							(int) relocation.getAddress().subtract(range.getMinAddress());
						System.arraycopy(relocationPatch, 0, bytes, patchOffset + offset,
							relocationPatch.length);
					}

					offset += length;
				}

				// Create section.
				int sectionType = memoryBlock.isInitialized()
						? ElfSectionConstants.SHT_PROGBITS
						: ElfSectionConstants.SHT_NOBITS;

				long flags = ElfSectionConstants.SHF_ALLOC;
				if (memoryBlock.isExecute()) {
					flags |= ElfSectionConstants.SHF_EXECINSTR;
				}
				if (memoryBlock.isWrite()) {
					flags |= ElfSectionConstants.SHF_WRITE;
				}

				return elf.addSection(memoryBlock.getName(), sectionType, flags, null, 0,
					program.getDefaultPointerSize(), 0, new ByteArrayProvider(bytes));
			}

			public ElfSection createElfRelSection(ElfFile elf, ElfSection section,
					ElfSection symbolTableSection,
					Map<String, Integer> nameToIndex) throws CancelledException, IOException {
				int sectionIndex = elf.getSections().indexOf(section);
				int symbolTableSectionIndex = elf.getSections().indexOf(symbolTableSection);
				MutableByteProvider relSectionProvider = new ByteArrayMutableProvider();
				ElfSection relSection = null;
				ElfRelocationTable relocationTable = null;

				int offset = 0;
				for (AddressRange range : sectionSet.getAddressRanges()) {
					taskMonitor.checkCanceled();

					int length = (int) range.getLength();

					// Unapply relocations.
					for (Relocation relocation : relocations) {
						if (!range.contains(relocation.getAddress())) {
							continue;
						}

						if (relocationTable == null) {
							relSection = elf.addSection(".rel" + section.getNameAsString(),
								ElfSectionConstants.SHT_REL, 0, symbolTableSection, sectionIndex,
								program.getDefaultPointerSize(), elf.is32Bit() ? 8 : 16,
								relSectionProvider);
							relocationTable = elf.getRelocationTable(relSection);
						}

						int symbolIndex = nameToIndex.get(relocation.getSymbolName());
						int r_offset = (int) (offset +
							relocation.getAddress().subtract(range.getMinAddress()));
						long r_info = elf.is32Bit()
								? relocation.getType() + (symbolIndex << 8)
								: relocation.getType() + (symbolIndex << 32L);

						ElfRelocation elfRelocation = ElfRelocation.createElfRelocation(elf,
							relocationTable.getRelocations().length, false, r_offset, r_info, 0);
						relocationTable.addRelocation(elfRelocation);
					}

					offset += length;
				}

				if (relocationTable != null) {
					relSectionProvider.writeBytes(0, relocationTable.toBytes(dc));
				}

				return relSection;
			}
		}

		public ElfRelocatableObject(Program program, AddressSetView programSet,
				AddressSetView fileSet, TaskMonitor taskMonitor, MessageLog log)
				throws CancelledException {
			this.program = program;
			this.dc = DataConverter.getInstance(program.getMemory().isBigEndian());
			this.symbolTable = program.getSymbolTable();
			this.relocationTable = program.getRelocationTable();
			this.programSet = programSet;
			this.fileSet = fileSet;
			this.taskMonitor = taskMonitor;
			this.log = log;

			for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
				taskMonitor.setMessage(String.format(MSG_ANALYZING_MEMORY_BLOCK, memoryBlock));

				AddressSet fullMemoryBlockSet =
					new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd());
				AddressSet memoryBlockSet = fullMemoryBlockSet.intersect(fileSet);
				if (memoryBlockSet.isEmpty()) {
					continue;
				}

				sections.add(new ElfRelocatableSection(memoryBlock, memoryBlockSet));
			}

			computeSymbolSets();
		}

		private void warnUnnamedSymbol(String section, Symbol symbol) {
			log.appendMsg(String.format(LOG_UNNAMMED_SYMBOL, section, symbol.getName()));
		}

		private void computeSymbolSets() throws CancelledException {
			for (ElfRelocatableSection section : sections) {
				taskMonitor.checkCanceled();

				for (Symbol symbol : section.internalSymbols) {
					int offset = section.computeOffsetOfSymbol(symbol);
					internalSymbols.put(symbol, offset);
				}

				externalSymbols.addAll(section.externalSymbols);
			}

			externalSymbols.removeAll(internalSymbols.keySet());

			for (Symbol symbol : externalSymbols) {
				if (symbol.getName().startsWith("DAT_")) {
					warnUnnamedSymbol("(external)", symbol);
				}
			}
		}

		private byte getElfClass() {
			int pointerSize = program.getDefaultPointerSize();

			if (pointerSize == 4) {
				return ElfConstants.ELF_CLASS_32;
			}
			else if (pointerSize == 8) {
				return ElfConstants.ELF_CLASS_64;
			}

			throw new NotYetImplementedException(
				"Unknown pointer size " + Integer.toString(pointerSize));
		}

		private byte getElfData() {
			return dc.isBigEndian() ? ElfConstants.ELF_DATA_BE : ElfConstants.ELF_DATA_LE;
		}

		private short getElfMachine() {
			Processor processor = program.getLanguage().getProcessor();
			int bits = program.getDefaultPointerSize();

			// FIXME: Processor to ELF machine mapping should probably be handled somewhere else.
			if (processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"))) {
				return ElfConstants.EM_MIPS;
			}
			else if (processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
				if (program.getDefaultPointerSize() == 4) {
					return ElfConstants.EM_386;
				}
				else if (program.getDefaultPointerSize() == 8) {
					return ElfConstants.EM_X86_64;
				}
			}

			throw new NotYetImplementedException(
				String.format("Unknown processor %s (%d bits)", processor, bits * 8));
		}

		private ElfFile createElfFile() throws ElfException {
			byte e_ident_class = getElfClass();
			byte e_ident_data = getElfData();
			byte e_ident_version = ElfConstants.EV_CURRENT;
			byte e_ident_osabi = ElfConstants.ELFOSABI_NONE;
			byte e_ident_abiversion = 0x0;
			short e_type = ElfConstants.ET_REL;
			short e_machine = getElfMachine();
			int e_version = 0;
			long e_entry = 0x0;
			int e_flags = 0x0;

			return new ElfFile(e_ident_class, e_ident_data, e_ident_version, e_ident_osabi,
				e_ident_abiversion, e_type, e_machine, e_version, e_entry, e_flags);
		}

		private Map<String, Integer> synthetizeSymbolTable(ElfFile elf, ElfStringTable stringTable,
				ElfSymbolTable symbolTable) throws IOException {
			Map<String, Integer> nameToIndex = new HashMap<>();

			// Create empty symbol.
			stringTable.add("");
			symbolTable.addSymbol(ElfSymbol.createNullSymbol(elf));

			for (Entry<Symbol, Integer> entry : internalSymbols.entrySet()) {
				Symbol symbol = entry.getKey();
				String symbolName = symbol.getName();
				int symbolSize = 0;
				byte symbolType = ElfSymbol.STT_NOTYPE;

				for (ElfRelocatableSection section : sections) {
					int sectionIdx = elf.getSections()
							.indexOf(elf.getSection(
								e -> e.getNameAsString().equals(section.memoryBlock.getName())));
					if (sectionIdx > Short.MAX_VALUE - 1) {
						throw new RuntimeException(
							"Too many sections for ELF relocatable object exporter!");
					}

					if (section.internalSymbols.contains(symbol)) {
						int name = stringTable.add(symbolName);
						int symbolIndex = symbolTable.getSymbols().length;
						ElfSymbol elfSymbol =
							ElfSymbol.createDefinedSymbol(elf, symbolTable, symbolName, name,
								entry.getValue(), symbolSize, symbolType, ElfSymbol.STB_GLOBAL,
								ElfSymbol.STV_DEFAULT, (short) sectionIdx, symbolIndex);

						symbolTable.addSymbol(elfSymbol);
						nameToIndex.put(symbolName, symbolIndex);

						break;
					}
				}
			}

			for (Symbol symbol : externalSymbols) {
				String symbolName = symbol.getName();
				int name = stringTable.add(symbolName);

				ElfSymbol elfSymbol = ElfSymbol.createUndefinedSymbol(elf, symbolTable, symbolName,
					name, symbolTable.getSymbols().length);
				symbolTable.addSymbol(elfSymbol);
			}

			return nameToIndex;
		}

		public ElfFile synthetize()
				throws IOException, ElfException, MemoryAccessException, CancelledException {
			ElfFile elf = createElfFile();

			// Create null section.
			elf.addSection("", ElfSectionConstants.SHT_NULL, 0, null, 0, 0, 0,
				ByteProvider.EMPTY_BYTEPROVIDER);

			// Create string table.
			MutableByteProvider strtabProvider = new ByteArrayMutableProvider();
			ElfSection strtab = elf.addSection(".strtab", ElfSectionConstants.SHT_STRTAB, 0,
				null, 0, 1, 0, strtabProvider);
			ElfStringTable stringTable = elf.getStringTable(strtab);

			// Create symbol table section.
			MutableByteProvider symtabProvider = new ByteArrayMutableProvider();
			ElfSection symtab = elf.addSection(".symtab", ElfSectionConstants.SHT_SYMTAB, 0,
				strtab, 0, program.getDefaultPointerSize(), elf.is32Bit() ? 16 : 24,
				symtabProvider);
			ElfSymbolTable symbolTable = elf.getSymbolTable(symtab);

			// Process each section.
			for (ElfRelocatableSection section : sections) {
				taskMonitor.setMessage(
					String.format(MSG_SYNTHETIZING_SECTION, section.memoryBlock.getName()));

				ElfSection elfSection = section.createElfSection(elf);
			}

			taskMonitor.setMessage(MSG_SYNTHETIZING_SYMBOL_TABLE);
			Map<String, Integer> nameToIndex = synthetizeSymbolTable(elf, stringTable, symbolTable);
			symtabProvider.writeBytes(0, symbolTable.toBytes(dc));

			for (ElfRelocatableSection section : sections) {
				taskMonitor.setMessage(
					String.format(MSG_SYNTHETIZING_RELOCATION_SECTION,
						section.memoryBlock.getName()));

				ElfSection elfSection =
					elf.getSection(e -> e.getNameAsString().equals(section.memoryBlock.getName()));
				ElfSection elfRelocatableSection =
					section.createElfRelSection(elf, elfSection, symtab, nameToIndex);
			}

			// Create section name string table.
			taskMonitor.setMessage(MSG_SYNTHETIZING_SECTION_NAME_STRING_TABLE);
			MutableByteProvider shstrtabProvider = new ByteArrayMutableProvider();
			ElfSection shstrtab = elf.addSection(".shstrtab", ElfSectionConstants.SHT_STRTAB, 0,
				null, 0, 1, 0, shstrtabProvider);
			ElfStringTable shStringTable = elf.getStringTable(shstrtab);

			for (ElfSection section : elf.getSections()) {
				String sectionName = section.getNameAsString();
				int strIndex = shStringTable.add(sectionName);

				section.sh_name = strIndex;
			}

			elf.getHeader().e_shstrndx = elf.getSections().indexOf(shstrtab);

			return elf;
		}
	}

	private static long alignTo(long value, long alignment) {
		if ((alignment > 1) && (value % alignment != 0)) {
			value = value + alignment - (value % alignment);
		}

		return value;
	}

	private static void write(ElfFile elf, RandomAccessFile raf, DataConverter dc)
			throws IOException {
		ElfHeader header = elf.getHeader();
		long offset = header.e_ehsize();
		raf.seek(offset);

		// Write sections.
		for (ElfSection section : elf.getSections()) {
			if (section.getType() != ElfSectionConstants.SHT_NULL) {
				long sectionOffset = alignTo(raf.getFilePointer(), section.getAddressAlignment());

				raf.seek(sectionOffset);
				section.setOffset(raf.getFilePointer());

				if (section.getType() != ElfSectionConstants.SHT_NOBITS) {
					ByteProvider provider = section.getByteProvider();
					section.setSize(provider.length());

					raf.write(provider.readBytes(0, section.getFileSize()));
				}
			}
		}

		// Write section header table.
		long sectionHeaderOffset = alignTo(raf.getFilePointer(), 16);
		raf.seek(sectionHeaderOffset);

		for (ElfSection section : elf.getSections()) {
			section.write(raf, dc);
		}

		// Write ELF header.
		raf.seek(0);
		header.setSectionHeaderOffset(sectionHeaderOffset);
		header.write(raf, dc);
	}
}
