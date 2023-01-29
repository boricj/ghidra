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
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

public final class ElfRelocatableObject {
	private Program program;
	private DataConverter dc;
	private AddressSetView programSet;
	private String fileName;
	private AddressSetView fileSet;
	private TaskMonitor taskMonitor;
	private MessageLog log;

	public ElfRelocatableObject(Program program, AddressSetView programSet,
			String fileName, AddressSetView fileSet, TaskMonitor taskMonitor, MessageLog log) {
		this.program = program;
		this.dc = DataConverter.getInstance(program.getMemory().isBigEndian());
		this.programSet = programSet;
		this.fileName = fileName;
		this.fileSet = fileSet;
		this.taskMonitor = taskMonitor;
		this.log = log;
	}

	public ElfHeader synthetize()
			throws IOException, CancelledException, MemoryAccessException, ElfException {
		String msg;

		// Create ELF header.
		ElfHeader elfHeader = createElfHeader();

		// Create null section.
		elfHeader.createSectionHeader("", ElfSectionHeaderConstants.SHT_NULL, 0, null, 0, 0, 0,
			ByteProvider.EMPTY_BYTEPROVIDER);

		// Prepare string and symbol tables.
		ElfRelocatableSymbolTable elfRelocatableSymbolTable =
			new ElfRelocatableSymbolTable(program, fileName, elfHeader, log);

		// Create all allocated sections.
		List<ElfRelocatableSection> elfRelocatableSections = new ArrayList<>();

		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			AddressSet memoryBlockSet =
				new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);
			if (memoryBlockSet.isEmpty()) {
				continue;
			}

			msg = String.format("Processing section %s...", memoryBlock.getName());
			taskMonitor.setMessage(msg);

			ElfRelocatableSection section =
				new ElfRelocatableSection(program, elfHeader, memoryBlock, memoryBlockSet,
					elfRelocatableSymbolTable, log);
			elfRelocatableSections.add(section);
			elfRelocatableSymbolTable.processSection(section);
		}

		for (ElfRelocatableSection section : elfRelocatableSections) {
			elfRelocatableSymbolTable.processSectionExternalSymbols(section);
		}

		// Create string and symbol tables.
		elfRelocatableSymbolTable.synthetize();

		// Create relocation tables.
		for (ElfRelocatableSection section : elfRelocatableSections) {
			msg = String.format("Processing relocations for section %s...", section.getName());
			taskMonitor.setMessage(msg);

			section.createRelocationSection(section.getSection());
		}

		// Create section name string table.
		elfHeader.createSectionNameStringTable(ElfSectionHeaderConstants.dot_shstrtab);

		return elfHeader;
	}

	private ElfHeader createElfHeader() throws ElfException {
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

		return new ElfHeader(e_ident_class, e_ident_data, e_ident_version, e_ident_osabi,
			e_ident_abiversion, e_type, e_machine, e_version, e_entry, e_flags);
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
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("PSX"))) {
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

	public DataConverter getDataConverter() {
		return dc;
	}
}
