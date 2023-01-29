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

import ghidra.app.util.bin.ByteArrayMutableByteProvider;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.MutableByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;

public final class ElfRelocatableSection {
	private Program program;
	private ElfHeader elfHeader;
	private MemoryBlock memoryBlock;
	private AddressSetView sectionSet;
	private MessageLog log;

	private ElfRelocatableSymbolTable elfRelocatableSymbolTable;

	private ElfSectionHeader elfSection;

	public ElfRelocatableSection(Program program, ElfHeader elfHeader, MemoryBlock memoryBlock,
			AddressSetView sectionSet, ElfRelocatableSymbolTable elfRelocatableSymbolTable, MessageLog log)
			throws CancelledException, MemoryAccessException, IOException {
		this.program = program;
		this.elfHeader = elfHeader;
		this.memoryBlock = memoryBlock;
		this.sectionSet = sectionSet;
		this.log = log;

		this.elfRelocatableSymbolTable = elfRelocatableSymbolTable;

		this.elfSection = createElfSectionHeader(elfHeader);
	}

	public ElfHeader getElfHeader() {
		return elfHeader;
	}

	public AddressSetView getAddressSet() {
		return sectionSet;
	}

	public String getName() {
		return memoryBlock.getName();
	}

	public ElfSectionHeader getSection() {
		return elfSection;
	}

	public int computeAddressOffset(Address address) {
		int offset = 0;

		for (AddressRange range : sectionSet.getAddressRanges()) {
			if (!range.contains(address)) {
				offset += range.getLength();
			}
			else {
				offset += address.subtract(range.getMinAddress());
				break;
			}
		}

		return offset;
	}

	public boolean isSectionTruncated() {
		return sectionSet
				.contains(new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd().next()));
	}

	private ElfSectionHeader createElfSectionHeader(ElfHeader elf)
			throws IOException, MemoryAccessException, CancelledException {
		// Build section data.
		byte[] bytes = synthetizeSectionBytes();

		// Create section.
		int sectionType = memoryBlock.isInitialized()
				? ElfSectionHeaderConstants.SHT_PROGBITS
				: ElfSectionHeaderConstants.SHT_NOBITS;

		long flags = ElfSectionHeaderConstants.SHF_ALLOC;
		if (memoryBlock.isExecute()) {
			flags |= ElfSectionHeaderConstants.SHF_EXECINSTR;
		}
		if (memoryBlock.isWrite()) {
			flags |= ElfSectionHeaderConstants.SHF_WRITE;
		}

		ElfSectionHeader section =
			elf.createSectionHeader(memoryBlock.getName(), sectionType, flags, null, 0,
				program.getDefaultPointerSize(), 0, new ByteArrayProvider(bytes));
		if (sectionType == ElfSectionHeaderConstants.SHT_NOBITS) {
			section.setSize(bytes.length);
		}

		return section;
	}

	private byte[] synthetizeSectionBytes() throws CancelledException, MemoryAccessException {
		byte[] bytes = new byte[(int) sectionSet.getNumAddresses()];

		int offset = 0;
		for (AddressRange range : sectionSet.getAddressRanges()) {
			AddressSetView rangeSet = new AddressSet(range);

			// Grab memory slices from range and add it to section data.
			int length = (int) range.getLength();
			if (memoryBlock.isInitialized()) {
				memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
			}

			// Unapply relocations.
			for (Relocation relocation : (Iterable<Relocation>) () -> program.getRelocationTable()
					.getRelocations(rangeSet)) {
				byte[] relocationPatch = relocation.getBytes();
				int patchOffset =
					(int) relocation.getAddress().subtract(range.getMinAddress());
				System.arraycopy(relocationPatch, 0, bytes, patchOffset + offset,
					relocationPatch.length);
			}

			offset += length;
		}

		return bytes;
	}

	public void createRelocationSection(ElfSectionHeader section) throws IOException {
		String msg;
		List<ElfRelocatableRelocation> elfRelocatableRelocations = new ArrayList<>();

		for (Relocation relocation : (Iterable<Relocation>) () -> program.getRelocationTable()
				.getRelocations(sectionSet)) {
			String symbolName = relocation.getSymbolName();
			ElfRelocatableSymbol elfRelocatableSymbol =
				elfRelocatableSymbolTable.getSymbol(symbolName);
			if (elfRelocatableSymbol == null) {
				msg = String.format("Couldn't find ELF symbol %s for relocation at %s", symbolName, relocation.getAddress().toString(false, true));
				log.appendMsg(memoryBlock.getName(), msg);

				continue;
			}

			ElfRelocatableRelocation elfRelocatableRelocation = new ElfRelocatableRelocation(this,
				elfRelocatableSymbol, relocation.getType(),
				computeAddressOffset(relocation.getAddress()));
			elfRelocatableRelocations.add(elfRelocatableRelocation);
		}

		if (!elfRelocatableRelocations.isEmpty()) {
			synthetizeRelocationSection(section, elfRelocatableRelocations);
		}
	}

	private void synthetizeRelocationSection(ElfSectionHeader section,
			List<ElfRelocatableRelocation> relocations) throws IOException {
		MutableByteProvider relSectionProvider = new ByteArrayMutableByteProvider();
		ElfSectionHeader symbolTable =
			(ElfSectionHeader) elfRelocatableSymbolTable.getSymbolTable().getFileSection();
		int sectionIndex = elfHeader.getSectionIndex(section);
		long flags = 0;
		// FIXME: Handle ELF relocation table types other than SHT_REL.
		int sectionType = ElfSectionHeaderConstants.SHT_REL;
		String namePrefix = ".rel";

		ElfSectionHeader relSection =
			elfHeader.createSectionHeader(namePrefix + memoryBlock.getName(),
				sectionType, flags, symbolTable, sectionIndex,
				program.getDefaultPointerSize(), elfHeader.is32Bit() ? 8 : 16,
				relSectionProvider);
		ElfRelocationTable relocationTable = elfHeader.getRelocationTable(relSection);

		for (ElfRelocatableRelocation relocation : relocations) {
			relocationTable.addRelocation(relocation.emitRelocation(relocationTable));
		}

		relSectionProvider.writeBytes(0,
			relocationTable.toBytes(DataConverter.getInstance(elfHeader.isBigEndian())));
	}
}
