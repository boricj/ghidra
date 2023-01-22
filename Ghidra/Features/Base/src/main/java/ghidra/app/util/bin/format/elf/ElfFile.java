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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.util.exception.NotFoundException;

/**
 * A class to represent the Executable and Linking Format (ELF)
 * header and specification.
 */
public class ElfFile {
	private static final int MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE = 20;

	private Map<Integer, ElfSegmentType> programHeaderTypeMap = new HashMap<>();
	private Map<Integer, ElfSectionType> sectionHeaderTypeMap = new HashMap<>();
	private Map<Integer, ElfDynamicType> dynamicTypeMap = new HashMap<>();

	private ElfLoadAdapter elfLoadAdapter = new ElfLoadAdapter();

	private ElfHeader header;
	private Long preLinkImageBase;
	private Long elfImageBase;
	private List<ElfSection> sections = new ArrayList<>();
	private List<ElfSegment> segments = new ArrayList<>();

	private List<ElfStringTable> stringTables = new ArrayList<>();
	private List<ElfSymbolTable> symbolTables = new ArrayList<>();
	private List<ElfRelocationTable> relocationTables = new ArrayList<>();
	private ElfDynamicTable dynamicTable;
	private ElfStringTable dynamicStringTable;
	private ElfSymbolTable dynamicSymbolTable;
	private boolean hasExtendedSymbolSectionIndexTable; // if SHT_SYMTAB_SHNDX sections exist

	private List<String> dynamicLibraryNames = new ArrayList<>();

	private Consumer<String> errorConsumer;

	private int sectionNameStringTableIndex;

	/**
	 * Load ELF file and parse all supported headers.
	 * @throws IOException if file IO error occurs
	 */
	public ElfFile(ByteProvider provider, Consumer<String> errorConsumer)
			throws ElfException, IOException {
		this.errorConsumer = errorConsumer != null ? errorConsumer : msg -> {
			/* no logging if errorConsumer was null */
		};

		ElfFileHeadersParseHelper helper = new ElfFileHeadersParseHelper(provider, this.errorConsumer);
		this.header = helper.header;
		this.sections = new ArrayList<>(Arrays.asList(helper.sections));
		this.segments = new ArrayList<>(Arrays.asList(helper.segments));
		this.sectionNameStringTableIndex = helper.sectionNameStringTableIndex;
		this.preLinkImageBase = helper.preLinkImageBase;
		this.hasExtendedSymbolSectionIndexTable = helper.hasExtendedSymbolSectionIndexTable;

		initElfLoadAdapter();

		parseDynamicTable();
		parseStringTables();
		sections.forEach(e -> e.updateName());
		parseDynamicLibraryNames();
		parseSymbolTables(helper.reader);
		parseRelocationTables();
		parseGNU_d();
		parseGNU_r();
	}

	/**
	 * Create an empty ELF file.
	 */
	public ElfFile(byte e_ident_class, byte e_ident_data, byte e_ident_version, byte e_ident_osabi,
			byte e_ident_abiversion, short e_type, short e_machine, int e_version, long e_entry,
			int e_flags) throws ElfException {
		this.header = new ElfHeader(e_ident_class, e_ident_data, e_ident_version, e_ident_osabi,
			e_ident_abiversion, e_type, e_machine, e_version, e_entry, e_flags);
    }

    /**
	 * An helper class to parse the header, segments and sections from
	 * an Executable and Linking Format (ELF) file. 
	 */
	private class ElfFileHeadersParseHelper {
		private final String TRUNCATED_MSG = "%2$ of %3$ %1$ are truncated/missing from file";

		ElfHeader header;
		ElfSection[] sections;
		ElfSegment[] segments;
		int sectionNameStringTableIndex;
		Long preLinkImageBase;
		boolean hasExtendedSymbolSectionIndexTable;

		ByteProvider provider;
		BinaryReader reader;

		public ElfFileHeadersParseHelper(ByteProvider provider, Consumer<String> errorConsumer)
				throws ElfException, IOException {
			this.provider = provider;
			this.header = new ElfHeader(provider);
			// Sections need the header inside ElfFile for parsing.
			ElfFile.this.header = this.header;
			this.reader = new BinaryReader(provider, header.isLittleEndian());

			// If the ELF file has an extended section count, then the
			// first section will hold the extended header count.
			int shnum = hasExtendedSectionCount() ? 1 : header.e_shnum;
			this.sections = new ElfSection[shnum];

			if (!hasExtendedSegmentCount()) {
				this.segments = new ElfSegment[this.header.e_phnum];
			}

			if (!hasExtendedSectionNameStringTableIndex()) {
				this.sectionNameStringTableIndex = this.header.e_shstrndx;
			}

			parseSections(errorConsumer);
			parseSegments(errorConsumer);
			parsePreLinkImageBase();
		}

		private void parseSections(Consumer<String> errorConsumer) throws IOException {
			boolean missing = false;

			for (int i = 0; i < sections.length; ++i) {
				long index = header.e_shoff + (i * header.e_shentsize);
				if (!missing && !providerContainsRegion(index, header.e_shentsize)) {
					errorConsumer.accept(TRUNCATED_MSG.formatted("sections",
						i - sections.length, sections.length));
					missing = true;
				}

				reader.setPointerIndex(index);
				ElfSection section = new ElfSection(ElfFile.this, reader);

				// Deal with all extended counts inside the first section.
				if (i == 0) {
					if (hasExtendedSectionCount()) {
						sections = new ElfSection[(int) section.sh_size];
					}

					if (hasExtendedSegmentCount()) {
						segments = new ElfSegment[section.sh_info];
					}

					if (hasExtendedSectionNameStringTableIndex()) {
						sectionNameStringTableIndex = section.sh_link;
					}
				}

				if (section.getType() == ElfSectionConstants.SHT_SYMTAB_SHNDX) {
					hasExtendedSymbolSectionIndexTable = true;
				}

				sections[i] = section;
			}
		}

		private void parseSegments(Consumer<String> errorConsumer) throws IOException {
			boolean missing = false;

			for (int i = 0; i < segments.length; ++i) {
				long index = header.e_phoff + (i * header.e_phentsize);
				if (!missing && !providerContainsRegion(index, header.e_phentsize)) {
					errorConsumer.accept(TRUNCATED_MSG.formatted("segments",
						i - sections.length, sections.length));
					missing = true;
				}

				reader.setPointerIndex(index);
				segments[i] = new ElfSegment(ElfFile.this, reader);
			}

			// TODO: Find sample file which requires this hack to verify its necessity
			// HACK: 07/01/2013 - Added hack for malformed ELF file with only segment sections
			long size = 0;
			for (ElfSegment pheader : segments) {
				size += pheader.getFileSize();
			}
			if (size == reader.length()) {
				// adjust program section file offset to be based on relative read offset
				long relOffset = 0;
				for (ElfSegment pheader : segments) {
					pheader.setOffset(relOffset);
					relOffset += pheader.getFileSize();
				}
			}
		}

		/**
		 * Some elfs can get pre-linked to an OS. At the very end a "PRE " string is
		 * appended with the image base load address set.
		 */
		private void parsePreLinkImageBase() throws IOException {
			long fileLength = reader.getByteProvider().length();

			int preLinkImageBaseInt = reader.readInt(fileLength - 8);
			String preLinkMagicString = reader.readAsciiString(fileLength - 4, 4).trim();

			if (preLinkMagicString.equals("PRE")) {
				preLinkImageBase = Integer.toUnsignedLong(preLinkImageBaseInt);
			}
		}

		private boolean hasExtendedSegmentCount() {
			return header.e_shoff != 0 &&
				header.e_phnum == Short.toUnsignedInt(ElfConstants.PN_XNUM);
		}

		private boolean hasExtendedSectionCount() {
			return header.e_shoff != 0 && (header.e_shnum == 0 ||
				header.e_shnum >= Short.toUnsignedInt(ElfSectionConstants.SHN_LORESERVE));
		}

		private boolean hasExtendedSectionNameStringTableIndex() {
			return header.e_shoff != 0 &&
				header.e_shstrndx == Short.toUnsignedInt(ElfSectionConstants.SHN_XINDEX);
		}

		private boolean providerContainsRegion(long offset, int length) {
			try {
				return offset >= 0 && (offset + length) <= provider.length();
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	private void initElfLoadAdapter() {
		ElfSegmentType.addDefaultTypes(programHeaderTypeMap);
		ElfSectionType.addDefaultTypes(sectionHeaderTypeMap);
		ElfDynamicType.addDefaultTypes(dynamicTypeMap);

		ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(this);
		if (extensionAdapter != null) {
			extensionAdapter.addSegmentTypes(programHeaderTypeMap);
			extensionAdapter.addSectionTypes(sectionHeaderTypeMap);
			extensionAdapter.addDynamicTypes(dynamicTypeMap);
			elfLoadAdapter = extensionAdapter;
		}
	}

	private ElfFileSection findFileSection(long address, long length, long entrySize) throws NotFoundException {
		for (ElfSection section : sections) {
			if (section.getVirtualAddress() == address &&
				section.getMemorySize() == length &&
				section.getEntrySize() == entrySize) {
					return section;
			}
		}

		ElfSegment loadHeader = getSegment(
			ElfSegment.isProgramLoadHeaderContaining(address));
		if (loadHeader == null || loadHeader.getMemorySize() < length) {
			throw new NotFoundException("No segment found covering " + length + " bytes at 0x" + Long.toHexString(address));
		}

		return loadHeader.subSection(address - loadHeader.getVirtualAddress(), length, entrySize);
	}


	private void parseDynamicTable() throws IOException {
		ElfFileSection dynamicFileSection = null;
		List<ElfSection> dynamicSections = getSections(e -> e.getType() == ElfSectionConstants.SHT_DYNAMIC);

		if (dynamicSections.size() >= 1) {
			dynamicFileSection = dynamicSections.get(0);

			if (dynamicSections.size() > 1) {
				errorConsumer.accept("Multiple ELF dynamic sections found");
			}
		}
		else {
			try {
				List<ElfSegment> dynamicHeaders = getSegments(e -> e.getType() == ElfSegmentConstants.PT_DYNAMIC);

				if (dynamicHeaders.size() >= 1) {
					long vaddr = dynamicHeaders.get(0).getVirtualAddress();
					long size = dynamicHeaders.get(0).getMemorySize();
					long entrySize = is32Bit() ? 8 : 16;

					dynamicFileSection = findFileSection(vaddr, size, entrySize);

					if (dynamicHeaders.size() > 1) {
						errorConsumer.accept("Multiple ELF dynamic table segments found");
					}
				}
			}
			catch (NotFoundException e) {
				errorConsumer.accept("Couldn't find dynamic table: " + e.getMessage());
			}
		}

		if (dynamicFileSection != null) {
			dynamicTable = new ElfDynamicTable(ElfFile.this, dynamicFileSection);
		}
	}

	private void parseDynamicLibraryNames() {
		if (dynamicTable == null) {
			return;
		}

		ElfDynamic[] needed = dynamicTable.getDynamics(ElfDynamicType.DT_NEEDED);

		for (int i = 0; i < needed.length; i++) {
			String dynamicLibraryName = null;

			if (dynamicStringTable != null) {
				try {
					dynamicLibraryName = dynamicStringTable.readString(needed[i].getValue());
				}
				catch (Exception e) {
					// ignore
				}
			}
			if (dynamicLibraryName == null) {
				dynamicLibraryName = "UNK_LIB_NAME_" + i;
			}

			dynamicLibraryNames.add(dynamicLibraryName);
		}
	}

	// String table parsing.

	private void parseStringTables() {
		ElfFileSection dynamicStringFileSection = null;

		try {
			if (dynamicTable != null) {
				long dynamicStringTableAddr = adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB));
				long dynamicStringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);

				dynamicStringFileSection = findFileSection(dynamicStringTableAddr, dynamicStringTableSize, 0);
			}
		}
		catch (NotFoundException e) {
			errorConsumer.accept("Couldn't find dynamic string table: " + e.getMessage());
		}

		List<ElfFileSection> stringFileSections =
			Stream.concat(
				sections.stream()
					.filter(e -> e.getType() == ElfSectionConstants.SHT_STRTAB)
					.map(e -> (ElfFileSection) e),
				dynamicStringFileSection != null ? Stream.of(dynamicStringFileSection) : Stream.empty()
			).distinct().toList();

		for (ElfFileSection stringFileSection : stringFileSections) {
			ElfStringTable stringTable = new ElfStringTable(ElfFile.this, stringFileSection);
			stringTables.add(stringTable);

			if (stringFileSection == dynamicStringFileSection) {
				dynamicStringTable = stringTable;
			}
		}
	}

	// Symbol table parsing.

	private void parseSymbolTables(BinaryReader reader) throws IOException {
		ElfFileSection dynamicSymbolFileSection = null;

		try {
			if (dynamicTable != null) {
				long dynamicSymbolTableAddr = adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB));
				long dynamicSymbolTableEntrySize = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);

				ElfDynamicType dynamicHashType = getDynamicHashTableType();
				long dynamicHashTableAddr = adjustAddressForPrelink(dynamicTable.getDynamicValue(dynamicHashType));
				ElfSegment hashTableLoadHeader = getSegment(
					ElfSegment.isProgramLoadHeaderContaining(dynamicHashTableAddr));
				if (hashTableLoadHeader == null) {
					throw new NotFoundException("Couldn't find segment containing dynamic hash table");
				}

				// determine symbol count from dynamic symbol hash table
				int symCount;
				long symbolHashTableOffset = hashTableLoadHeader.getOffset(dynamicHashTableAddr);
				if (dynamicHashType == ElfDynamicType.DT_GNU_HASH) {
					symCount = deriveGnuHashDynamicSymbolCount(reader, symbolHashTableOffset);
				}
				else if (dynamicHashType == ElfDynamicType.DT_GNU_XHASH) {
					symCount = deriveGnuXHashDynamicSymbolCount(reader, symbolHashTableOffset);
				}
				else {
					// DT_HASH table, nchain corresponds is same as symbol count
					symCount = reader.readInt(symbolHashTableOffset + 4); // nchain from DT_HASH
				}

				dynamicSymbolFileSection = findFileSection(
					dynamicSymbolTableAddr, dynamicSymbolTableEntrySize * symCount,
					dynamicSymbolTableEntrySize
				);
			}
		}
		catch (NotFoundException e) {
			errorConsumer.accept("Couldn't find dynamic symbol table:" + e.getMessage());
		}

		// Note: we might not be able to recover the full symbol count from dynamic data alone in some cases with
		// GNU_HASH, which results in a truncated dynamic symbol table. Recover from the DYNSYM section if we can.
		for (ElfFileSection dynsym : getSections(e -> e.getType() == ElfSectionConstants.SHT_DYNSYM)) {
			if (dynsym != null && dynsym.getVirtualAddress() == dynamicSymbolFileSection.getVirtualAddress() &&
					dynsym.getMemorySize() > dynamicSymbolFileSection.getMemorySize()) {
				dynamicSymbolFileSection = dynsym;
			}
		}

		List<ElfFileSection> symbolFileSections =
			Stream.concat(
				sections.stream()
					.filter(e -> e.getType() == ElfSectionConstants.SHT_SYMTAB || e.getType() == ElfSectionConstants.SHT_DYNSYM)
					.map(e -> (ElfFileSection) e),
					dynamicSymbolFileSection != null ? Stream.of(dynamicSymbolFileSection) : Stream.empty()
			).distinct().toList();

		for (ElfFileSection symbolFileSection : symbolFileSections) {
			boolean isDynamicSymbolTable = symbolFileSection == dynamicSymbolFileSection;
			int[] symbolSectionIndexTable;
			ElfStringTable stringTable;

			if (symbolFileSection instanceof ElfSection) {
				ElfSection symbolTableSection = (ElfSection) symbolFileSection;
				stringTable = getStringTable(sections.get(symbolTableSection.getLink()));

				// get extended symbol section index table if present
				symbolSectionIndexTable = getExtendedSymbolSectionIndexTable(symbolTableSection);
			}
			else {
				stringTable = dynamicStringTable;

				// NOTE: When parsed from dynamic table and not found via section parse
				// it is assumed that the extended symbol section table is not used.
				symbolSectionIndexTable = null;
			}

			ElfSymbolTable symbolTable = new ElfSymbolTable(ElfFile.this, symbolFileSection, stringTable, symbolSectionIndexTable, isDynamicSymbolTable);
			symbolTables.add(symbolTable);

			if (isDynamicSymbolTable) {
				dynamicSymbolTable = symbolTable;
			}
		}
	}

	private ElfDynamicType getDynamicHashTableType() {
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_HASH)) {
			return ElfDynamicType.DT_HASH;
		}
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_HASH)) {
			return ElfDynamicType.DT_GNU_HASH;
		}
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_XHASH)) {
			return ElfDynamicType.DT_GNU_XHASH;
		}
		return null;
	}

	/**
	 * Walk DT_GNU_HASH table to determine dynamic symbol count
	 * @param gnuHashTableOffset DT_GNU_HASH table file offset
	 * @return dynamic symbol count
	 * @throws IOException file read error
	 */
	private int deriveGnuHashDynamicSymbolCount(BinaryReader reader, long gnuHashTableOffset) throws IOException {
		int numBuckets = reader.readInt(gnuHashTableOffset);
		int symbolBase = reader.readInt(gnuHashTableOffset + 4);
		int bloomSize = reader.readInt(gnuHashTableOffset + 8);
		// int bloomShift = reader.readInt(gnuHashTableOffset + 12);
		int bloomWordSize = is64Bit() ? 8 : 4;
		long bucketsOffset = gnuHashTableOffset + 16 + (bloomWordSize * bloomSize);

		long bucketOffset = bucketsOffset;
		int maxSymbolIndex = 0;
		for (int i = 0; i < numBuckets; i++) {
			int symbolIndex = reader.readInt(bucketOffset);
			if (symbolIndex > maxSymbolIndex) {
				maxSymbolIndex = symbolIndex;
			}
			bucketOffset += 4;
		}

		int chainIndex = maxSymbolIndex - symbolBase;

		++maxSymbolIndex;
		long chainOffset = bucketOffset + (4 * chainIndex); // chains immediately follow buckets
		while (true) {
			int chainValue = reader.readInt(chainOffset);
			if ((chainValue & 1) != 0) {
				break;
			}
			++maxSymbolIndex;
			chainOffset += 4;
		}
		return maxSymbolIndex;
	}

	/**
	 * Walk DT_GNU_XHASH table to determine dynamic symbol count
	 * @param gnuHashTableOffset DT_GNU_XHASH table file offset
	 * @return dynamic symbol count
	 * @throws IOException file read error
	 */
	private int deriveGnuXHashDynamicSymbolCount(BinaryReader reader, long gnuHashTableOffset) throws IOException {
		// Elf32_Word  ngnusyms;  // number of entries in chains (and xlat); dynsymcount=symndx+ngnusyms
		// Elf32_Word  nbuckets;  // number of hash table buckets
		// Elf32_Word  symndx;  // number of initial .dynsym entires skipped in chains[] (and xlat[])
		int ngnusyms = reader.readInt(gnuHashTableOffset);
		int symndx = reader.readInt(gnuHashTableOffset + 8);

		return symndx + ngnusyms;
	}

	private int[] getExtendedSymbolSectionIndexTable(ElfSection symbolTableSection) {
		ElfSection symbolSectionIndexHeader = null;
		int[] indexTable = null;

		if (hasExtendedSymbolSectionIndexTable) {
			// Find SHT_SYMTAB_SHNDX section linked to specified symbol table section
			for (ElfSection section : sections) {
				if (section.getType() != ElfSectionConstants.SHT_SYMTAB_SHNDX) {
					continue;
				}
				int linkIndex = section.getLink();
				if (linkIndex <= 0 || linkIndex >= sections.size()) {
					continue;
				}
				if (sections.get(linkIndex) == symbolTableSection) {
					symbolSectionIndexHeader = section;
					break;
				}
			}
		}

		if (symbolSectionIndexHeader != null) {
			// determine number of 32-bit index elements for int[]
			int count = (int) (symbolSectionIndexHeader.getFileSize() / 4);
			indexTable = new int[count];
			BinaryReader reader = symbolSectionIndexHeader.getReader();

			try {
				for (int i = 0; i < count; i++) {
					indexTable[i] = reader.readNextInt();
				}
			}
			catch (IOException e) {
				errorConsumer.accept("Failed to read symbol section index table at 0x" +
					Long.toHexString(symbolSectionIndexHeader.getFileOffset()) + ": " +
					symbolSectionIndexHeader.getNameAsString());
			}
		}

		return indexTable;
	}

	// Relocation table parsing.

	private class ElfRelocationTableBuilder {
		public ElfFileSection fileSection;
		public boolean addendTypeReloc;
		public ElfSymbolTable symbolTable;
		public ElfSection sectionToBeRelocated;
		public ElfRelocationTable.TableFormat format;

		public ElfRelocationTableBuilder(ElfSection section) throws NotFoundException {
			this.fileSection = section;

			int sectionType = section.getType();

			this.addendTypeReloc = (sectionType == ElfSectionConstants.SHT_RELA ||
				sectionType == ElfSectionConstants.SHT_ANDROID_RELA);

			int link = section.getLink(); // section index of associated symbol table
			if (link == 0) {
				// dynamic symbol table assumed when link section value is 0
				symbolTable = dynamicSymbolTable;
			}
			else {
				ElfSection symbolTableSection = getLinkedSection(link,
					ElfSectionConstants.SHT_DYNSYM, ElfSectionConstants.SHT_SYMTAB);
				symbolTable = getSymbolTable(symbolTableSection);
			}

			int info = section.getInfo(); // section index of section to which relocations apply (relocation offset base)
			this.sectionToBeRelocated = info != 0 ? getLinkedSection(info) : null;

			if (sectionType == ElfSectionConstants.SHT_ANDROID_REL ||
				sectionType == ElfSectionConstants.SHT_ANDROID_RELA) {
				this.format = ElfRelocationTable.TableFormat.ANDROID;
			}
			else if (sectionType == ElfSectionConstants.SHT_RELR ||
				sectionType == ElfSectionConstants.SHT_ANDROID_RELR) {
				this.format = ElfRelocationTable.TableFormat.RELR;
			}
			else {
				this.format = ElfRelocationTable.TableFormat.DEFAULT;
			}
		}

		public ElfRelocationTableBuilder(ElfFileSection fileSection, ElfDynamicType relocType,
				boolean addendTypeReloc) {
			this.fileSection = fileSection;
			this.addendTypeReloc = addendTypeReloc;
			this.symbolTable = dynamicSymbolTable;
			this.sectionToBeRelocated = null;

			if (relocType == ElfDynamicType.DT_ANDROID_REL ||
				relocType == ElfDynamicType.DT_ANDROID_RELA) {
				this.format = ElfRelocationTable.TableFormat.ANDROID;
			}
			else if (relocType == ElfDynamicType.DT_RELR ||
				relocType == ElfDynamicType.DT_ANDROID_RELR) {
				this.format = ElfRelocationTable.TableFormat.RELR;
			}
			else {
				this.format = ElfRelocationTable.TableFormat.DEFAULT;
			}
		}

		public ElfRelocationTable build() throws IOException {
			return new ElfRelocationTable(ElfFile.this, fileSection, addendTypeReloc,
				symbolTable, sectionToBeRelocated, format);
		}

		/**
		 * Get linked section
		 * @param sectionIndex section index
		 * @param expectedTypes list of expectedTypes (may be omitted to accept any type)
		 * @return section or null if not found
		 */
		private ElfSection getLinkedSection(int sectionIndex, int... expectedTypes)
				throws NotFoundException {
			if (sectionIndex < 0 || sectionIndex >= sections.size()) {
				throw new NotFoundException("invalid linked section index " + sectionIndex);
			}
			ElfSection section = sections.get(sectionIndex);
			if (expectedTypes.length == 0) {
				return section;
			}
			for (int type : expectedTypes) {
				if (type == section.getType()) {
					return section;
				}
			}
			throw new NotFoundException("unexpected section type for section index " + sectionIndex);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}

			if (!(obj instanceof ElfRelocationTableBuilder)) {
				return false;
			}

			ElfRelocationTableBuilder builder = (ElfRelocationTableBuilder) obj;
			return fileSection == builder.fileSection &&
				addendTypeReloc == builder.addendTypeReloc &&
				symbolTable == builder.symbolTable &&
				sectionToBeRelocated == builder.sectionToBeRelocated &&
				format == builder.format;
		}

		@Override
		public int hashCode() {
			return Objects.hash(fileSection, addendTypeReloc, symbolTable, sectionToBeRelocated,
				format);
		}
	}

	private static Set<Integer> SECTION_RELOCATION_TYPES =
		Set.of(ElfSectionConstants.SHT_REL, ElfSectionConstants.SHT_RELA,
			ElfSectionConstants.SHT_RELR, ElfSectionConstants.SHT_ANDROID_REL,
			ElfSectionConstants.SHT_ANDROID_RELA, ElfSectionConstants.SHT_ANDROID_RELR);

	private void parseRelocationTables() throws IOException {
		ArrayList<ElfRelocationTableBuilder> relocationTableBuilderList = new ArrayList<>();

		// Order of parsing and processing dynamic relocation tables can be important to ensure that
		// GOT/PLT relocations are applied late.
		if (dynamicTable != null && dynamicSymbolTable != null) {
			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_REL,
				ElfDynamicType.DT_RELENT, ElfDynamicType.DT_RELSZ, false));

			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_RELA,
				ElfDynamicType.DT_RELAENT, ElfDynamicType.DT_RELASZ, true));

			relocationTableBuilderList.add(parseJMPRelocTable());

			// Android versions
			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_ANDROID_REL,
				null, ElfDynamicType.DT_ANDROID_RELSZ, false));

			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_ANDROID_RELA,
				null, ElfDynamicType.DT_ANDROID_RELASZ, true));

			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_RELR,
				ElfDynamicType.DT_RELRENT, ElfDynamicType.DT_RELRSZ, false));

			relocationTableBuilderList.add(parseDynamicRelocTable(ElfDynamicType.DT_ANDROID_RELR,
				ElfDynamicType.DT_ANDROID_RELRENT, ElfDynamicType.DT_ANDROID_RELRSZ, false));
		}

		// In general the above dynamic relocation tables should cover most cases, we will
		// check sections for possible custom relocation tables
		for (ElfSection section : sections) {
			if (SECTION_RELOCATION_TYPES.contains(section.getType())) {
				try {
					relocationTableBuilderList.add(new ElfRelocationTableBuilder(section));
				}
				catch (NotFoundException e) {
					String msg = String.format("Failed to process relocation section %s: %s",
						section.getNameAsString(), e.getMessage());
					errorConsumer.accept(msg);
				}
			}
		}

		List<ElfRelocationTableBuilder> filteredRelocationTableBuilderList =
			relocationTableBuilderList.stream().filter(r -> r != null).distinct().toList();

		for (ElfRelocationTableBuilder builder : filteredRelocationTableBuilderList) {
			relocationTables.add(builder.build());
		}
	}

	private ElfRelocationTableBuilder parseDynamicRelocTable(
			ElfDynamicType relocTableAddrType, ElfDynamicType relocEntrySizeType,
			ElfDynamicType relocTableSizeType, boolean addendTypeReloc) throws IOException {
		// NOTE: Dynamic and Relocation tables are loaded into memory, however,
		// we construct them without loading so we must map memory addresses 
		// back to file offsets.
		ElfRelocationTableBuilder builder = null;

		try {
			long relocTableAddr =
				adjustAddressForPrelink(dynamicTable.getDynamicValue(relocTableAddrType));
			long tableSize = dynamicTable.getDynamicValue(relocTableSizeType);
			long tableEntrySize =
				relocEntrySizeType != null ? dynamicTable.getDynamicValue(relocEntrySizeType) : 1;

			ElfFileSection fileSection = findFileSection(relocTableAddr, tableSize, tableEntrySize);

			if (fileSection instanceof ElfSection) {
				builder = new ElfRelocationTableBuilder((ElfSection) fileSection);
			}
			else {
				builder =
					new ElfRelocationTableBuilder(fileSection, relocTableAddrType, addendTypeReloc);
			}
		}
		catch (NotFoundException e) {
			// ignore - skip (required dynamic table value is missing)
		}

		return builder;
	}

	private ElfRelocationTableBuilder parseJMPRelocTable()
			throws IOException {
		ElfRelocationTableBuilder builder = null;

		try {
			long tableType = dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTREL);
			boolean addendTypeReloc = (tableType == ElfDynamicType.DT_RELA.value);

			builder = parseDynamicRelocTable(ElfDynamicType.DT_JMPREL,
				addendTypeReloc ? ElfDynamicType.DT_RELAENT : ElfDynamicType.DT_RELENT,
				ElfDynamicType.DT_PLTRELSZ, addendTypeReloc);
		}
		catch (NotFoundException e) {
			// ignore - skip
		}

		return builder;
	}

	// Misc. parsing.

	private void parseGNU_d() {
		List<ElfSection> sections = getSections(e -> e.getType() == ElfSectionConstants.SHT_GNU_verdef);
		if (sections.size() == 0) {
			return;
		}
		//TODO: ElfSection gnuVersionD = sections[0];
	}

	private void parseGNU_r() {
		List<ElfSection> sections = getSections(e -> e.getType() == ElfSectionConstants.SHT_GNU_verneed);
		if (sections.size() == 0) {
			return;
		}
		//TODO ElfSection gnuVersionR = sections[0];
	}

	//
	// Getters/setters.
	//

	public ElfHeader getHeader() {
		return header;
	}

	/**
	 * Returns the sections as defined in this ELF file.
	 * @return the sections as defined in this ELF file
	 */
	public List<ElfSection> getSections() {
		return Collections.unmodifiableList(sections);
	}

	/**
	 * Returns the sections matching the predicate.
	 * @param predicate predicate for section
	 * @return the sections matching the predicate
	 * @see ElfSection
	 */
	public List<ElfSection> getSections(Predicate<ElfSection> predicate) {
		return sections.stream().filter(predicate).toList();
	}

	/**
	 * Returns the first section matching the predicate, or null.
	 * @param predicate for section
	 * @return the section matching the predicate
	 */
	public ElfSection getSection(Predicate<ElfSection> predicate) {
		return sections.stream().filter(predicate).findFirst().orElse(null);
	}

	public ElfSection addSection(String name, int type, long flags, ElfSection link,
		int info, long addressAlignment, long entrySize, ByteProvider data) throws IOException {
		int linkNum = link != null ? sections.indexOf(link) : 0;

		ElfSection section = new ElfSection(this, name, type, flags,
				linkNum, info, addressAlignment, entrySize, data);

		if (type == ElfSectionConstants.SHT_STRTAB) {
			stringTables.add(new ElfStringTable(this, section));
		}
		else if (type == ElfSectionConstants.SHT_SYMTAB) {
			ElfStringTable stringTable = getStringTable(link);
			symbolTables.add(new ElfSymbolTable(this, section, stringTable, null, false));
		}
		else if (type == ElfSectionConstants.SHT_REL) {
			ElfSymbolTable symbolTable = getSymbolTable(link);
			relocationTables.add(new ElfRelocationTable(this, section, false, symbolTable, null, ElfRelocationTable.TableFormat.DEFAULT));
		}

		sections.add(section);
		header.e_shnum += 1;

		return section;
	}
	/**
	 * Returns the segments as defined in this ELF file.
	 * @return the segments as defined in this ELF file
	 */
	public List<ElfSegment> getSegments() {
		return Collections.unmodifiableList(segments);
	}

	/**
	 * Returns the segments matching the predicate.
	 * @param predicate predicate for segment
	 * @return the segments matching the predicate
	 * @see ElfSegment
	 */
	public List<ElfSegment> getSegments(Predicate<ElfSegment> predicate) {
		return segments.stream().filter(predicate).toList();
	}

	/**
	 * Returns the first segment matching the predicate, or null.
	 * @param predicate for segment
	 * @return the segment matching the predicate
	 */
	public ElfSegment getSegment(Predicate<ElfSegment> predicate) {
		return segments.stream().filter(predicate).findFirst().orElse(null);
	}
	
	/**
	 * Returns the dynamic table defined by segment of type PT_DYNAMIC or the .dynamic program section.
	 * Or, null if one does not exist.
	 * @return the dynamic table
	 */
	public ElfDynamicTable getDynamicTable() {
		return dynamicTable;
	}

	/**
	 * Returns list of dynamic library names defined by DT_NEEDED
	 * @return list of dynamic library names
	 */
	public List<String> getDynamicLibraryNames() {
		return Collections.unmodifiableList(dynamicLibraryNames);
	}

	/**
	 * Returns the dynamic string table as defined in this ELF file.
	 * @return the dynamic string table as defined in this ELF file
	 */
	public ElfStringTable getDynamicStringTable() {
		return dynamicStringTable;
	}

	/**
	 * Returns the string tables as defined in this ELF file.
	 * @return the string tables as defined in this ELF file
	 */
	public List<ElfStringTable> getStringTables() {
		return Collections.unmodifiableList(stringTables);
	}

	/**
	 * Returns the string table associated to the specified section.
	 * Or, null if one does not exist.
	 * @param section section whose associated string table is requested
	 * @return the string table associated to the specified section
	 */
	public ElfStringTable getStringTable(ElfSection section) {
		for (ElfStringTable stringTable : stringTables) {
			if (stringTable.getFileSection() == section) {
				return stringTable;
			}
		}
		return null;
	}

	/**
	 * Returns the dynamic symbol table as defined in this ELF file.
	 * @return the dynamic symbol table as defined in this ELF file
	 */
	public ElfSymbolTable getDynamicSymbolTable() {
		return dynamicSymbolTable;
	}

	/**
	 * Returns the symbol tables as defined in this ELF file.
	 * @return the symbol tables as defined in this ELF file
	 */
	public List<ElfSymbolTable> getSymbolTables() {
		return Collections.unmodifiableList(symbolTables);
	}

	/**
	 * Returns the symbol table associated to the specified section.
	 * Or, null if one does not exist.
	 * @param section symbol table section
	 * @return the symbol table associated to the specified section
	 */
	public ElfSymbolTable getSymbolTable(ElfSection section) {
		for (ElfSymbolTable symbolTable : symbolTables) {
			if (symbolTable.getFileSection() == section) {
				return symbolTable;
			}
		}
		return null;
	}

	/**
	 * Returns the relocation tables as defined in this ELF file.
	 * @return the relocation tables as defined in this ELF file
	 */
	public List<ElfRelocationTable> getRelocationTables() {
		return Collections.unmodifiableList(relocationTables);
	}

	/**
	 * Returns the relocation table associated to the specified section,
	 * or null if one does not exist.
	 * @param section section corresponding to relocation table
	 * @return the relocation table associated to the specified section
	 */
	public ElfRelocationTable getRelocationTable(ElfSection section) {
		for (ElfRelocationTable relocationTable : relocationTables) {
			if (relocationTable.getFileSection() == section) {
				return relocationTable;
			}
		}
		return null;
	}

	/**
	 * Returns the relocation table located at the specified fileOffset,
	 * or null if one does not exist.
	 * @param fileOffset file offset corresponding to start of relocation table
	 * @return the relocation table located at the specified fileOffset or null
	 */
	public ElfRelocationTable getRelocationTableAtOffset(long fileOffset) {
		for (ElfRelocationTable relocationTable : relocationTables) {
			if (relocationTable.getFileSection().getFileOffset() == fileOffset) {
				return relocationTable;
			}
		}
		return null;
	}

	/**
	 * Returns the index for the section name string table.
	 * @return section index
	 */
	public int getSectionNameStringTableIndex() {
		return sectionNameStringTableIndex;
	}

	//
	// Load adapter.
	//

	/**
	 * Get the installed extension provider.  If the parse method has not yet been 
	 * invoked, the default adapter will be returned.
	 * @return ELF load adapter
	 */
	public ElfLoadAdapter getLoadAdapter() {
		return elfLoadAdapter;
	}

	protected Map<Integer, ElfSegmentType> getSegmentTypeMap() {
		return programHeaderTypeMap;
	}

	protected Map<Integer, ElfSectionType> getSectionTypeMap() {
		return sectionHeaderTypeMap;
	}

	public ElfSegmentType getSegmentType(int type) {
		if (programHeaderTypeMap != null) {
			return programHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	public ElfSectionType getSectionType(int type) {
		if (sectionHeaderTypeMap != null) {
			return sectionHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	protected Map<Integer, ElfDynamicType> getDynamicTypeMap() {
		return dynamicTypeMap;
	}

	public ElfDynamicType getDynamicType(int type) {
		if (dynamicTypeMap != null) {
			return dynamicTypeMap.get(type);
		}
		return null; // not found
	}

	String getTypeSuffix() {
		if (elfLoadAdapter == null) {
			return null;
		}
		String typeSuffix = elfLoadAdapter.getDataTypeSuffix();
		if (typeSuffix != null && typeSuffix.length() == 0) {
			typeSuffix = null;
		}
		return typeSuffix;
	}

	//
	// Helper methods.
	//
	
	/**
	 * Returns true if this ELF was created for a big endian processor.
	 * @return true if this ELF was created for a big endian processor
	 */
	public boolean isBigEndian() {
		return header.isBigEndian();
	}

	/**
	 * Returns true if this ELF was created for a little endian processor.
	 * @return true if this ELF was created for a little endian processor
	 */
	public boolean isLittleEndian() {
		return header.isLittleEndian();
	}

	/**
	 * Returns true if this ELF was created for a 32-bit processor.
	 * @return true if this ELF was created for a 32-bit processor
	 */
	public boolean is32Bit() {
		return header.is32Bit();
	}

	/**
	 * Returns true if this ELF was created for a 64-bit processor.
	 * @return true if this ELF was created for a 64-bit processor
	 */
	public boolean is64Bit() {
		return header.is64Bit();
	}

	/**
	 * Determine if the image has been pre-linked.
	 * NOTE: Currently has very limited support.  Certain pre-link
	 * cases can not be detected until after a full parse has been 
	 * performed.
	 * @return true if image has been pre-linked
	 */
	public boolean isPreLinked() {
		if (preLinkImageBase != null) {
			return true;
		}
		if (dynamicTable != null) {
			if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_PRELINKED)) {
				return true;
			}
		}
		return false;
	}
	/**
	 * Returns true if this is a relocatable file.
	 * @return true if this is a relocatable file
	 */
	public boolean isRelocatable() {
		return header.isRelocatable();
	}

	/**
	 * Returns true if this is a shared object file.
	 * @return true if this is a shared object file
	 */
	public boolean isSharedObject() {
		return header.isSharedObject();
	}

	/**
	 * Returns true if this is an executable file.
	 * @return true if this is a executable file
	 */
	public boolean isExecutable() {
		return header.isExecutable();
	}

	private long getMinBase(long addr, long minBase) {
		if (is32Bit()) {
			addr = Integer.toUnsignedLong((int) addr);
		}
		if (Long.compareUnsigned(addr, minBase) < 0) {
			minBase = addr;
		}
		return minBase;
	}

	/**
	 * Returns the image base of this ELF. 
	 * The image base is the virtual address of the first PT_LOAD
	 * segment or 0 if no segments. By default,
	 * the image base address should be treated as a addressable unit offset.s
	 * @return the image base of this ELF
	 */
	public long getImageBase() {
		if (elfImageBase != null) {
			return elfImageBase;
		}

		elfImageBase = 0L;

		if (preLinkImageBase != null) {
			elfImageBase = preLinkImageBase;
		}
		else {
			int n = Math.min(segments.size(), MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
			long minBase = -1;
			for (int i = 0; i < n; i++) {
				ElfSegment header = segments.get(i);
				if (header.getType() == ElfSegmentConstants.PT_LOAD) {
					minBase = getMinBase(header.getVirtualAddress(), minBase);
				}
			}
			elfImageBase = (minBase == -1 ? 0 : minBase);
		}
		return elfImageBase;
	}

	/**
	 * Adjust address offset for certain pre-linked binaries which do not adjust certain
	 * header fields (e.g., dynamic table address entries).  Standard GNU/Linux pre-linked 
	 * shared libraries have adjusted header entries and this method should have no effect. 
	 * @param address unadjusted address offset
	 * @return address with appropriate pre-link adjustment added
	 */
	public long adjustAddressForPrelink(long address) {

		// TODO: how do we ensure that adjustment is only made to 
		// addresses in the default space?  Should loads into
		// data space have the same adjustment?

		return address + (preLinkImageBase != null ? preLinkImageBase : 0);
	}

	/**
	 * Unadjust address offset for certain pre-linked binaries which do not adjust certain
	 * header fields (e.g., dynamic table address entries).  This may be needed when updating
	 * a header address field which requires pre-link adjustment.
	 * @param address prelink-adjusted address offset
	 * @return address with appropriate pre-link adjustment subtracted
	 */
	public long unadjustAddressForPrelink(long address) {

		// TODO: how do we ensure that adjustment is only made to 
		// addresses in the default space?  Should loads into
		// data space have the same adjustment?

		return address - (preLinkImageBase != null ? preLinkImageBase : 0);
	}

	public void logError(String string) {
		errorConsumer.accept(string);
	}
}