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
import java.io.RandomAccessFile;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

/**
 * A class to represent the Executable and Linking Format (ELF)
 * header and specification.
 */
public class ElfHeader implements StructConverter, Writeable {

	private static final int MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE = 20;

	private static final int PAD_LENGTH = 7;

	private HashMap<Integer, ElfProgramHeaderType> programHeaderTypeMap;
	private HashMap<Integer, ElfSectionHeaderType> sectionHeaderTypeMap;
	private HashMap<Integer, ElfDynamicType> dynamicTypeMap;

	private ByteProvider provider; // original byte provider
	private BinaryReader reader; // unlimited reader
	private ElfLoadAdapter elfLoadAdapter = new ElfLoadAdapter();

	private byte e_ident_magic_num; //magic number
	private String e_ident_magic_str; //magic string
	private byte e_ident_class; //file class
	private byte e_ident_data; //data encoding
	private byte e_ident_version; //file version
	private byte e_ident_osabi; //operating system and abi
	private byte e_ident_abiversion; //abi version
	private byte[] e_ident_pad; //padding
	private short e_type; //object file type
	private short e_machine; //target architecture
	private int e_version; //object file version
	private long e_entry; //executable entry point
	private long e_phoff; //program header table offset
	private long e_shoff; //section header table offset
	private int e_flags; //processor-specific flags
	private short e_ehsize; //elf header size
	private short e_phentsize; //size of entries in the program header table
	private int e_phnum; //number of enties in the program header table (may be extended and may not be preserved)
	private short e_shentsize; //size of entries in the section header table
	private int e_shnum; //number of enties in the section header table (may be extended and may not be preserved)
	private int e_shstrndx; //section index of the section name string table (may be extended and may not be preserved)

	private Structure headerStructure;

	private boolean parsed = false;
	private boolean parsedSectionHeaders = false;

	private Long preLinkImageBase = null;
	private ElfSectionHeader section0 = null;
	private ElfSectionHeader[] sectionHeaders = new ElfSectionHeader[0];
	private ElfProgramHeader[] programHeaders = new ElfProgramHeader[0];
	private ElfStringTable[] stringTables = new ElfStringTable[0];
	private ElfSymbolTable[] symbolTables = new ElfSymbolTable[0];
	private ElfRelocationTable[] relocationTables = new ElfRelocationTable[0];
	private ElfDynamicTable dynamicTable;

	private ElfStringTable dynamicStringTable;
	private ElfSymbolTable dynamicSymbolTable;
	private boolean hasExtendedSymbolSectionIndexTable; // if SHT_SYMTAB_SHNDX sections exist

	private String[] dynamicLibraryNames;

	private boolean hasLittleEndianHeaders;

	private Consumer<String> errorConsumer;

	private static int INITIAL_READ_LEN = ElfConstants.EI_NIDENT + 18;

	/**
	 * Construct <code>ElfHeader</code> from byte provider
	 * @param provider byte provider
	 * @param errorConsumer error consumer
	 * @throws ElfException if header parse failed
	 */
	public ElfHeader(ByteProvider provider, Consumer<String> errorConsumer) throws ElfException {
		this.provider = provider;
		this.errorConsumer = errorConsumer != null ? errorConsumer : msg -> {
			/* no logging if errorConsumer was null */
		};
		initElfHeader();
	}

	private ElfFileSection findFileSection(long address, long length, long entrySize) throws NotFoundException {
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.getVirtualAddress() == address &&
				sectionHeader.getMemorySize() == length &&
				sectionHeader.getEntrySize() == entrySize) {
					return sectionHeader;
			}
		}

		ElfProgramHeader loadHeader = getProgramLoadHeaderContaining(address);
		if (loadHeader == null || loadHeader.getMemorySize() < length) {
			throw new NotFoundException("No program header found covering " + length + " bytes at 0x" + Long.toHexString(address));
		}

		return loadHeader.subSection(address - loadHeader.getVirtualAddress(), length, entrySize);
	}

	/**
	 * Returns the unconstrained binary reader (i.e., reads beyond EOF
	 * will return 0-bytes).
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Returns the byte provider
	 * @return the byte provider
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	void logError(String msg) {
		errorConsumer.accept(msg);
	}

	protected void initElfHeader() throws ElfException {
		try {
			if (provider.length() < INITIAL_READ_LEN) {
				throw new ElfException("Not enough bytes to be a valid ELF executable.");
			}
			byte[] initialBytes = provider.readBytes(0, INITIAL_READ_LEN);

			determineHeaderEndianess(initialBytes);

			// reader uses unbounded provider wrapper to allow handling of missing/truncated headers
			reader = new BinaryReader(new UnlimitedByteProviderWrapper(provider),
				hasLittleEndianHeaders);

			e_ident_magic_num = reader.readNextByte();
			e_ident_magic_str = reader.readNextAsciiString(ElfConstants.MAGIC_STR_LEN);

			boolean magicMatch = ElfConstants.MAGIC_NUM == e_ident_magic_num &&
				ElfConstants.MAGIC_STR.equalsIgnoreCase(e_ident_magic_str);

			if (!magicMatch) {
				throw new ElfException("Not a valid ELF executable.");
			}

			e_ident_class = reader.readNextByte();
			e_ident_data = reader.readNextByte();
			e_ident_version = reader.readNextByte();
			e_ident_osabi = reader.readNextByte();
			e_ident_abiversion = reader.readNextByte();
			e_ident_pad = reader.readNextByteArray(PAD_LENGTH);
			e_type = reader.readNextShort();
			e_machine = reader.readNextShort();
			e_version = reader.readNextInt();

			if (is32Bit()) {
				e_entry = reader.readNextUnsignedInt();
				e_phoff = reader.readNextUnsignedInt();
				e_shoff = reader.readNextUnsignedInt();
			}
			else if (is64Bit()) {
				e_entry = reader.readNextLong();
				e_phoff = reader.readNextLong();
				e_shoff = reader.readNextLong();
			}
			else {
				throw new ElfException(
					"Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x" +
						Integer.toHexString(e_ident_class) + ")");
			}

			e_flags = reader.readNextInt();
			e_ehsize = reader.readNextShort();

			e_phentsize = reader.readNextShort();
			e_phnum = reader.readNextUnsignedShort();

			e_shentsize = reader.readNextShort();
			e_shnum = reader.readNextUnsignedShort();

			e_shstrndx = Short.toUnsignedInt(reader.readNextShort());

			if (e_shnum == 0 ||
				e_shnum >= Short.toUnsignedInt(ElfSectionHeaderConstants.SHN_LORESERVE)) {
				e_shnum = readExtendedSectionHeaderCount(); // use extended stored section header count
			}

			if (e_phnum == Short.toUnsignedInt(ElfConstants.PN_XNUM)) {
				e_phnum = readExtendedProgramHeaderCount(); // use extended stored program header count
			}

			if (e_shnum == 0) {
				e_shstrndx = 0;
			}
			else if (e_shstrndx == Short.toUnsignedInt(ElfSectionHeaderConstants.SHN_XINDEX)) {
				e_shstrndx = readExtendedSectionHeaderStringTableIndex();
			}
		}
		catch (IOException e) {
			throw new ElfException(e);
		}
	}

	private ElfSectionHeader getSection0() throws IOException {
		if (section0 == null && e_shoff != 0) {
			if (!providerContainsRegion(e_shoff, e_shentsize)) {
				return null;
			}
			reader.setPointerIndex(e_shoff);
			section0 = new ElfSectionHeader(reader, this);
		}
		return section0;
	}

	/**
	 * Read extended program header count (e_phnum) stored in first section header (ST_NULL) 
	 * sh_info field value. This is done to overcome the short value limitation of the
	 * e_phnum header field.  Returned value is restricted to the range 0..0x7fffffff.
	 * @return extended program header count or 0 if not found or out of range
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedProgramHeaderCount() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s != null && s.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			int val = s.sh_info;
			return val < 0 ? 0 : val;
		}
		return 0;
	}

	/**
	 * Read extended section header count (e_shnum) stored in first section header (ST_NULL) 
	 * sh_size field value.  This is done to overcome the short value limitation of the
	 * e_shnum header field.  Returned value is restricted to the range 0..0x7fffffff.
	 * @return extended section header count or 0 if not found or out of range
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedSectionHeaderCount() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s != null && s.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			long val = s.sh_size;
			return (val < 0 || val > Integer.MAX_VALUE) ? 0 : (int) val;
		}
		return 0;
	}

	/**
	 * Read extended section header string table index (e_shstrndx) stored in first section header 
	 * (ST_NULL) sh_size field value.  This is done to overcome the short value limitation of the
	 * e_shstrndx header field.  Returned value is restricted to the range 0..0x7fffffff.
	 * @return extended section header count or 0 if not found or out of range
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedSectionHeaderStringTableIndex() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s != null && s.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			int val = s.sh_link;
			return val < 0 ? 0 : val;
		}
		return 0;
	}

	private void initElfLoadAdapter() {

		programHeaderTypeMap = new HashMap<>();
		ElfProgramHeaderType.addDefaultTypes(programHeaderTypeMap);

		sectionHeaderTypeMap = new HashMap<>();
		ElfSectionHeaderType.addDefaultTypes(sectionHeaderTypeMap);

		dynamicTypeMap = new HashMap<>();
		ElfDynamicType.addDefaultTypes(dynamicTypeMap);

		ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(this);
		if (extensionAdapter != null) {
			extensionAdapter.addProgramHeaderTypes(programHeaderTypeMap);
			extensionAdapter.addSectionHeaderTypes(sectionHeaderTypeMap);
			extensionAdapter.addDynamicTypes(dynamicTypeMap);
			elfLoadAdapter = extensionAdapter;
		}
	}

	/**
	 * Perform parse of all supported headers.
	 * @throws IOException if file IO error occurs
	 */
	public void parse() throws IOException {

		if (reader == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (parsed) {
			return;
		}

		initElfLoadAdapter();

		parsed = true;

		parsePreLinkImageBase();

		parseProgramHeaders();

		parseSectionHeaders();

		parseDynamicTable();

		parseStringTables();
		parseDynamicLibraryNames();
		parseSymbolTables();
		parseRelocationTables();

		parseGNU_d();
		parseGNU_r();
	}

	/**
	 * Get the installed extension provider.  If the parse method has not yet been 
	 * invoked, the default adapter will be returned.
	 * @return ELF load adapter
	 */
	public ElfLoadAdapter getLoadAdapter() {
		return elfLoadAdapter;
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

		return address + (preLinkImageBase != null ? preLinkImageBase : 0L);
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

		return address - (preLinkImageBase != null ? preLinkImageBase : 0L);
	}

	protected HashMap<Integer, ElfProgramHeaderType> getProgramHeaderTypeMap() {
		return programHeaderTypeMap;
	}

	protected HashMap<Integer, ElfSectionHeaderType> getSectionHeaderTypeMap() {
		return sectionHeaderTypeMap;
	}

	public ElfProgramHeaderType getProgramHeaderType(int type) {
		if (programHeaderTypeMap != null) {
			return programHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	public ElfSectionHeaderType getSectionHeaderType(int type) {
		if (sectionHeaderTypeMap != null) {
			return sectionHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	protected HashMap<Integer, ElfDynamicType> getDynamicTypeMap() {
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

	private void parseGNU_d() {
		ElfSectionHeader[] sections = getSections(ElfSectionHeaderConstants.SHT_GNU_verdef);
		if (sections.length == 0) {
			return;
		}
		//TODO: ElfSectionHeader gnuVersionD = sections[0];
	}

	private void parseGNU_r() {
		ElfSectionHeader[] sections = getSections(ElfSectionHeaderConstants.SHT_GNU_verneed);
		if (sections.length == 0) {
			return;
		}
		//TODO ElfSectionHeader gnuVersionR = sections[0];
	}

	private class ElfRelocationTableBuilder {
		public ElfFileSection fileSection;
		public boolean addendTypeReloc;
		public ElfSymbolTable symbolTable;
		public ElfSectionHeader sectionToBeRelocated;
		public ElfRelocationTable.TableFormat format;

		public ElfRelocationTableBuilder(ElfSectionHeader section) throws NotFoundException {
			this.fileSection = section;

			int sectionHeaderType = section.getType();

			this.addendTypeReloc = (sectionHeaderType == ElfSectionHeaderConstants.SHT_RELA ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA);

			int link = section.getLink(); // section index of associated symbol table
			if (link == 0) {
				// dynamic symbol table assumed when link section value is 0
				symbolTable = dynamicSymbolTable;
			}
			else {
				ElfSectionHeader symbolTableSection = getLinkedSection(link,
					ElfSectionHeaderConstants.SHT_DYNSYM, ElfSectionHeaderConstants.SHT_SYMTAB);
				symbolTable = getSymbolTable(symbolTableSection);
			}

			int info = section.getInfo(); // section index of section to which relocations apply (relocation offset base)
			this.sectionToBeRelocated = info != 0 ? getLinkedSection(info) : null;

			if (sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_REL ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA) {
				this.format = TableFormat.ANDROID;
			}
			else if (sectionHeaderType == ElfSectionHeaderConstants.SHT_RELR ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELR) {
				this.format = TableFormat.RELR;
			}
			else {
				this.format = TableFormat.DEFAULT;
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
				this.format = TableFormat.ANDROID;
			}
			else if (relocType == ElfDynamicType.DT_RELR ||
				relocType == ElfDynamicType.DT_ANDROID_RELR) {
				this.format = TableFormat.RELR;
			}
			else {
				this.format = TableFormat.DEFAULT;
			}
		}

		public ElfRelocationTable build() throws IOException {
			return new ElfRelocationTable(ElfHeader.this, fileSection, addendTypeReloc,
				symbolTable, sectionToBeRelocated, format);
		}

		/**
		 * Get linked section
		 * @param sectionIndex section index
		 * @param expectedTypes list of expectedTypes (may be omitted to accept any type)
		 * @return section or null if not found
		 */
		private ElfSectionHeader getLinkedSection(int sectionIndex, int... expectedTypes)
				throws NotFoundException {
			if (sectionIndex < 0 || sectionIndex >= sectionHeaders.length) {
				throw new NotFoundException("invalid linked section index " + sectionIndex);
			}
			ElfSectionHeader section = sectionHeaders[sectionIndex];
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

	private static Set<Integer> SECTION_HEADER_RELOCATION_TYPES =
		Set.of(ElfSectionHeaderConstants.SHT_REL, ElfSectionHeaderConstants.SHT_RELA,
			ElfSectionHeaderConstants.SHT_RELR, ElfSectionHeaderConstants.SHT_ANDROID_REL,
			ElfSectionHeaderConstants.SHT_ANDROID_RELA, ElfSectionHeaderConstants.SHT_ANDROID_RELR);

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
		// check section headers for possible custom relocation tables
		for (ElfSectionHeader section : sectionHeaders) {
			if (SECTION_HEADER_RELOCATION_TYPES.contains(section.getType())) {
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

		ArrayList<ElfRelocationTable> relocationTableList = new ArrayList<>();
		List<ElfRelocationTableBuilder> filteredRelocationTableBuilderList =
			relocationTableBuilderList.stream().filter(r -> r != null).distinct().toList();

		for (ElfRelocationTableBuilder builder : filteredRelocationTableBuilderList) {
			relocationTableList.add(builder.build());
		}

		relocationTables = new ElfRelocationTable[relocationTableList.size()];
		relocationTableList.toArray(relocationTables);
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

			if (fileSection instanceof ElfSectionHeader) {
				builder = new ElfRelocationTableBuilder((ElfSectionHeader) fileSection);
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

	private void parseDynamicLibraryNames() {

		if (dynamicTable == null) {
			dynamicLibraryNames = new String[0];
			return;
		}

		ElfDynamic[] needed = dynamicTable.getDynamics(ElfDynamicType.DT_NEEDED);
		dynamicLibraryNames = new String[needed.length];
		for (int i = 0; i < needed.length; i++) {
			if (dynamicStringTable != null) {
				try {
					dynamicLibraryNames[i] =
						dynamicStringTable.readString(needed[i].getValue());
				}
				catch (Exception e) {
					// ignore
				}
			}
			if (dynamicLibraryNames[i] == null) {
				dynamicLibraryNames[i] = "UNK_LIB_NAME_" + i;
			}
		}
	}

	private void parseDynamicTable() throws IOException {
		ElfFileSection dynamicFileSection = null;
		ElfSectionHeader[] dynamicSections = getSections(ElfSectionHeaderConstants.SHT_DYNAMIC);

		if (dynamicSections.length >= 1) {
			dynamicFileSection = dynamicSections[0];

			if (dynamicSections.length > 1) {
				errorConsumer.accept("Multiple ELF dynamic sections found");
			}
		}
		else {
			try {
				ElfProgramHeader[] dynamicHeaders = getProgramHeaders(ElfProgramHeaderConstants.PT_DYNAMIC);

				if (dynamicHeaders.length >= 1) {
					long vaddr = dynamicHeaders[0].getVirtualAddress();
					long size = dynamicHeaders[0].getMemorySize();
					long entrySize = is32Bit() ? 8 : 16;

					dynamicFileSection = findFileSection(vaddr, size, entrySize);

					if (dynamicHeaders.length > 1) {
						errorConsumer.accept("Multiple ELF dynamic table program headers found");
					}
				}
			}
			catch (NotFoundException e) {
				errorConsumer.accept("Couldn't find dynamic table: " + e.getMessage());
			}
		}

		if (dynamicFileSection != null) {
			dynamicTable = new ElfDynamicTable(this, dynamicFileSection);
		}
	}

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
				Arrays.asList(sectionHeaders).stream()
					.filter(e -> e.getType() == ElfSectionHeaderConstants.SHT_STRTAB)
					.map(e -> (ElfFileSection) e),
				dynamicStringFileSection != null ? Stream.of(dynamicStringFileSection) : Stream.empty()
			).distinct().toList();

		ArrayList<ElfStringTable> stringTableList = new ArrayList<>();
		for (ElfFileSection stringFileSection : stringFileSections) {
			ElfStringTable stringTable = new ElfStringTable(this, stringFileSection);
			stringTableList.add(stringTable);

			if (stringFileSection == dynamicStringFileSection) {
				dynamicStringTable = stringTable;
			}
		}

		stringTables = new ElfStringTable[stringTableList.size()];
		stringTableList.toArray(stringTables);
	}

	private int[] getExtendedSymbolSectionIndexTable(ElfSectionHeader symbolTableSectionHeader) {

		if (!hasExtendedSymbolSectionIndexTable) {
			return null;
		}

		// Find SHT_SYMTAB_SHNDX section linked to specified symbol table section
		ElfSectionHeader symbolSectionIndexHeader = null;
		for (ElfSectionHeader section : sectionHeaders) {
			if (section.getType() != ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX) {
				continue;
			}
			int linkIndex = section.getLink();
			if (linkIndex <= 0 || linkIndex >= sectionHeaders.length) {
				continue;
			}
			if (sectionHeaders[linkIndex] == symbolTableSectionHeader) {
				symbolSectionIndexHeader = section;
				break;
			}
		}
		if (symbolSectionIndexHeader == null) {
			return null;
		}

		// determine number of 32-bit index elements for int[]
		int count = (int) (symbolSectionIndexHeader.getFileSize() / 4);
		int[] indexTable = new int[count];

		long ptr = reader.getPointerIndex();
		try {
			reader.setPointerIndex(symbolSectionIndexHeader.getFileOffset());
			for (int i = 0; i < count; i++) {
				indexTable[i] = reader.readNextInt();
			}
		}
		catch (IOException e) {
			errorConsumer.accept("Failed to read symbol section index table at 0x" +
				Long.toHexString(symbolSectionIndexHeader.getFileOffset()) + ": " +
				symbolSectionIndexHeader.getNameAsString());
		}
		finally {
			reader.setPointerIndex(ptr); // restore reader position
		}

		return indexTable;
	}

	private void parseSymbolTables() throws IOException {
		ElfFileSection dynamicSymbolFileSection = null;

		try {
			if (dynamicTable != null) {
				long dynamicSymbolTableAddr = adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB));
				long dynamicSymbolTableEntrySize = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);

				ElfDynamicType dynamicHashType = getDynamicHashTableType();
				long dynamicHashTableAddr = adjustAddressForPrelink(dynamicTable.getDynamicValue(dynamicHashType));
				ElfProgramHeader hashTableLoadHeader = getProgramLoadHeaderContaining(dynamicHashTableAddr);
				if (hashTableLoadHeader == null) {
					throw new NotFoundException("Couldn't find program header containing dynamic hash table");
				}

				// determine symbol count from dynamic symbol hash table
				int symCount;
				long symbolHashTableOffset = hashTableLoadHeader.getOffset(dynamicHashTableAddr);
				if (dynamicHashType == ElfDynamicType.DT_GNU_HASH) {
					symCount = deriveGnuHashDynamicSymbolCount(symbolHashTableOffset);
				}
				else if (dynamicHashType == ElfDynamicType.DT_GNU_XHASH) {
					symCount = deriveGnuXHashDynamicSymbolCount(symbolHashTableOffset);
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
		for (ElfFileSection dynsym : getSections(ElfSectionHeaderConstants.SHT_DYNSYM)) {
			if (dynsym != null && dynsym.getVirtualAddress() == dynamicSymbolFileSection.getVirtualAddress() &&
					dynsym.getMemorySize() > dynamicSymbolFileSection.getMemorySize()) {
				dynamicSymbolFileSection = dynsym;
			}
		}

		List<ElfFileSection> symbolFileSections =
			Stream.concat(
				Arrays.asList(sectionHeaders).stream()
					.filter(e -> e.getType() == ElfSectionHeaderConstants.SHT_SYMTAB || e.getType() == ElfSectionHeaderConstants.SHT_DYNSYM)
					.map(e -> (ElfFileSection) e),
					dynamicSymbolFileSection != null ? Stream.of(dynamicSymbolFileSection) : Stream.empty()
			).distinct().toList();

		ArrayList<ElfSymbolTable> symbolTableList = new ArrayList<>();
		for (ElfFileSection symbolFileSection : symbolFileSections) {
			boolean isDynamicSymbolTable = symbolFileSection == dynamicSymbolFileSection;
			int[] symbolSectionIndexTable;
			ElfStringTable stringTable;

			if (symbolFileSection instanceof ElfSectionHeader) {
				ElfSectionHeader symbolTableSectionHeader = (ElfSectionHeader) symbolFileSection;
				stringTable = getStringTable(sectionHeaders[symbolTableSectionHeader.getLink()]);

				// get extended symbol section index table if present
				symbolSectionIndexTable = getExtendedSymbolSectionIndexTable(symbolTableSectionHeader);
			}
			else {
				stringTable = dynamicStringTable;

				// NOTE: When parsed from dynamic table and not found via section header parse
				// it is assumed that the extended symbol section table is not used.
				symbolSectionIndexTable = null;
			}

			ElfSymbolTable symbolTable = new ElfSymbolTable(this, symbolFileSection, stringTable, symbolSectionIndexTable, isDynamicSymbolTable);
			symbolTableList.add(symbolTable);

			if (isDynamicSymbolTable) {
				dynamicSymbolTable = symbolTable;
			}
		}

		symbolTables = new ElfSymbolTable[symbolTableList.size()];
		symbolTableList.toArray(symbolTables);
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
	private int deriveGnuHashDynamicSymbolCount(long gnuHashTableOffset) throws IOException {
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
	private int deriveGnuXHashDynamicSymbolCount(long gnuHashTableOffset) throws IOException {
		// Elf32_Word  ngnusyms;  // number of entries in chains (and xlat); dynsymcount=symndx+ngnusyms
		// Elf32_Word  nbuckets;  // number of hash table buckets
		// Elf32_Word  symndx;  // number of initial .dynsym entires skipped in chains[] (and xlat[])
		int ngnusyms = reader.readInt(gnuHashTableOffset);
		int symndx = reader.readInt(gnuHashTableOffset + 8);

		return symndx + ngnusyms;
	}

	/**
	 * Perform offset region check against byte provider.
	 * This is done against the byte provider since the
	 * reader is unbounded.
	 * @param offset starting offset
	 * @param length length of range
	 * @return true if provider contains specified byte offset range
	 */
	private boolean providerContainsRegion(long offset, int length) {
		try {
			return offset >= 0 && (offset + length) <= provider.length();
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Some elfs can get pre-linked to an OS. At the very end a "PRE " string is
	 * appended with the image base load address set.
	 */
	protected void parsePreLinkImageBase() throws IOException {
		long fileLength = reader.getByteProvider().length();

		int preLinkImageBaseInt = reader.readInt(fileLength - 8);
		String preLinkMagicString = reader.readAsciiString(fileLength - 4, 4).trim();

		if (preLinkMagicString.equals("PRE")) {
			preLinkImageBase = Integer.toUnsignedLong(preLinkImageBaseInt);
		}
	}

	protected void parseSectionHeaders()
			throws IOException {
		if (reader == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (parsedSectionHeaders) {
			return;
		}

		parsedSectionHeaders = true;
		boolean missing = false;
		sectionHeaders = new ElfSectionHeader[e_shnum];
		for (int i = 0; i < e_shnum; ++i) {
			long index = e_shoff + (i * e_shentsize);
			if (!missing && !providerContainsRegion(index, e_shentsize)) {
				int unreadCnt = e_shnum - i;
				errorConsumer.accept(
					unreadCnt + " of " + e_shnum +
						" section headers are truncated/missing from file");
				missing = true;
			}
			reader.setPointerIndex(index);
			sectionHeaders[i] = new ElfSectionHeader(reader, this);
			if (sectionHeaders[i].getType() == ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX) {
				hasExtendedSymbolSectionIndexTable = true;
			}
		}

		if (sectionHeaders.length != 0) {
			section0 = sectionHeaders[0];
		}

		//note: we cannot retrieve all the names
		//until after we have read all the section headers.
		//this is because one of the section headers 
		//is a string table that contains the names of the sections.
		for (int i = 0; i < e_shnum; ++i) {
			sectionHeaders[i].updateName();
		}
	}

	private void parseProgramHeaders()
			throws IOException {
		boolean missing = false;
		programHeaders = new ElfProgramHeader[e_phnum];
		for (int i = 0; i < e_phnum; ++i) {
			long index = e_phoff + (i * e_phentsize);
			if (!missing && !providerContainsRegion(index, e_phentsize)) {
				int unreadCnt = e_phnum - i;
				errorConsumer.accept(
					unreadCnt + " of " + e_phnum +
						" program headers are truncated/missing from file");
				missing = true;
			}
			reader.setPointerIndex(index);
			programHeaders[i] = new ElfProgramHeader(reader, this);
		}

		// TODO: Find sample file which requires this hack to verify its necessity
		// HACK: 07/01/2013 - Added hack for malformed ELF file with only program header sections
		long size = 0;
		for (ElfProgramHeader pheader : programHeaders) {
			size += pheader.getFileSize();
		}
		if (size == reader.length()) {
			// adjust program section file offset to be based on relative read offset
			long relOffset = 0;
			for (ElfProgramHeader pheader : programHeaders) {
				pheader.setOffset(relOffset);
				relOffset += pheader.getFileSize();
			}
		}
	}

	/**
	 * Returns true if this ELF was created for a big endian processor.
	 * @return true if this ELF was created for a big endian processor
	 */
	public boolean isBigEndian() {
		return e_ident_data == ElfConstants.ELF_DATA_BE;
	}

	/**
	 * Returns true if this ELF was created for a little endian processor.
	 * @return true if this ELF was created for a little endian processor
	 */
	public boolean isLittleEndian() {
		return e_ident_data == ElfConstants.ELF_DATA_LE;
	}

	/**
	 * Returns true if this ELF was created for a 32-bit processor.
	 * @return true if this ELF was created for a 32-bit processor
	 */
	public boolean is32Bit() {
		return e_ident_class == ElfConstants.ELF_CLASS_32;
	}

	/**
	 * Returns true if this ELF was created for a 64-bit processor.
	 * @return true if this ELF was created for a 64-bit processor
	 */
	public boolean is64Bit() {
		return e_ident_class == ElfConstants.ELF_CLASS_64;
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
	 * Inspect the Elf image and determine the default image base prior 
	 * to any parse method being invoked (i.e., only the main Elf
	 * header structure has been parsed during initialization.
	 * The image base is the virtual address of the PT_LOAD program header
	 * with the smallest address or 0 if no program headers exist.  By default,
	 * the image base address should be treated as a addressable unit offset.
	 * @return preferred image base 
	 */
	public long findImageBase() {

		// FIXME! This needs to be consistent with the getImageBase() method
		// which currently considers prelink. 

		long minBase = -1;

		int n = Math.min(e_phnum, MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
		for (int i = 0; i < n; ++i) {
			long index = e_phoff + (i * e_phentsize);
			if (!providerContainsRegion(index, e_phentsize)) {
				break;
			}
			reader.setPointerIndex(index);
			try {
				int headerType = reader.peekNextInt();
				if (headerType == ElfProgramHeaderConstants.PT_LOAD) {
					ElfProgramHeader header = new ElfProgramHeader(reader, this);
					minBase = getMinBase(header.getVirtualAddress(), minBase);
				}
			}
			catch (IOException e) {
				// skip
			}
		}
		return minBase == -1 ? 0 : minBase;
	}

	private Long elfImageBase;

	/**
	 * Returns the image base of this ELF. 
	 * The image base is the virtual address of the first PT_LOAD
	 * program header or 0 if no program headers. By default,
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
			int n = Math.min(programHeaders.length, MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
			long minBase = -1;
			for (int i = 0; i < n; i++) {
				ElfProgramHeader header = programHeaders[i];
				if (programHeaders[i].getType() == ElfProgramHeaderConstants.PT_LOAD) {
					minBase = getMinBase(header.getVirtualAddress(), minBase);
				}
			}
			elfImageBase = (minBase == -1 ? 0 : minBase);
		}
		return elfImageBase;
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

	public boolean isSectionLoaded(ElfSectionHeader section) {
		if (section.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			return false;
		}
		long sectionStart = section.getVirtualAddress();
		if (sectionStart == 0) {
			return false;
		}
		long sectionEnd = section.getFileSize() - 1 + sectionStart;
		for (ElfProgramHeader segment : programHeaders) {
			if (segment.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				continue;
			}
			long segmentStart = segment.getVirtualAddress();
			long segmentEnd = segment.getMemorySize() - 1 + segmentStart;
			if (segmentStart <= sectionStart && segmentEnd >= sectionEnd) {
				return true;
			}
		}
		return false;
	}

	private void determineHeaderEndianess(byte ident_data) throws ElfException {
		hasLittleEndianHeaders = true;

		if (ident_data == ElfConstants.ELF_DATA_BE) {
			hasLittleEndianHeaders = false;
		}
		else if (ident_data != ElfConstants.ELF_DATA_LE) {
			errorConsumer.accept("Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x" +
				Integer.toHexString(ident_data) + ")");
		}
	}

	private void determineHeaderEndianess(byte[] bytes) throws ElfException {
		determineHeaderEndianess(bytes[ElfConstants.EI_DATA]);

		if (!hasLittleEndianHeaders && bytes[ElfConstants.EI_NIDENT] != 0) {
			// Header endianess sanity check
			// Some toolchains always use little endian Elf Headers

			// TODO: unsure if forced endianess applies to relocation data

			// Check first byte of version (allow switch if equal 1)
			if (bytes[ElfConstants.EI_NIDENT + 4] == 1) {
				hasLittleEndianHeaders = true;
			}
		}
	}

	/**
	 * This member holds the ELF header's size in bytes.
	 * @return the ELF header's size in bytes
	 */
	public short e_ehsize() {
		return e_ehsize;
	}

	/**
	 * This member gives the virtual address to which the system first transfers control, thus
	 * starting the process. If the file has no associated entry point, this member holds zero.
	 * @return the virtual address to which the system first transfers control
	 */
	public long e_entry() {
		// guard against adjustment of 0
		// TODO: this might need to be re-thought.  
		if (e_entry == 0) {
			return 0;
		}
		return adjustAddressForPrelink(e_entry);
	}

	/**
	 * This member holds processor-specific flags associated with the file. Flag names take
	 * the form EF_machine_flag.
	 * @return the processor-specific flags associated with the file
	 * @see ElfConstants for flag definitions
	 */
	public int e_flags() {
		return e_flags;
	}

	/**
	 * This member's value specifies the required architecture for an individual file.
	 * @return the required architecture for an individual file
	 * @see ElfConstants for machine definitions
	 */
	public short e_machine() {
		return e_machine;
	}

	/**
	 * This member identifies the target operating system and ABI.
	 * @return the target operating system and ABI
	 */
	public byte e_ident_osabi() {
		return e_ident_osabi;
	}

	/**
	 * This member identifies the target ABI version.
	 * @return the target ABI version
	 */
	public byte e_ident_abiversion() {
		return e_ident_abiversion;
	}

	/**
	 * This member holds the size in bytes of one entry in the file's program header table;
	 * all entries are the same size.
	 * @return the size in bytes of one program header table entry 
	 */
	public short e_phentsize() {
		return e_phentsize;
	}

	/**
	 * This member holds the number of entries in the program header table. Thus the product
	 * of e_phentsize and unsigned e_phnum gives the table's size in bytes. If original 
	 * e_phnum equals PNXNUM (0xffff) an attempt will be made to obtained the extended size
	 * from section[0].sh_info field.  If a file has no program header table, e_phnum holds 
	 * the value zero.
	 * @return the number of entries in the program header table
	 */
	public int getProgramHeaderCount() {
		return e_phnum;
	}

	/**
	 * This member holds the program header table's file offset in bytes. If the file has no
	 * program header table, this member holds zero.
	 * @return the program header table's file offset in bytes
	 */
	public long e_phoff() {
		return e_phoff;
	}

	/**
	 * This member holds the section header's size in bytes. A section header is one entry in
	 * the section header table; all entries are the same size.
	 * @return the section header's size in bytes
	 */
	public short e_shentsize() {
		return e_shentsize;
	}

	/**
	 * This member holds the number of entries in the section header table. Thus the product
	 * of e_shentsize and unsigned e_shnum gives the section header table's size in bytes. If a file
	 * has no section header table, e_shnum holds the value zero.
	 * @return the number of entries in the section header table
	 */
	public int getSectionHeaderCount() {
		return e_shnum;
	}

	/**
	 * This member holds the section header table's file offset in bytes. If the file has no section
	 * header table, this member holds zero.
	 * @return the section header table's file offset in bytes
	 */
	public long e_shoff() {
		return e_shoff;
	}

	/**
	 * This member holds the section header table index of the entry associated with the section
	 * name string table. If the file has no section name string table, this member holds
	 * the value SHN_UNDEF.
	 * @return the section header table index of the entry associated with the section name string table
	 */
	public int e_shstrndx() {
		return e_shstrndx;
	}

	/**
	 * This member identifies the object file type; executable, shared object, etc.
	 * @return the object file type
	 */
	public short e_type() {
		return e_type;
	}

	/**
	 * Returns true if this is a relocatable file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_REL
	 * @return true if this is a relocatable file
	 */
	public boolean isRelocatable() {
		return e_type == ElfConstants.ET_REL;
	}

	/**
	 * Returns true if this is a shared object file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_DYN
	 * @return true if this is a shared object file
	 */
	public boolean isSharedObject() {
		return e_type == ElfConstants.ET_DYN;
	}

	/**
	 * Returns true if this is an executable file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_EXEC
	 * @return true if this is a executable file
	 */
	public boolean isExecutable() {
		return e_type == ElfConstants.ET_EXEC;
	}

	/**
	 * This member identifies the object file version,
	 * where "EV_NONE == Invalid Version" and "EV_CURRENT == Current Version"
	 * The value 1 signifies the original file format; extensions will 
	 * create new versions with higher numbers. 
	 * The value of EV_CURRENT, though given as 1 above, will change as
	 * necessary to reflect the current version number.
	 * @return the object file version
	 */
	public int e_version() {
		return e_version;
	}

	/**
	 * Returns the section headers as defined in this ELF file.
	 * @return the section headers as defined in this ELF file
	 */
	public ElfSectionHeader[] getSections() {
		return sectionHeaders;
	}

	/**
	 * Returns the section headers with the specified type.
	 * The array could be zero-length, but will not be null.
	 * @param type section type
	 * @return the section headers with the specified type
	 * @see ElfSectionHeader
	 */
	public ElfSectionHeader[] getSections(int type) {
		ArrayList<ElfSectionHeader> list = new ArrayList<>();
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.getType() == type) {
				list.add(sectionHeader);
			}
		}
		ElfSectionHeader[] sections = new ElfSectionHeader[list.size()];
		list.toArray(sections);
		return sections;
	}

	/**
	 * Returns the section header with the specified name, or null
	 * if no section exists with that name.
	 * @param name the name of the requested section
	 * @return the section header with the specified name
	 */
	public ElfSectionHeader getSection(String name) {
		List<ElfSectionHeader> list = new ArrayList<>();
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (name != null && name.equals(sectionHeader.getNameAsString())) {
				list.add(sectionHeader);
			}
		}
		if (list.size() == 0) {
			return null;
		}
		if (list.size() > 1) {
			throw new RuntimeException(">1 section with name of " + name);
		}
		return list.get(0);
	}

	/**
	 * Returns the section header at the specified address,
	 * or null if no section exists at that address.
	 * @param address the address of the requested section
	 * @return the section header with the specified address
	 */
	public ElfSectionHeader getSectionAt(long address) {
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (!sectionHeader.isAlloc()) {
				continue;
			}
			if (sectionHeader.getVirtualAddress() == address) {
				return sectionHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the section header that loads/contains the specified address,
	 * or null if no section contains the address.
	 * @param address the address of the requested section
	 * @return the section header that contains the address
	 */
	public ElfSectionHeader getSectionLoadHeaderContaining(long address) {
// FIXME: verify 
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (!sectionHeader.isAlloc()) {
				continue;
			}
			long start = sectionHeader.getVirtualAddress();
			long end = start + sectionHeader.getFileSize();
			if (start <= address && address <= end) {
				return sectionHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the section header which fully contains the specified file offset range.
	 * @param fileOffset file offset
	 * @param fileRangeLength length of file range in bytes
	 * @return section or null if not found
	 */
	public ElfSectionHeader getSectionHeaderContainingFileRange(long fileOffset,
			long fileRangeLength) {
		long maxOffset = fileOffset + fileRangeLength - 1;
		for (ElfSectionHeader section : sectionHeaders) {
			if (section.getType() == ElfSectionHeaderConstants.SHT_NULL ||
				section.isInvalidOffset()) {
				continue;
			}
			long size = section.getFileSize();
			if (size == 0) {
				continue;
			}
			long start = section.getFileOffset();
			long end = start + size - 1;
			if (fileOffset >= start && maxOffset <= end) {
				return section;
			}
		}
		return null;
	}

	/**
	 * Returns the index of the specified section.
	 * The index is the order in which the section was
	 * defined in the section header table.
	 * @param section the section header
	 * @return the index of the specified section header
	 */
	public int getSectionIndex(ElfSectionHeader section) {
		for (int i = 0; i < sectionHeaders.length; i++) {
			if (sectionHeaders[i] == section) {
				return i;
			}
		}
		throw new RuntimeException("Section not located.");
	}

	/**
	 * Returns the program headers as defined in this ELF file.
	 * @return the program headers as defined in this ELF file
	 */
	public ElfProgramHeader[] getProgramHeaders() {
		return programHeaders;
	}

	/**
	 * Returns the program headers with the specified type.
	 * The array could be zero-length, but will not be null.
	 * @param type program header type
	 * @return the program headers with the specified type
	 * @see ElfProgramHeader
	 */
	public ElfProgramHeader[] getProgramHeaders(int type) {
		ArrayList<ElfProgramHeader> list = new ArrayList<>();
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader.getType() == type) {
				list.add(programHeader);
			}
		}
		ElfProgramHeader[] arr = new ElfProgramHeader[list.size()];
		list.toArray(arr);
		return arr;
	}

	/**
	 * Returns the dynamic table defined by program header of type PT_DYNAMIC or the .dynamic program section.
	 * Or, null if one does not exist.
	 * @return the dynamic table
	 */
	public ElfDynamicTable getDynamicTable() {
		return dynamicTable;
	}

	/**
	 * Returns the program header with type of PT_PHDR.
	 * Or, null if one does not exist.
	 * @return the program header with type of PT_PHDR
	 */
	public ElfProgramHeader getProgramHeaderProgramHeader() {
		ElfProgramHeader[] pharr = getProgramHeaders(ElfProgramHeaderConstants.PT_PHDR);
		if (pharr.length == 0 || pharr.length > 1) {
			return null;
			//throw new RuntimeException("Unable to locate PT_PHDR program header");
		}
		return pharr[0];
	}

	/**
	 * Returns the program header at the specified address,
	 * or null if no program header exists at that address.
	 * @param virtualAddr the address of the requested program header
	 * @return the program header with the specified address
	 */
	public ElfProgramHeader getProgramHeaderAt(long virtualAddr) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader.getType() == ElfProgramHeaderConstants.PT_LOAD &&
				programHeader.getVirtualAddress() == virtualAddr) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the PT_LOAD program header which loads a range containing 
	 * the specified address, or null if not found.
	 * @param virtualAddr the address of the requested program header
	 * @return the program header with the specified address
	 */
	public ElfProgramHeader getProgramLoadHeaderContaining(long virtualAddr) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				continue;
			}
			long start = programHeader.getVirtualAddress();
			long end = programHeader.getAdjustedMemorySize() - 1 + start;
			if (virtualAddr >= start && virtualAddr <= end) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the PT_LOAD program header which loads a range containing 
	 * the specified file offset, or null if not found.
	 * @param offset the file offset to be loaded
	 * @return the program header with the specified file offset
	 */
	public ElfProgramHeader getProgramLoadHeaderContainingFileOffset(long offset) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader == null ||
				programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD ||
				programHeader.isInvalidOffset()) {
				continue;
			}
			long start = programHeader.getFileOffset();
			long end = start + (programHeader.getFileSize() - 1);
			if (offset >= start && offset <= end) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns array of dynamic library names defined by DT_NEEDED
	 * @return array of dynamic library names
	 */
	public String[] getDynamicLibraryNames() {
		return dynamicLibraryNames;
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
	public ElfStringTable[] getStringTables() {
		return stringTables;
	}

	/**
	 * Returns the string table associated to the specified section header.
	 * Or, null if one does not exist.
	 * @param section section whose associated string table is requested
	 * @return the string table associated to the specified section header
	 */
	public ElfStringTable getStringTable(ElfSectionHeader section) {
		for (ElfStringTable stringTable : stringTables) {
			if (stringTable.getFileSection().getFileOffset() == section.getFileOffset()) {
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
	public ElfSymbolTable[] getSymbolTables() {
		return symbolTables;
	}

	/**
	 * Returns the symbol table associated to the specified section header.
	 * Or, null if one does not exist.
	 * @param symbolTableSection symbol table section header
	 * @return the symbol table associated to the specified section header
	 */
	public ElfSymbolTable getSymbolTable(ElfSectionHeader symbolTableSection) {
		if (symbolTableSection == null) {
			return null;
		}
		for (ElfSymbolTable symbolTable : symbolTables) {
			if (symbolTable.getFileSection().getFileOffset() == symbolTableSection.getFileOffset()) {
				return symbolTable;
			}
		}
		return null;
	}

	/**
	 * Returns the relocation tables as defined in this ELF file.
	 * @return the relocation tables as defined in this ELF file
	 */
	public ElfRelocationTable[] getRelocationTables() {
		return relocationTables;
	}

	/**
	 * Returns the relocation table associated to the specified section header,
	 * or null if one does not exist.
	 * @param relocSection section header corresponding to relocation table
	 * @return the relocation table associated to the specified section header
	 */
	public ElfRelocationTable getRelocationTable(ElfSectionHeader relocSection) {
		return getRelocationTableAtOffset(relocSection.getFileOffset());
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
	 * Returns a string name of the processor specified in this ELF header.
	 * For example, if "e_machine==EM_386", then it returns "80386".
	 * @return a string name of the processor specified in this ELF header
	 */
	public String getMachineName() {
		return Short.toString(e_machine);
	}

	/**
	 * Returns a string representation of the numeric flags field.
	 * @return elf flags field value
	 */
	public String getFlags() {
		return Integer.toString(e_flags);
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		if (headerStructure != null) {
			return headerStructure;
		}
		String name = is32Bit() ? "Elf32_Ehdr" : "Elf64_Ehdr";
		headerStructure = new StructureDataType(new CategoryPath("/ELF"), name, 0);
		headerStructure.add(BYTE, "e_ident_magic_num", null);
		headerStructure.add(STRING, e_ident_magic_str.length(), "e_ident_magic_str", null);
		headerStructure.add(BYTE, "e_ident_class", null);
		headerStructure.add(BYTE, "e_ident_data", null);
		headerStructure.add(BYTE, "e_ident_version", null);
		headerStructure.add(BYTE, "e_ident_osabi", null);
		headerStructure.add(BYTE, "e_ident_abiversion", null);
		headerStructure.add(new ArrayDataType(BYTE, PAD_LENGTH, 1), "e_ident_pad", null);
		headerStructure.add(WORD, "e_type", null);
		headerStructure.add(WORD, "e_machine", null);
		headerStructure.add(DWORD, "e_version", null);

		if (is32Bit()) {
			headerStructure.add(DWORD, "e_entry", null);
			headerStructure.add(DWORD, "e_phoff", null);
			headerStructure.add(DWORD, "e_shoff", null);
		}
		else {
			headerStructure.add(QWORD, "e_entry", null);
			headerStructure.add(QWORD, "e_phoff", null);
			headerStructure.add(QWORD, "e_shoff", null);
		}

		headerStructure.add(DWORD, "e_flags", null);
		headerStructure.add(WORD, "e_ehsize", null);
		headerStructure.add(WORD, "e_phentsize", null);
		headerStructure.add(WORD, "e_phnum", null);
		headerStructure.add(WORD, "e_shentsize", null);
		headerStructure.add(WORD, "e_shnum", null);
		headerStructure.add(WORD, "e_shstrndx", null);
		return headerStructure;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_entry element
	 * @return e_entry component ordinal 
	 */
	public int getEntryComponentOrdinal() {
		return 11;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_phoff element
	 * @return e_phoff component ordinal 
	 */
	public int getPhoffComponentOrdinal() {
		return 12;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_shoff element
	 * @return e_shoff component ordinal 
	 */
	public int getShoffComponentOrdinal() {
		return 13;
	}

	private void addSection(ElfSectionHeader newSection) {
		++e_shnum;

		ElfSectionHeader[] tmp = new ElfSectionHeader[e_shnum];
		System.arraycopy(sectionHeaders, 0, tmp, 0, sectionHeaders.length);
		sectionHeaders = tmp;

		sectionHeaders[e_shnum - 1] = newSection;

		if (e_shnum != sectionHeaders.length) {
			throw new IllegalStateException();
		}
	}

	/**
	 * Adds a new section using the specified memory block.
	 * The memory block is used to setting the address and size.
	 * As well as, setting the data.
	 * @param block the memory block
	 * @param sh_name the byte index into the string table where the name begins
	 * @return the newly created section
	 * @throws MemoryAccessException if any of the requested memory block bytes are uninitialized.
	 */
	public ElfSectionHeader addSection(MemoryBlock block, int sh_name)
			throws MemoryAccessException {
		ElfSectionHeader newSection = new ElfSectionHeader(this, block, sh_name, getImageBase());
		addSection(newSection);
		return newSection;
	}

	/**
	 * Adds a new section the specifed name and name index.
	 * The type of the section will be SHT_PROGBITS.
	 * @param name the actual name of the new section
	 * @param sh_name the byte index into the string table where the name begins
	 * @return the newly created section
	 */
	public ElfSectionHeader addSection(String name, int sh_name) {
		return addSection(name, sh_name, ElfSectionHeaderConstants.SHT_PROGBITS);
	}

	/**
	 * Adds a new section the specifed name and name index.
	 * The type of the section will be SHT_PROGBITS.
	 * @param name the actual name of the new section
	 * @param sh_name the byte index into the string table where the name begins
	 * @param type the type of the new section
	 * @return the newly created section
	 */
	public ElfSectionHeader addSection(String name, int sh_name, int type) {
		ElfSectionHeader newSection = new ElfSectionHeader(this, name, sh_name, type);
		addSection(newSection);
		return newSection;
	}

	/**
	 * Appends the new program header to the end of the existing
	 * program header table.
	 * @param ph the new program header
	 */
	public void addProgramHeader(ElfProgramHeader ph) {
		ElfProgramHeader[] tmp = new ElfProgramHeader[programHeaders.length + 1];

		int pos = tmp.length - 1;

		boolean firstLoad = true;
		int firstLoadPos = -1;

		/*PT_LOAD segments must be inserted in sorted order*/
		if (ph.getType() == ElfProgramHeaderConstants.PT_LOAD) {
			for (int i = 0; i < programHeaders.length - 1; ++i) {
				if (programHeaders[i].getType() == ElfProgramHeaderConstants.PT_LOAD) {
					if (firstLoad) {
						firstLoad = false;
						firstLoadPos = i;
					}
					pos = i;
				}
			}
			++pos;
		}

		System.arraycopy(programHeaders, 0, tmp, 0, pos);
		tmp[pos] = ph;
		System.arraycopy(programHeaders, pos, tmp, pos + 1, programHeaders.length - pos);

		if (ph.getType() == ElfProgramHeaderConstants.PT_LOAD) {
			Arrays.sort(tmp, firstLoadPos, pos + 1);
		}

		programHeaders = tmp;

		e_phnum = programHeaders.length;

	}

	/**
	 * @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
	 */
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.seek(0);
		raf.writeByte(e_ident_magic_num);
		raf.write(e_ident_magic_str.getBytes());
		raf.writeByte(e_ident_class);
		raf.writeByte(e_ident_data);
		raf.writeByte(e_ident_version);
		raf.writeByte(e_ident_osabi);
		raf.writeByte(e_ident_abiversion);
		raf.write(e_ident_pad);
		raf.write(dc.getBytes(e_type));
		raf.write(dc.getBytes(e_machine));
		raf.write(dc.getBytes(e_version));

		if (is32Bit()) {
			raf.write(dc.getBytes((int) e_entry));
			raf.write(dc.getBytes((int) e_phoff));
			raf.write(dc.getBytes((int) e_shoff));
		}
		else if (is64Bit()) {
			raf.write(dc.getBytes(e_entry));
			raf.write(dc.getBytes(e_phoff));
			raf.write(dc.getBytes(e_shoff));
		}

		raf.write(dc.getBytes(e_flags));
		raf.write(dc.getBytes(e_ehsize));
		raf.write(dc.getBytes(e_phentsize));
		if (e_phnum >= Short.toUnsignedInt(ElfConstants.PN_XNUM)) {
			throw new IOException(
				"Unsupported program header count serialization: " + e_phnum);
		}
		raf.write(dc.getBytes((short) e_phnum));
		raf.write(dc.getBytes(e_shentsize));
		if (e_shnum >= Short.toUnsignedInt(ElfSectionHeaderConstants.SHN_LORESERVE)) {
			throw new IOException(
				"Unsupported section header count serialization: " + e_shnum);
		}
		raf.write(dc.getBytes((short) e_shnum));
		raf.write(dc.getBytes((short) e_shstrndx));
	}

	/**
	 * Sets the section header offset.
	 * @param offset the new section header offset
	 */
	public void setSectionHeaderOffset(long offset) {
		this.e_shoff = offset;
	}

	/**
	 * Sets the program header offset.
	 * @param offset the new program header offset
	 */
	public void setProgramHeaderOffset(long offset) {
		this.e_phoff = offset;
	}

}
