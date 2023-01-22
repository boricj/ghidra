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
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.UnlimitedByteProviderWrapper;
import ghidra.app.util.bin.format.Writeable;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.DataConverter;
import ghidra.util.StringUtilities;

/**
 * A class to represent the Elf32_Shdr data structure.
 * <br>
 * <pre>
 * typedef  int32_t  Elf32_Sword;
 * typedef uint32_t  Elf32_Word;
 * typedef uint32_t  Elf32_Addr;
 * 
 * typedef struct {
 *     Elf32_Word    sh_name;       //Section name (string tbl index)
 *     Elf32_Word    sh_type;       //Section type
 *     Elf32_Word    sh_flags;      //Section flags
 *     Elf32_Addr    sh_addr;       //Section virtual addr at execution
 *     Elf32_Off     sh_offset;     //Section file offset
 *     Elf32_Word    sh_size;       //Section size in bytes
 *     Elf32_Word    sh_link;       //Link to another section
 *     Elf32_Word    sh_info;       //Additional section information
 *     Elf32_Word    sh_addralign;  //Section alignment
 *     Elf32_Word    sh_entsize;    //Entry size if section holds table *
 * } Elf32_Shdr;
 * 
 * typedef  uint32_t  Elf64_Word;
 * typedef  uint64_t  Elf64_Xword;
 * typedef  uint64_t  Elf64_Addr;
 * typedef  uint64_t  Elf64_Off;
 * 
 * typedef struct {
 *     Elf64_Word    sh_name;       //Section name (string tbl index)
 *     Elf64_Word    sh_type;       //Section type
 *     Elf64_Xword   sh_flags;      //Section flags
 *     Elf64_Addr    sh_addr;       //Section virtual addr at execution
 *     Elf64_Off     sh_offset;     //Section file offset
 *     Elf64_Xword   sh_size;       //Section size in bytes
 *     Elf64_Word    sh_link;       //Link to another section
 *     Elf64_Word    sh_info;       //Additional section information
 *     Elf64_Xword   sh_addralign;  //Section alignment
 *     Elf64_Xword   sh_entsize;    //Entry size if section holds table *
 * } Elf64_Shdr;
 * </pre>
 */

public class ElfSection implements ElfFileSection, StructConverter, Writeable {

	public int sh_name;
	int sh_type;
	long sh_flags;
	long sh_addr;
	long sh_offset;
	long sh_size;
	int sh_link;
	int sh_info;
	long sh_addralign;
	long sh_entsize;

	private BinaryReader reader;

	private ElfFile elf;
	private String name;

	public ElfSection(ElfFile elf, BinaryReader reader)
			throws IOException {
		this.elf = elf;

		sh_name = reader.readNextInt();
		sh_type = reader.readNextInt();

		if (elf.is32Bit()) {
			sh_flags = Integer.toUnsignedLong(reader.readNextInt());
			sh_addr = Integer.toUnsignedLong(reader.readNextInt());
			sh_offset = Integer.toUnsignedLong(reader.readNextInt());
			sh_size = Integer.toUnsignedLong(reader.readNextInt());
		}
		else if (elf.is64Bit()) {
			sh_flags = reader.readNextLong();
			sh_addr = reader.readNextLong();
			sh_offset = reader.readNextLong();
			sh_size = reader.readNextLong();
		}

		sh_link = reader.readNextInt();
		sh_info = reader.readNextInt();

		if (elf.is32Bit()) {
			sh_addralign = Integer.toUnsignedLong(reader.readNextInt());
			sh_entsize = Integer.toUnsignedLong(reader.readNextInt());
		}
		else if (elf.is64Bit()) {
			sh_addralign = reader.readNextLong();
			sh_entsize = reader.readNextLong();
		}
		//checkSize();

		ByteProvider provider;
		if (sh_type == ElfSectionConstants.SHT_NULL) {
			provider = ByteProvider.EMPTY_BYTEPROVIDER;
		}
		else if (sh_type == ElfSectionConstants.SHT_NOBITS || isInvalidOffset()) {
			provider = new ByteArrayProvider(new byte[(int) sh_size]);
		}
		else {
			provider = new UnlimitedByteProviderWrapper(reader.getByteProvider(), sh_offset, sh_size);
		}
		this.reader = new BinaryReader(provider, reader.isLittleEndian());
	}

	public ElfSection(ElfFile elf, String name, int type, long flags, int link, int info,
			long addressAlignment, long entrySize, ByteProvider data) {
		this.sh_type = type;
		this.sh_flags = flags;
		this.sh_link = link;
		this.sh_info = info;
		this.sh_addralign = addressAlignment;
		this.sh_entsize = entrySize;

		this.elf = elf;
		this.name = name;
		this.reader = new BinaryReader(data, elf.isLittleEndian());
	}

	/**
	 * @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
	 */
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.write(dc.getBytes(sh_name));
		raf.write(dc.getBytes(sh_type));

		if (elf.is32Bit()) {
			raf.write(dc.getBytes((int) sh_flags));
			raf.write(dc.getBytes((int) sh_addr));
			raf.write(dc.getBytes((int) sh_offset));
			raf.write(dc.getBytes((int) sh_size));
		}
		else if (elf.is64Bit()) {
			raf.write(dc.getBytes(sh_flags));
			raf.write(dc.getBytes(sh_addr));
			raf.write(dc.getBytes(sh_offset));
			raf.write(dc.getBytes(sh_size));
		}

		raf.write(dc.getBytes(sh_link));
		raf.write(dc.getBytes(sh_info));

		if (elf.is32Bit()) {
			raf.write(dc.getBytes((int) sh_addralign));
			raf.write(dc.getBytes((int) sh_entsize));
		}
		else if (elf.is64Bit()) {
			raf.write(dc.getBytes(sh_addralign));
			raf.write(dc.getBytes(sh_entsize));
		}
	}

	/**
	 * If the section will appear in the memory image of a process, this 
	 * member gives the address at which the section's first byte 
	 * should reside. Otherwise, the member contains 0.
	 * @return the address of the section in memory
	 */
	public long getVirtualAddress() {
		return elf.adjustAddressForPrelink(sh_addr);
	}

	/**
	 * Some sections have address alignment constraints. For example, if a section holds a
	 * doubleword, the system must ensure doubleword alignment for the entire section.
	 * That is, the value of sh_addr must be congruent to 0, modulo the value of
	 * sh_addralign. Currently, only 0 and positive integral powers of two are allowed.
	 * Values 0 and 1 mean the section has no alignment constraints.
	 * @return the section address alignment constraints
	 */
	public long getAddressAlignment() {
		return sh_addralign;
	}

	/**
	 * Some sections hold a table of fixed-size entries, such as a symbol table. For such a section,
	 * this member gives the size in bytes of each entry. The member contains 0 if the
	 * section does not hold a table of fixed-size entries.
	 * @return the section entry size
	 */
	@Override
	public long getEntrySize() {
		return sh_entsize;
	}

	/**
	 * Sections support 1-bit flags that describe miscellaneous attributes. Flag definitions
	 * appear aove.
	 * @return the section flags
	 */
	public long getFlags() {
		return sh_flags;
	}

	/**
	 * Returns true if this section is writable.
	 * @return true if this section is writable.
	 */
	public boolean isWritable() {
		return elf.getLoadAdapter().isSectionWritable(this);
	}

	/**
	 * Returns true if this section is executable.
	 * @return true if this section is executable.
	 */
	public boolean isExecutable() {
		return elf.getLoadAdapter().isSectionExecutable(this);
	}

	/**
	 * Returns true if this section is allocated (e.g., SHF_ALLOC is set)
	 * @return true if this section is allocated.
	 */
	public boolean isAlloc() {
		return elf.getLoadAdapter().isSectionAllocated(this);
	}

	/**
	 * This member holds extra information, whose interpretation 
	 * depends on the section type.
	 *  
	 * If sh_type is SHT_REL or SHT_RELA, then sh_info holds 
	 * the section index of the
	 * section to which the relocation applies.
	 * 
	 * If sh_type is SHT_SYMTAB or SHT_DYNSYM, then sh_info
	 * holds one greater than the symbol table index of the last
	 * local symbol (binding STB_LOCAL).
	 * 
	 * @return the section info
	 */
	public int getInfo() {
		return sh_info;
	}

	/**
	 * This member holds extra information, whose interpretation 
	 * depends on the section type.
	 * 
	 * If sh_type is SHT_SYMTAB, SHT_DYNSYM, or SHT_DYNAMIC, 
	 * then sh_link holds the section table index of
	 * its associated string table.
	 * 
	 * If sh_type is SHT_REL, SHT_RELA, or SHT_HASH
	 * sh_link holds the section index of the 
	 * associated symbol table.
	 * 
	 * @return the section link
	 */
	public int getLink() {
		return sh_link;
	}

	/**
	 * An index into the section string table section, 
	 * giving the location of a null-terminated string which is the name of this section.
	 * @return the index of the section name
	 */
	public int getName() {
		return sh_name;
	}

	void updateName() {
		List<ElfSection> sections = elf.getSections();
		int e_shstrndx = elf.getSectionNameStringTableIndex();
		name = null;

		if (sh_name >= 0 && e_shstrndx > 0 && e_shstrndx < sections.size()) {
			ElfSection section = sections.get(e_shstrndx);
			ElfStringTable stringTable = elf.getStringTable(section);
			name = stringTable.readString(sh_name);
			if ("".equals(name)) {
				name = null;
			}
		}

		if (name == null) {
			name = "NO-NAME";

			//find this section's index
			for (int i = 0; i < sections.size(); ++i) {
				if (sections.get(i) == this) {
					name = "SECTION" + i;
					break;
				}
			}
		}
	}

	/**
	 * Returns the actual string name for this section. The section only
	 * stores an byte index into the string table where
	 * the name string is located.
	 * @return the actual string name for this section
	 */
	public String getNameAsString() {
		return name;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return name + " - " + "0x" + Long.toHexString(sh_addr) + ":0x" +
			Long.toHexString(sh_addr + sh_size - 1) + " - 0x" + Long.toHexString(sh_size) + " " +
			" - 0x" + Long.toHexString(sh_offset) + "";
	}

	/**
	 * The byte offset from the beginning of the file to the first
	 * byte in the section.
	 * One section type, SHT_NOBITS described below, occupies no
	 * space in the file, and its sh_offset member locates the conceptual placement in the
	 * file.
	 * @return byte offset from the beginning of the file to the first byte in the section
	 */
	public long getFileOffset() {
		return sh_offset;
	}

	/**
	 * Returns true if this section's offset is invalid.
	 * 
	 * @return true if this section's offset is invalid
	 */
	public boolean isInvalidOffset() {
		return sh_offset < 0 ||
			(elf.is32Bit() && sh_offset == ElfConstants.ELF32_INVALID_OFFSET);
	}

	/**
	 * Sets the section's size.
	 * @param size the new size of the section
	 */
	public void setSize(long size) {
		this.sh_size = size;
		checkSize();
	}

	/**
	 * This member gives the section's size in bytes. Unless the section type is
	 * SHT_NOBITS, the section occupies sh_size bytes in the file. A section of type
	 * SHT_NOBITS may have a non-zero size, but it occupies no space in the file.
	 * @return the section's size in bytes
	 */
	public long getFileSize() {
		return sh_size;
	}

	/**
	 * Get the adjusted size of the section in bytes (i.e., memory block) which relates to this section; it may be zero
	 * if no block should be created.  The returned value reflects any adjustment the ElfExtension may require
	 * based upon the specific processor/language implementation which may require filtering of file bytes
	 * as read into memory.
	 * @return the number of bytes in the resulting memory block
	 */
	public long getAdjustedSize() {
		return elf.getLoadAdapter().getAdjustedSize(this);
	}

	/**
	 * This member categorizes the section's contents and semantics.
	 * @return the section's contents and semantics
	 */
	public int getType() {
		return sh_type;
	}

	/**
	 * Get header type as string.  ElfSectionType name will be returned
	 * if know, otherwise a numeric name of the form "SHT_0x12345678" will be returned.
	 * @return header type as string
	 */
	public String getTypeAsString() {
		ElfSectionType sectionHeaderType = elf.getSectionType(sh_type);
		if (sectionHeaderType != null) {
			return sectionHeaderType.name;
		}
		return "SHT_0x" + StringUtilities.pad(Integer.toHexString(sh_type), '0', 8);
	}

	/**
	 * Returns an input stream starting at offset into
	 * the byte provider.
	 * NOTE: Do not use this method if you have called setData().
	 * @return the input stream 
	 * @throws IOException if an I/O error occurs
	 */
	public InputStream getDataStream() throws IOException {
		if (reader == null) {
			throw new UnsupportedOperationException("This ElfSection does not have a reader");
		}
		return reader.getByteProvider().getInputStream(sh_offset);
	}

	/**
	 * Returns the binary reader.
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Sets the offset of this section. The offset is the actual byte
	 * offset into the file.
	 * @param offset the file byte offset
	 * @throws IOException if an I/O occurs
	 */
	public void setOffset(long offset) throws IOException {
		this.sh_offset = offset;
	}

	/**
	 * Sets the start address of this section.
	 * @param addr the new start address of this section
	 */
	public void setAddress(long addr) {
		if (!elf.isRelocatable() && sh_addr == 0) {
			throw new RuntimeException(
				"Attempting to place non-loaded section into memory :" + name);
		}
		this.sh_addr = elf.unadjustAddressForPrelink(addr);
	}

	/**
	 * Sets the name of this section (may get changed due to conflict)
	 * @param name section name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		String dtName = elf.is32Bit() ? "Elf32_Shdr" : "Elf64_Shdr";
		StructureDataType struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(DWORD, "sh_name", null);
		struct.add(getTypeDataType(), "sh_type", null);
		if (elf.is32Bit()) {
			struct.add(DWORD, "sh_flags", null);
			struct.add(DWORD, "sh_addr", null);
			struct.add(DWORD, "sh_offset", null);
			struct.add(DWORD, "sh_size", null);
		}
		else if (elf.is64Bit()) {
			struct.add(QWORD, "sh_flags", null);
			struct.add(QWORD, "sh_addr", null);
			struct.add(QWORD, "sh_offset", null);
			struct.add(QWORD, "sh_size", null);
		}
		struct.add(DWORD, "sh_link", null);
		struct.add(DWORD, "sh_info", null);
		if (elf.is32Bit()) {
			struct.add(DWORD, "sh_addralign", null);
			struct.add(DWORD, "sh_entsize", null);
		}
		else if (elf.is64Bit()) {
			struct.add(QWORD, "sh_addralign", null);
			struct.add(QWORD, "sh_entsize", null);
		}
		return struct;
	}

	private DataType getTypeDataType() {

		Map<Integer, ElfSectionType> sectionHeaderTypeMap =
			elf.getSectionTypeMap();
		if (sectionHeaderTypeMap == null) {
			return DWordDataType.dataType;
		}

		String dtName = "Elf_SectionType";

		String typeSuffix = elf.getTypeSuffix();
		if (typeSuffix != null) {
			dtName = dtName + typeSuffix;
		}

		EnumDataType typeEnum = new EnumDataType(new CategoryPath("/ELF"), dtName, 4);
		for (ElfSectionType type : sectionHeaderTypeMap.values()) {
			typeEnum.add(type.name, type.value);
		}
		return typeEnum;
	}

	private void checkSize() {
		if (sh_size > Integer.toUnsignedLong(Integer.MAX_VALUE)) {
			throw new UnsupportedOperationException(
				"ELF Section is too large: 0x" + Long.toHexString(sh_size));
		}
	}

	@Override
	public int hashCode() {
		return (int) ((17 * sh_offset) + (sh_offset >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ElfSection)) {
			return false;
		}
		ElfSection other = (ElfSection) obj;
		return reader == other.reader && sh_name == other.sh_name && sh_type == other.sh_type &&
			sh_flags == other.sh_flags && sh_addr == other.sh_addr &&
			sh_offset == other.sh_offset && sh_size == other.sh_size && sh_link == other.sh_link &&
			sh_info == other.sh_info && sh_addralign == other.sh_addralign &&
			sh_entsize == other.sh_entsize;
	}

	/**
	 * Returns a predicate for sections which loads/contains the specified address.
	 * @param address the address of the requested section
	 * @return predicate
	 */
	public static Predicate<ElfSection> isSectionLoadHeaderContaining(long address) {
		Predicate<ElfSection> predicate = section -> {
			// FIXME: verify
			if (section.isAlloc()) {
				long start = section.getVirtualAddress();
				long end = start + section.getFileSize();
				if (start <= address && address <= end) {
					return true;
				}
			}

			return false;
		};

		return predicate;
	}

	/**
	 * Returns a predicate for sections which fully contains the specified file offset range.
	 * @param fileOffset file offset
	 * @param fileRangeLength length of file range in bytes
	 * @return predicate
	 */
	public static Predicate<ElfSection> isSectionContainingFileRange(long fileOffset,
			long fileRangeLength) {
		long maxOffset = fileOffset + fileRangeLength - 1;
		Predicate<ElfSection> predicate = section -> {
			if (section.getType() == ElfSectionConstants.SHT_NULL ||
				section.isInvalidOffset()) {
				return false;
			}

			long size = section.getFileSize();
			if (size >= 0) {
				long start = section.getFileOffset();
				long end = start + size - 1;
				if (fileOffset >= start && maxOffset <= end) {
					return true;
				}
			}

			return false;
		};

		return predicate;
	}
}
