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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.UnlimitedByteProviderWrapper;
import ghidra.app.util.bin.format.Writeable;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.DataConverter;

/**
 * A class to represent the Executable and Linking Format (ELF)
 * header and specification.
 */
public class ElfHeader implements StructConverter, Writeable {
    private static final int INITIAL_READ_LEN = ElfConstants.EI_NIDENT + 18;
	private static final int PAD_LENGTH = 7;

	byte e_ident_magic_num; //magic number
	String e_ident_magic_str; //magic string
	byte e_ident_class; //file class
	byte e_ident_data; //data encoding
	byte e_ident_version; //file version
	byte e_ident_osabi; //operating system and abi
	byte e_ident_abiversion; //abi version
	byte[] e_ident_pad; //padding
	short e_type; //object file type
	short e_machine; //target architecture
	int e_version; //object file version
	long e_entry; //executable entry point
	long e_phoff; //segment table offset
	long e_shoff; //section table offset
	int e_flags; //processor-specific flags
	short e_ehsize; //elf header size
	short e_phentsize; //size of entries in the segment table
	int e_phnum; //number of enties in the segment table (may be extended and may not be preserved)
	short e_shentsize; //size of entries in the section table
	int e_shnum; //number of enties in the section table (may be extended and may not be preserved)
	public int e_shstrndx; //section index of the section name string table (may be extended and may not be preserved)

	private Structure headerStructure;

	/**
	 * Construct <code>ElfHeader</code> from byte provider
	 * @param provider byte provider
	 * @throws ElfException if header parse failed
	 * @throws IOException if file IO error occurs
	 */
	public ElfHeader(ByteProvider provider) throws ElfException, IOException {
		try {
			if (provider.length() < INITIAL_READ_LEN) {
				throw new ElfException("Not enough bytes to be a valid ELF executable.");
			}
			byte[] initialBytes = provider.readBytes(0, INITIAL_READ_LEN);

			boolean hasLittleEndianHeaders = determineHeaderEndianess(initialBytes);

			// reader uses unbounded provider wrapper to allow handling of missing/truncated headers
			BinaryReader reader = new BinaryReader(new UnlimitedByteProviderWrapper(provider),
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
		}
		catch (IOException e) {
			throw new ElfException(e);
		}
	}

	public ElfHeader(byte e_ident_class, byte e_ident_data, byte e_ident_version,
			byte e_ident_osabi, byte e_ident_abiversion, short e_type, short e_machine,
			int e_version, long e_entry, int e_flags) throws ElfException {
		this.e_ident_magic_num = ElfConstants.MAGIC_NUM;
		this.e_ident_magic_str = ElfConstants.MAGIC_STR;
		this.e_ident_class = e_ident_class;
		this.e_ident_data = e_ident_data;
		this.e_ident_version = e_ident_version;
		this.e_ident_osabi = e_ident_osabi;
		this.e_ident_abiversion = e_ident_abiversion;
		this.e_ident_pad = new byte[PAD_LENGTH];

		determineHeaderEndianess(e_ident_data);
		if (!is32Bit() && !is64Bit()) {
			throw new ElfException(
				"Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x" +
					Integer.toHexString(e_ident_class) + ")");
		}

		this.e_type = e_type;
		this.e_machine = e_machine;
		this.e_version = e_version;
		this.e_entry = e_entry;
		this.e_phoff = 0;
		this.e_shoff = 0;
		this.e_flags = e_flags;
		this.e_ehsize = (short) (is32Bit() ? 52 : 64);
		this.e_phentsize = (short) (is32Bit() ? 32 : 56);
		this.e_phnum = 0;
		this.e_shentsize = (short) (is32Bit() ? 40 : 64);
		this.e_shnum = 0;
		this.e_shstrndx = 0;
    }

    private boolean determineHeaderEndianess(byte ident_data) throws ElfException {
		boolean hasLittleEndianHeaders = true;

		if (ident_data == ElfConstants.ELF_DATA_BE) {
			hasLittleEndianHeaders = false;
		}
		else if (ident_data != ElfConstants.ELF_DATA_LE) {
			throw new ElfException("Invalid EI_DATA=0x" + Integer.toHexString(ident_data));
		}

        return hasLittleEndianHeaders;
	}

	private boolean determineHeaderEndianess(byte[] bytes) throws ElfException {
		boolean hasLittleEndianHeaders = determineHeaderEndianess(bytes[ElfConstants.EI_DATA]);

		if (!hasLittleEndianHeaders && bytes[ElfConstants.EI_NIDENT] != 0) {
			// Header endianess sanity check
			// Some toolchains always use little endian Elf Headers

			// TODO: unsure if forced endianess applies to relocation data

			// Check first byte of version (allow switch if equal 1)
			if (bytes[ElfConstants.EI_NIDENT + 4] == 1) {
				hasLittleEndianHeaders = true;
			}
		}

        return hasLittleEndianHeaders;
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
		return e_entry;
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
	 * This member holds the size in bytes of one entry in the file's segment table;
	 * all entries are the same size.
	 * @return the size in bytes of one segment table entry 
	 */
	public short e_phentsize() {
		return e_phentsize;
	}

	/**
	 * This member holds the segment table's file offset in bytes. If the file has no
	 * segment table, this member holds zero.
	 * @return the segment table's file offset in bytes
	 */
	public long e_phoff() {
		return e_phoff;
	}

	/**
	 * This member holds the section's size in bytes. A section is one entry in
	 * the section table; all entries are the same size.
	 * @return the section's size in bytes
	 */
	public short e_shentsize() {
		return e_shentsize;
	}

	/**
	 * This member holds the section table's file offset in bytes. If the file has no section
	 * header table, this member holds zero.
	 * @return the section table's file offset in bytes
	 */
	public long e_shoff() {
		return e_shoff;
	}

	/**
	 * 
	 * @param shoff New section header offset
	 */
	public void setSectionHeaderOffset(long shoff) {
		e_shoff = shoff;
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
				"Unsupported segment count serialization: " + e_phnum);
		}
		raf.write(dc.getBytes((short) e_phnum));
		raf.write(dc.getBytes(e_shentsize));
		if (e_shnum >= Short.toUnsignedInt(ElfSectionConstants.SHN_LORESERVE)) {
			throw new IOException(
				"Unsupported section count serialization: " + e_shnum);
		}
		raf.write(dc.getBytes((short) e_shnum));
		raf.write(dc.getBytes((short) e_shstrndx));
	}

}
