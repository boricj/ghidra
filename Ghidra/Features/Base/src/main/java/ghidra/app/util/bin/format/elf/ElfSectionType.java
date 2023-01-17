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

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

public class ElfSectionType {

	private static Map<Integer, ElfSectionType> defaultElfSectionTypeMap =
		new HashMap<Integer, ElfSectionType>();

	public static ElfSectionType SHT_NULL = addDefaultSectionType(
		ElfSectionConstants.SHT_NULL, "SHT_NULL", "Inactive section");
	public static ElfSectionType SHT_PROGBITS = addDefaultSectionType(
		ElfSectionConstants.SHT_PROGBITS, "SHT_PROGBITS", "Program defined section");
	public static ElfSectionType SHT_SYMTAB =
		addDefaultSectionType(ElfSectionConstants.SHT_SYMTAB, "SHT_SYMTAB",
			"Symbol table for link editing and dynamic linking");
	public static ElfSectionType SHT_STRTAB = addDefaultSectionType(
		ElfSectionConstants.SHT_STRTAB, "SHT_STRTAB", "String table");
	public static ElfSectionType SHT_RELA = addDefaultSectionType(
		ElfSectionConstants.SHT_RELA, "SHT_RELA", "Relocation entries with explicit addends");
	public static ElfSectionType SHT_HASH = addDefaultSectionType(
		ElfSectionConstants.SHT_HASH, "SHT_HASH", "Symbol hash table for dynamic linking");
	public static ElfSectionType SHT_DYNAMIC = addDefaultSectionType(
		ElfSectionConstants.SHT_DYNAMIC, "SHT_DYNAMIC", "Dynamic linking information");
	public static ElfSectionType SHT_NOTE =
		addDefaultSectionType(ElfSectionConstants.SHT_NOTE, "SHT_NOTE",
			"Section holds information that marks the file");
	public static ElfSectionType SHT_NOBITS = addDefaultSectionType(
		ElfSectionConstants.SHT_NOBITS, "SHT_NOBITS", "Section contains no bytes");
	public static ElfSectionType SHT_REL = addDefaultSectionType(
		ElfSectionConstants.SHT_REL, "SHT_REL", "Relocation entries w/o explicit addends");
	public static ElfSectionType SHT_SHLIB =
		addDefaultSectionType(ElfSectionConstants.SHT_SHLIB, "SHT_SHLIB", "");
	public static ElfSectionType SHT_DYNSYM = addDefaultSectionType(
		ElfSectionConstants.SHT_DYNSYM, "SHT_DYNSYM", "Symbol table for dynamic linking");
	public static ElfSectionType SHT_INIT_ARRAY =
		addDefaultSectionType(ElfSectionConstants.SHT_INIT_ARRAY, "SHT_INIT_ARRAY",
			"Array of initializer functions");
	public static ElfSectionType SHT_FINI_ARRAY = addDefaultSectionType(
		ElfSectionConstants.SHT_FINI_ARRAY, "SHT_FINI_ARRAY", "Array of finalizer functions");
	public static ElfSectionType SHT_PREINIT_ARRAY =
		addDefaultSectionType(ElfSectionConstants.SHT_PREINIT_ARRAY,
			"SHT_PREINIT_ARRAY", "Array of pre-initializer functions");
	public static ElfSectionType SHT_GROUP = addDefaultSectionType(
		ElfSectionConstants.SHT_GROUP, "SHT_GROUP", "Section group");
	public static ElfSectionType SHT_SYMTAB_SHNDX = addDefaultSectionType(
		ElfSectionConstants.SHT_SYMTAB_SHNDX, "SHT_SYMTAB_SHNDX", "Extended section indeces");

	// OS-specific range: 0x60000000 - 0x6fffffff
	
	public static ElfSectionType SHT_ANDROID_REL = addDefaultSectionType(
		ElfSectionConstants.SHT_ANDROID_REL, "SHT_ANDROID_REL", "Android relocation entries w/o explicit addends");
	public static ElfSectionType SHT_ANDROID_RELA = addDefaultSectionType(
		ElfSectionConstants.SHT_ANDROID_RELA, "SHT_ANDROID_RELA", "Android relocation entries with explicit addends");

	public static ElfSectionType SHT_GNU_ATTRIBUTES = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_ATTRIBUTES, "SHT_GNU_ATTRIBUTES", "Object attributes");
	public static ElfSectionType SHT_GNU_HASH = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_HASH, "SHT_GNU_HASH", "GNU-style hash table");
	public static ElfSectionType SHT_GNU_LIBLIST = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_LIBLIST, "SHT_GNU_LIBLIST", "Prelink library list");
	public static ElfSectionType SHT_CHECKSUM = addDefaultSectionType(
		ElfSectionConstants.SHT_CHECKSUM, "SHT_CHECKSUM", "Checksum for DSO content");

	public static ElfSectionType SHT_SUNW_move =
		addDefaultSectionType(ElfSectionConstants.SHT_SUNW_move, "SHT_SUNW_move", "");
	public static ElfSectionType SHT_SUNW_COMDAT = addDefaultSectionType(
		ElfSectionConstants.SHT_SUNW_COMDAT, "SHT_SUNW_COMDAT", "");
	public static ElfSectionType SHT_SUNW_syminfo = addDefaultSectionType(
		ElfSectionConstants.SHT_SUNW_syminfo, "SHT_SUNW_syminfo", "");
	public static ElfSectionType SHT_GNU_verdef = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_verdef, "SHT_GNU_verdef", "Version definition section");
	public static ElfSectionType SHT_GNU_verneed = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_verneed, "SHT_GNU_verneed", "Version needs section");
	public static ElfSectionType SHT_GNU_versym = addDefaultSectionType(
		ElfSectionConstants.SHT_GNU_versym, "SHT_GNU_versym", "Version symbol table");

	// Processor-specific range: 0x70000000 - 0x7fffffff

	private static ElfSectionType addDefaultSectionType(int value, String name,
			String description) {
		try {
			ElfSectionType type = new ElfSectionType(value, name, description);
			addSectionType(type, defaultElfSectionTypeMap);
			return type;
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException("ElfSectionType initialization error", e);
		}
	}

	/**
	 * Add the specified section type to the specified map.
	 * @param type section type
	 * @param sectionHeaderTypeMap
	 * @throws DuplicateNameException if new type name already defined within
	 * the specified map
	 */
	public static void addSectionType(ElfSectionType type,
			Map<Integer, ElfSectionType> sectionHeaderTypeMap) throws DuplicateNameException {
		ElfSectionType conflictType = sectionHeaderTypeMap.get(type.value);
		if (conflictType != null) {
			throw new DuplicateNameException(
				"ElfSectionType conflict during initialization (" + type.name + " / " +
					conflictType.name + "), value=0x" + Integer.toHexString(type.value));
		}
		for (ElfSectionType existingType : sectionHeaderTypeMap.values()) {
			if (type.name.equalsIgnoreCase(existingType.name)) {
				throw new DuplicateNameException(
					"ElfSectionType conflict during initialization, name=" + type.name);
			}
		}
		sectionHeaderTypeMap.put(type.value, type);
	}

	public final int value;
	public final String name;
	public final String description;

	public ElfSectionType(int value, String name, String description) {
		this.value = value;
		this.name = name;
		this.description = description;
	}

	public static void addDefaultTypes(Map<Integer, ElfSectionType> programHeaderTypeMap) {
		programHeaderTypeMap.putAll(defaultElfSectionTypeMap);
	}

	public static EnumDataType getEnumDataType(boolean is32bit, String typeSuffix,
			Map<Integer, ElfSectionType> dynamicTypeMap) {
		int size = is32bit ? 4 : 8;
		String name = is32bit ? "Elf32_PHType" : "Elf64_PHType";
		if (typeSuffix != null) {
			name = name + typeSuffix;
		}
		EnumDataType phTypeEnum = new EnumDataType(new CategoryPath("/ELF"), name, size);
		for (ElfSectionType type : dynamicTypeMap.values()) {
			phTypeEnum.add(type.name, type.value);
		}
		return phTypeEnum;
	}

	@Override
	public String toString() {
		return name + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")";
	}

}
