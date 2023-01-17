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

public class ElfSegmentType {

	private static Map<Integer, ElfSegmentType> defaultElfSegmentTypeMap =
		new HashMap<Integer, ElfSegmentType>();

	public static ElfSegmentType PT_NULL = addDefaultSegmentType(
		ElfSegmentConstants.PT_NULL, "PT_NULL", "Unused/Undefined segment");
	public static ElfSegmentType PT_LOAD = addDefaultSegmentType(
		ElfSegmentConstants.PT_LOAD, "PT_LOAD", "Loadable segment");
	public static ElfSegmentType PT_DYNAMIC = addDefaultSegmentType(
		ElfSegmentConstants.PT_DYNAMIC, "PT_DYNAMIC", "Dynamic linking information");
	public static ElfSegmentType PT_INTERP = addDefaultSegmentType(
		ElfSegmentConstants.PT_INTERP, "PT_INTERP", "Interpreter path name");
	public static ElfSegmentType PT_NOTE = addDefaultSegmentType(
		ElfSegmentConstants.PT_NOTE, "PT_NOTE", "Auxiliary information location");
	public static ElfSegmentType PT_SHLIB =
		addDefaultSegmentType(ElfSegmentConstants.PT_SHLIB, "PT_SHLIB", "");
	public static ElfSegmentType PT_PHDR = addDefaultSegmentType(
		ElfSegmentConstants.PT_PHDR, "PT_PHDR", "Program header table");
	public static ElfSegmentType PT_TLS = addDefaultSegmentType(
		ElfSegmentConstants.PT_TLS, "PT_TLS", "Thread-Local Storage template");

	// OS-specific range: 0x60000000 - 0x6fffffff

	public static ElfSegmentType PT_GNU_EH_FRAME = addDefaultSegmentType(
		ElfSegmentConstants.PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME", "GCC .eh_frame_hdr segment");
	public static ElfSegmentType PT_GNU_STACK = addDefaultSegmentType(
		ElfSegmentConstants.PT_GNU_STACK, "PT_GNU_STACK", "Indicates stack executability");
	public static ElfSegmentType PT_GNU_RELRO = addDefaultSegmentType(
			ElfSegmentConstants.PT_GNU_RELRO, "PT_GNU_RELRO", "Specifies segments which may be read-only post-relocation");

	// Processor-specific range: 0x70000000 - 0x7fffffff

	private static ElfSegmentType addDefaultSegmentType(int value, String name,
			String description) {
		try {
			ElfSegmentType type = new ElfSegmentType(value, name, description);
			addSegmentType(type, defaultElfSegmentTypeMap);
			return type;
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException("ElfSegmentType initialization error", e);
		}
	}

	/**
	 * Add the specified segment type to the specified map.
	 * @param type segment type
	 * @param programHeaderTypeMap
	 * @throws DuplicateNameException if new type name already defined within
	 * the specified map
	 */
	public static void addSegmentType(ElfSegmentType type,
			Map<Integer, ElfSegmentType> programHeaderTypeMap)
					throws DuplicateNameException {
		ElfSegmentType conflictType = programHeaderTypeMap.get(type.value);
		if (conflictType != null) {
			throw new DuplicateNameException(
				"ElfSegmentType conflict during initialization (" + type.name + " / " +
					conflictType.name + "), value=0x" +
					Integer.toHexString(type.value));
		}
		for (ElfSegmentType existingType : programHeaderTypeMap.values()) {
			if (type.name.equalsIgnoreCase(existingType.name)) {
				throw new DuplicateNameException(
					"ElfSegmentType conflict during initialization, name=" + type.name);
			}
		}
		programHeaderTypeMap.put(type.value, type);
	}

	public final int value;
	public final String name;
	public final String description;

	public ElfSegmentType(int value, String name, String description) {
		if (value < 0) {
			throw new IllegalArgumentException(
				"ElfSegmentType value out of range: 0x" + Long.toHexString(value));
		}
		this.value = value;
		this.name = name;
		this.description = description;
	}

	public static void addDefaultTypes(Map<Integer, ElfSegmentType> programHeaderTypeMap) {
		programHeaderTypeMap.putAll(defaultElfSegmentTypeMap);
	}

	public static EnumDataType getEnumDataType(boolean is32bit, String typeSuffix,
			Map<Integer, ElfSegmentType> dynamicTypeMap) {
		int size = is32bit ? 4 : 8;
		String name = is32bit ? "Elf32_PHType" : "Elf64_PHType";
		if (typeSuffix != null) {
			name = name + typeSuffix;
		}
		EnumDataType phTypeEnum = new EnumDataType(new CategoryPath("/ELF"), name, size);
		for (ElfSegmentType type : dynamicTypeMap.values()) {
			phTypeEnum.add(type.name, type.value);
		}
		return phTypeEnum;
	}

	@Override
	public String toString() {
		return name + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")";
	}

}
