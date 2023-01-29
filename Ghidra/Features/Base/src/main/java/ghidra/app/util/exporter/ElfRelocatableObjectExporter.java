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
import java.util.List;

import org.jgrapht.nio.ExportException;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.DataConverter;
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
				new ElfRelocatableObject(program, programSet, file.getName(), fileSet, taskMonitor, log);

			ElfHeader elf = relocatableObject.synthetize();

			taskMonitor.setMessage("Writing out ELF relocatable object file...");
			write(elf, raf, relocatableObject.getDataConverter());
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

	private static long alignTo(long value, long alignment) {
		if ((alignment > 1) && (value % alignment != 0)) {
			value = value + alignment - (value % alignment);
		}

		return value;
	}

	private static void write(ElfHeader elf, RandomAccessFile raf, DataConverter dc)
			throws IOException {
		long offset = elf.e_ehsize();
		raf.seek(offset);

		// Write sections.
		for (ElfSectionHeader section : elf.getSections()) {
			if (section.getType() != ElfSectionHeaderConstants.SHT_NULL) {
				long sectionOffset = alignTo(raf.getFilePointer(), section.getAddressAlignment());

				raf.seek(sectionOffset);
				section.setOffset(raf.getFilePointer());

				if (section.getType() != ElfSectionHeaderConstants.SHT_NOBITS) {
					ByteProvider provider = section.getByteProvider();
					section.setSize(provider.length());

					raf.write(provider.readBytes(0, section.getFileSize()));
				}
			}
		}

		// Write section header table.
		long sectionHeaderOffset = alignTo(raf.getFilePointer(), 16);
		raf.seek(sectionHeaderOffset);

		for (ElfSectionHeader section : elf.getSections()) {
			section.write(raf, dc);
		}

		// Write ELF header.
		raf.seek(0);
		elf.setSectionHeaderOffset(sectionHeaderOffset);
		elf.write(raf, dc);
	}
}
