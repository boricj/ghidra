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
package ghidra.program.model.reloc;

import java.util.Iterator;
import java.util.List;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * An interface for storing the relocations defined in a program.
 * Table must preserve the order in which relocations are added such that
 * the iterators return them in the same order.
 */
public interface RelocationTable {
	/** Name of the relocatable property in the program information property list. */
	public static final String RELOCATABLE_PROP_NAME = "Relocatable";

	/**
	 * Creates and adds a new relocation with the specified
	 * address, type, and value. 
	 * 
	 * @param addr the address where the relocation is required
	 * @param type the type of relocation to perform
	 * @param values the values needed when performing the relocation.  Definition of values is
	 * specific to loader used and relocation type.
	 * @param bytes original instruction bytes affected by relocation.  A null value should be
	 * passed to rely on original underlying {@link FileBytes}.
	 * @param symbolName the name of the symbol being relocated; may be null 
	 * @return the newly added relocation object
	 */
	public Relocation add(Address addr, int type, long[] values, byte[] bytes, String symbolName);

	/**
	 * Clears the relocation table.
	 */
	public void clear();

	/**
	 * Returns the ordered list of relocations which have been defined for the specified address.
	 * In most cases there will be one or none, but in some cases multiple relocations may be
	 * applied to a single address. 
	 * @param addr the address where the relocation(s) are defined
	 * @return the ordered list of relocations which have been defined for the specified address.
	 */
	public List<Relocation> getRelocations(Address addr);

	/**
	 * Determine if the specified address has a relocation defined.
	 * @param addr memory address within program
	 * @return true if relocation defined, otherwise false
	 */
	public boolean hasRelocation(Address addr);

	/**
	 * Returns an iterator over all defined relocations (in ascending address order) located 
	 * within the program.
	 * @return ordered relocation iterator
	 */
	public Iterator<Relocation> getRelocations();

	/**
	 * Returns an iterator over all defined relocations (in ascending address order) located 
	 * within the program over the specified address set.
	 * @param set address set
	 * @return ordered relocation iterator
	 */
	public Iterator<Relocation> getRelocations(AddressSetView set);

	/**
	 * Returns the next relocation address which follows the specified address.
	 * @param addr starting point
	 * @return next relocation address after addr or null if none
	 */
	public Address getRelocationAddressAfter(Address addr);

	/**
	 * Returns the number of relocation in this table.
	 * @return the number of relocation in this table
	 */
	public int getSize();

	/**
	 * Returns true if this relocation table contains relocations for a relocatable binary.
	 * Some binaries may contain relocations, but not actually be relocatable. For example, ELF executables.
	 * @return true if this relocation table contains relocations for a relocatable binary
	 */
	public boolean isRelocatable();
}
