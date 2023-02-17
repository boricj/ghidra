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
package ghidra.app.util.bin.format.aout;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.aout.UnixAoutHeader.ExecutableType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing UNIX-style A.out executables
 *
 * This style was also used by UNIX-like systems such as SunOS, BSD, and
 * VxWorks, as well as some early distributions of Linux. Although there do
 * exist implementations of A.out with 64-bit and GNU extensions, this loader
 * does not currently support them.
 *
 * @see <a href="https://wiki.osdev.org/A.out">OSDev.org A.out</a>
 * @see <a href="https://man.freebsd.org/cgi/man.cgi?a.out(5)">FreeBSD
 *      manpage</a>
 */
public class UnixAoutLoader extends AbstractProgramWrapperLoader {

    private MemoryBlock textBlock;
    private AddressSpace textAddrSpace;
    private MemoryBlock dataBlock;
    private AddressSpace dataAddrSpace;
    private MemoryBlock bssBlock;
    private AddressSpace bssAddrSpace;
    private Hashtable<String,Long> bssSymbols;
    private Hashtable<String,Long> possibleBssSymbols;
    private Namespace namespace;
    private Vector<UnixAoutSymbolTableEntry> symTab;
    private Vector<UnixAoutRelocationTableEntry> textRelocTab;
    private Vector<UnixAoutRelocationTableEntry> dataRelocTab;
    private Hashtable<Address,String> localFunctions = new Hashtable<Address, String>();
    private long bssLocation = 0;
    private FlatProgramAPI api;
    private Program program;
    private MessageLog log;
    private UnixAoutHeader header;
    private String filename;
    private boolean isOverlay;
    private boolean bigEndian;

    public static final String OPTION_NAME_BASE_ADDR = "Base Address";

    @Override
    public String getName() {
        return "UNIX A.out executable";
    }

    @Override
    public boolean supportsLoadIntoProgram() {
        return true;
    }

    /**
     * Retrieves the Address offset given in the "Base Address" option.
     * Returns 0 if the option could not be found or contains an invalid value.
     */
    private long getBaseAddrOffset(List<Option> options) {
        Address baseAddr = null;
        if (options != null) {
            for (Option option : options) {
                String optName = option.getName();
                if (optName.equals(OPTION_NAME_BASE_ADDR)) {
                    baseAddr = (Address) option.getValue();
                }
            }
        }

        long offset = 0;
        if (baseAddr != null) {
            offset = baseAddr.getOffset();
        }

        return offset;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
                                  Program program) {

        Address baseAddr = null;

        for (Option option : options) {
            String optName = option.getName();
            try {
                if (optName.equals(OPTION_NAME_BASE_ADDR)) {
                    baseAddr = (Address) option.getValue();
                }
            } catch (Exception e) {
                if (e instanceof OptionException) {
                    return e.getMessage();
                }
                return "Invalid value for " + optName + " - " + option.getValue();
            }
        }
        if (baseAddr == null) {
            return "Invalid base address";
        }

        return super.validateOptions(provider, loadSpec, options, program);
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
                                          DomainObject domainObject, boolean loadIntoProgram) {

        Address baseAddr = null;

        if (domainObject instanceof Program) {
            Program program = (Program)domainObject;
            AddressFactory addressFactory = program.getAddressFactory();
            if (addressFactory != null) {
                AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
                if (defaultAddressSpace != null) {
                    baseAddr = defaultAddressSpace.getAddress(0);
                }
            }
        }

        List<Option> list = new ArrayList<Option>();
        list.add(new Option(OPTION_NAME_BASE_ADDR, baseAddr, Address.class,
                            Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));

        list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram));
        return list;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Attempt to parse the header as both little- and big-endian.
        // It is likely that only one of these will produce sensible values.
        UnixAoutHeader hdrBE = new UnixAoutHeader(provider, false);
        UnixAoutHeader hdrLE = new UnixAoutHeader(provider, true);
        boolean beValid = false;

        if (hdrBE.isValid()) {
            final String lang = hdrBE.getLanguageSpec();
            final String comp = hdrBE.getCompilerSpec();
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang, comp), true));
            beValid = true;
        }
        if (hdrLE.isValid()) {
            final String lang = hdrLE.getLanguageSpec();
            final String comp = hdrLE.getCompilerSpec();
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang, comp), !beValid));
        }

        return loadSpecs;
    }

    /**
     * Creates an AddressSpace and MemoryBlock for the .text section of the binary, reading its
     * contents from the provider.
     */
    protected void createTextSection(ByteProvider provider, TaskMonitor monitor, long size,
                                     long addressFromHeader, long fileOffset) {

        this.log.appendMsg(".text section: " + size + " bytes loaded to address " +
                           String.format("%08X", addressFromHeader) + " from file offset " +
                           String.format("%08X", fileOffset));

        if (size > 0) {
            Address address = this.program.getAddressFactory().getDefaultAddressSpace().getAddress(
				addressFromHeader);
            try {
                InputStream stream = provider.getInputStream(fileOffset);
                this.textBlock = this.program.getMemory().createInitializedBlock(
					this.filename + ".text", address, stream, size, monitor, this.isOverlay);
                this.textBlock.setRead(true);
                this.textBlock.setWrite(false);
                this.textBlock.setExecute(true);
                this.textAddrSpace = textBlock.getStart().getAddressSpace();
            } catch (LockException | MemoryConflictException | AddressOverflowException |
                         CancelledException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Creates an AddressSpace and MemoryBlock for the .data section of the binary, reading its
     * contents from the provider.
     */
    protected void createDataSection(ByteProvider provider, TaskMonitor monitor, long size,
                                     long addressFromHeader, long fileOffset) {

        this.log.appendMsg(".data section: " + size + " bytes loaded to address " +
                           String.format("%08X", addressFromHeader) + " from file offset " +
                           String.format("%08X", fileOffset));

        if (size > 0) {
            Address address =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(addressFromHeader);
            try {
                InputStream stream = provider.getInputStream(fileOffset);
                this.dataBlock = program.getMemory().createInitializedBlock(
                                     this.filename + ".data", address, stream, size, monitor, this.isOverlay);
                this.dataBlock.setRead(true);
                this.dataBlock.setWrite(true);
                this.dataBlock.setExecute(false);
                this.dataAddrSpace = dataBlock.getStart().getAddressSpace();
            } catch (LockException | MemoryConflictException | AddressOverflowException |
                         CancelledException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Creates a .bss section for this binary, ensuring that it has enough space to accommodate
     * all of the symbols that are explictly assigned to .bss and also the symbols marked as
     * N_UNDF and that need to be dynamically assigned space in this section.
     */
    protected void createBssSection(long bssAddrVal) {
        // Add up the sizes of all the symbols that are supposed to be allocated
        // in .bss, and ensure that our .bss segment has enough additional space
        // to accommodate them (beyond the size allocated by the header.)
        // Until we search the global symbol table for the symbols in the
        // 'possibleBssSymbols' list (which will happen as we walk the relocation
        // table, below), we won't know whether these symbols exist in another
        // binary file that was previously loaded, or, instead, if we'll need to
        // mimic the linker behavior and assign them space in .bss.
        Long additionalBssSpace = (long) 0;
        for (Long symbolSize : this.possibleBssSymbols.values()) {
            additionalBssSpace += symbolSize;
        }

        final long givenBssSize = this.header.getBssSize();

        // Keep track of the next available location in .bss. The dynamically
        // located symbols (of N_UNDF type) will start after the fix section.
        this.bssLocation = givenBssSize;

        final long totalBssSize = givenBssSize + additionalBssSpace;

        this.log.appendMsg(".bss section: " + totalBssSize + " bytes (" + givenBssSize + " + " +
                           additionalBssSpace + " additional) loaded to address " +
                           String.format("%08X", bssAddrVal));

        if (totalBssSize > 0) {
            Address bssAddr =
                this.program.getAddressFactory().getDefaultAddressSpace().getAddress(bssAddrVal);
            try {
                this.bssBlock = this.program.getMemory().createUninitializedBlock(
                    this.filename + ".bss", bssAddr, totalBssSize, this.isOverlay);
                this.bssAddrSpace = bssBlock.getStart().getAddressSpace();
                this.bssBlock.setRead(true);
                this.bssBlock.setWrite(true);
                this.bssBlock.setExecute(false);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Labels the known symbols in the .bss section.
     */
    protected void placeBssSymbols() {
        if (this.bssSymbols.size() > 0) {
            if (this.bssAddrSpace != null) {
                try {
                    for (String bssSymbolName : this.bssSymbols.keySet()) {
                        final Long bssSymbolAddr = this.bssSymbols.get(bssSymbolName);
                        this.api.createLabel(this.bssAddrSpace.getAddress(bssSymbolAddr),
                            bssSymbolName, this.namespace, true, SourceType.IMPORTED);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                this.log.appendMsg("Warning: some symbols were identified as being in .bss, but" +
                                   " .bss could not be created.");
            }
        }
    }

    /**
     * Processes the binary's symbol table, taking one of four different actions depending on the
     * symbol type:
     *  - N_TEXT are added to a list for disassembly later.
     *  - N_DATA are labeled immediately.
     *  - N_BSS are added to a list for labeling after the .bss section size has been established.
     *  - N_UNDF are added to a list for address assignment and labeling in .bss if the symbol is
     *    not found to already exist in a global symbol table (i.e. provided by another binary.)
     */
    protected void processSymbolTable() {

        this.bssSymbols = new Hashtable<String, Long>();
        this.possibleBssSymbols = new Hashtable<String, Long>();

        // Process the symbol table by applying labels to identify any symbols whose
        // addresses are given
        for (Integer i = 0; i < this.symTab.size(); i++) {
            UnixAoutSymbolTableEntry symTabEntry = this.symTab.elementAt(i);
            try {
                if (symTabEntry.value != 0) {
                    if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_TEXT) {
                        if (symTabEntry.isExt) {
                            // Save the entry point to this function in a list. Disassembly should
							// wait until after we've processed the relocation tables.
                            Address funcAddr = this.textAddrSpace.getAddress(symTabEntry.value);
                            this.localFunctions.put(funcAddr, symTabEntry.name);
                        }
                    } else if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_DATA) {
                        this.api.createLabel(this.dataAddrSpace.getAddress(symTabEntry.value),
							symTabEntry.name, this.namespace, true, SourceType.IMPORTED);

                    } else if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_BSS) {
                        // Save the symbols that are explicitly identified as being in .bss
                        // to a list so that they can be labeled later (after we actually
                        // create the .bss block, which must wait until after we total all
                        // the space used by N_UNDF symbols; see below.)
                        this.bssSymbols.put(symTabEntry.name, symTabEntry.value);

                    } else if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_UNDF) {
                        // This is a special case given by the A.out spec: if the linker cannot find
                        // this symbol in any of the other binary files, then the fact that it is
                        // marked as N_UNDF but has a non-zero value means that its value should be
                        // interpreted as a size, and the linker should reserve space in .bss for it.
                        this.possibleBssSymbols.put(symTabEntry.name, symTabEntry.value);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Processes the text relocation table by fixing addresses based on the true location of each
     * symbol.
     */
    protected void processTextRelocation() {
        for (Integer i = 0; i < this.textRelocTab.size(); i++) {

            UnixAoutRelocationTableEntry relocationEntry = this.textRelocTab.elementAt(i);
            if (relocationEntry.symbolNum < symTab.size()) {

                UnixAoutSymbolTableEntry symbolEntry =
                    this.symTab.elementAt((int) relocationEntry.symbolNum);
                AddressSpace addrSpace = this.textBlock.getStart().getAddressSpace();
                Address relocAddr =
                    addrSpace.getAddress(relocationEntry.address + this.header.getTextAddr());

                // If this symbol's N_EXT flag is clear, then we didn't mark it as a function when
                // we were processing the symbol table (above). This is because special symbols like
                // "gcc2_compiled", "___gnu_compiled_c", and names of object files are in the symbol
                // table for this segment, but do not point to disassemblable code. However, since
                // there is now a reference from the relocation table, we should be able to
                // disassemble at its address. Save the address for disassembly later.
                if (!symbolEntry.isExt) {
                    Address funcAddr = textAddrSpace.getAddress(symbolEntry.value);
                    this.localFunctions.put(funcAddr, symbolEntry.name);
                }

                if (relocationEntry.extern && this.textBlock.contains(relocAddr)) {

                    List<Function> funcs = this.api.getCurrentProgram().getListing().
                                           getGlobalFunctions(symbolEntry.name);
                    List<Symbol> symbolsGlobal = this.api.getSymbols(symbolEntry.name, null);
                    List<Symbol> symbolsLocal = this.api.getSymbols(symbolEntry.name, namespace);

                    if (funcs.size() > 0) {
                        Address funcAddr = funcs.get(0).getEntryPoint();
                        fixAddress(this.textBlock, relocAddr, funcAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (symbolsGlobal.size() > 0) {
                        Address globalSymbolAddr = symbolsGlobal.get(0).getAddress();
                        fixAddress(this.textBlock, relocAddr, globalSymbolAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (symbolsLocal.size() > 0) {
                        Address localSymbolAddr = symbolsLocal.get(0).getAddress();
                        fixAddress(this.textBlock, relocAddr, localSymbolAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (this.possibleBssSymbols.containsKey(symbolEntry.name)) {
                        try {
                            Address bssSymbolAddress =
                                this.bssBlock.getStart().getAddressSpace().getAddress(bssLocation);
                            long bssSymbolSize = this.possibleBssSymbols.get(symbolEntry.name);
                            this.api.createLabel(bssSymbolAddress, symbolEntry.name, this.namespace,
                                                 true, SourceType.IMPORTED);
                            fixAddress(this.textBlock, relocAddr, bssSymbolAddress,
                                       relocationEntry.pcRelativeAddressing, this.bigEndian,
                                       relocationEntry.pointerLength);
                            this.program.getReferenceManager().addMemoryReference(relocAddr,
                                    bssSymbolAddress, RefType.DATA, SourceType.IMPORTED, 0);
                            this.bssLocation += bssSymbolSize;

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        this.log.appendMsg("Symbol '" + symbolEntry.name +
                            "' was not found and was not a candidate for allocation in .bss.");
                    }
                }
            } else {
                this.log.appendMsg("Symbol number " + relocationEntry.symbolNum +
                                   " is beyond symbol table length of " + symTab.size());
            }
        }
    }

    /**
     * Processes the data relocation table by fixing addresses based on the true location of each
     * symbol.
     */
    protected void processDataRelocation() {
        for (Integer i = 0; i < this.dataRelocTab.size(); i++) {

            UnixAoutRelocationTableEntry relocationEntry = this.dataRelocTab.elementAt(i);
            if (relocationEntry.symbolNum < symTab.size()) {

                UnixAoutSymbolTableEntry symbolEntry =
                    this.symTab.elementAt((int) relocationEntry.symbolNum);
                AddressSpace addrSpace = this.dataBlock.getStart().getAddressSpace();
                Address relocAddr =
                    addrSpace.getAddress(relocationEntry.address + this.header.getDataAddr());

                if (this.dataBlock.contains(relocAddr)) {

                    List<Function> funcs = this.api.getCurrentProgram().getListing().
                                           getGlobalFunctions(symbolEntry.name);
                    List<Symbol> symbolsGlobal = this.api.getSymbols(symbolEntry.name, null);
                    List<Symbol> symbolsLocal = this.api.getSymbols(symbolEntry.name, namespace);

                    if (funcs.size() > 0) {
                        Address funcAddr = funcs.get(0).getEntryPoint();
                        fixAddress(this.dataBlock, relocAddr, funcAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (symbolsGlobal.size() > 0) {
                        Address globalSymbolAddr = symbolsGlobal.get(0).getAddress();
                        fixAddress(this.dataBlock, relocAddr, globalSymbolAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (symbolsLocal.size() > 0) {
                        Address localSymbolAddr = symbolsLocal.get(0).getAddress();
                        fixAddress(this.dataBlock, relocAddr, localSymbolAddr,
                                   relocationEntry.pcRelativeAddressing, this.bigEndian,
                                   relocationEntry.pointerLength);

                    } else if (this.possibleBssSymbols.containsKey(symbolEntry.name)) {
                        try {
                            Address bssSymbolAddress =
                                this.bssBlock.getStart().getAddressSpace().getAddress(bssLocation);
                            this.api.createLabel(bssSymbolAddress, symbolEntry.name, namespace,
												 true, SourceType.IMPORTED);
                            fixAddress(this.dataBlock, relocAddr, bssSymbolAddress,
                                       relocationEntry.pcRelativeAddressing, this.bigEndian,
                                       relocationEntry.pointerLength);
                            this.program.getReferenceManager().addMemoryReference(relocAddr,
                                    bssSymbolAddress, RefType.DATA, SourceType.IMPORTED, 0);
                            this.bssLocation += this.possibleBssSymbols.get(symbolEntry.name);

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        this.log.appendMsg("Symbol '" + symbolEntry.name +
                            "' was not found and was not a candidate for allocation in .bss.");
                    }
                }
            } else {
                this.log.appendMsg("Symbol number " + relocationEntry.symbolNum +
                                   " is beyond symbol table length of " + symTab.size());
            }
        }
    }

    /**
     * Walks through the table of local function addresses, marks the locations as functions, and
     * starts disassembly of those routines.
     */
    protected void disassembleKnownFuncs() {
        // Now that all relocation addresses have been rewritten, it's safe to start disassembly
        // at all the known function entry points.
        for (Address funcAddr : this.localFunctions.keySet()) {
            this.api.disassemble(funcAddr);
            this.api.createFunction(funcAddr, this.localFunctions.get(funcAddr));
        }

        if ((this.header.getExecutableType() != UnixAoutHeader.ExecutableType.OMAGIC)
                && (this.header.getExecutableType() != UnixAoutHeader.ExecutableType.CMAGIC)) {
            this.api.disassemble(textAddrSpace.getAddress(this.header.getEntryPoint()));
        }
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
                        Program program, TaskMonitor monitor, MessageLog log)
    throws CancelledException, IOException {

        this.bigEndian = program.getLanguage().isBigEndian();
        this.program = program;
        this.log = log;
        this.api = new FlatProgramAPI(program, monitor);
        this.header = new UnixAoutHeader(provider, !this.bigEndian);
        this.filename = provider.getFile().getName();
        this.isOverlay = (header.getExecutableType() == ExecutableType.OMAGIC);

        try {
            this.namespace = this.api.createNamespace(program.getGlobalNamespace(), this.filename);
        } catch (DuplicateNameException | InvalidInputException e1) {
            e1.printStackTrace();
        }

        this.log.appendMsg("Found executable type " + this.header.getExecutableType().name() + ".");

        final long baseAddr = getBaseAddrOffset(options);

        createTextSection(provider, monitor, this.header.getTextSize(),
                          baseAddr + this.header.getTextAddr(), this.header.getTextOffset());
        createDataSection(provider, monitor, this.header.getDataSize(),
                          baseAddr + this.header.getDataAddr(), this.header.getDataOffset());

        BinaryReader reader = new BinaryReader(provider, !this.bigEndian);

        this.symTab = getSymbolTable(reader, this.header.getSymOffset(), this.header.getSymSize(),
                                     this.header.getStrOffset());
        this.textRelocTab = getRelocationTable(reader, this.header.getTextRelocOffset(),
                                               this.header.getTextRelocSize());
        this.dataRelocTab = getRelocationTable(reader, this.header.getDataRelocOffset(),
                                               this.header.getDataRelocSize());

        final long bssAddrVal = baseAddr + this.header.getBssAddr();

        processSymbolTable();
        createBssSection(bssAddrVal);
        placeBssSymbols();
        processTextRelocation();
        processDataRelocation();
        disassembleKnownFuncs();
    }

    /**
     * Rewrites the pointer at the specified location to instead point to the
     * provided address.
     *
     * @param block           Memory block containing the pointer to be rewritten.
     * @param pointerLocation Address at which the pointer to be rewritten is.
     * @param newAddress      Address that will be the new pointer target.
     * @param isPcRelative    Indicates whether the address is program counter
     *                        relative, in which case the pointer will be written
     *                        with the delta between the pointer location and the
     *                        new destination address. Otherwise it will be written
     *                        with the absolute address.
     * @param isBigEndian     True if the program (and therefore the byte order of
     *                        the pointer) is big endian. False if little endian.
     * @param pointerSize     1, 2, and 4-byte pointers are supported.
     */
    private void fixAddress(MemoryBlock block, Address pointerLocation, Address newAddress,
                            boolean isPcRelative, boolean isBigEndian, int pointerSize) {

        final long value = isPcRelative ? (newAddress.getOffset() - pointerLocation.getOffset())
                           : newAddress.getOffset();

        byte[] valueBytes = new byte[pointerSize];

        for (int i = 0; i < pointerSize; i++) {
            int shiftCount = isBigEndian ? (24 - (i * 8)) : (i * 8);
            valueBytes[i] = (byte) ((value >> shiftCount) & 0xff);
        }
        try {
            block.putBytes(pointerLocation, valueBytes);
        } catch (MemoryAccessException e) {
            e.printStackTrace();
        }
    }

    /**
     * Reads a single relocation table for either text or data relocations,
     * depending on the offset/length provided.
     *
     * @param reader Source of file data
     * @param offset File byte offset to the start of the relocation table
     * @param len    Length of the relocation table in bytes
     * @return Vector of relocation table entries
     */
    private Vector<UnixAoutRelocationTableEntry> getRelocationTable(BinaryReader reader,
		long offset, long len) {
        Vector<UnixAoutRelocationTableEntry> relocTable =
			new Vector<UnixAoutRelocationTableEntry>();
        reader.setPointerIndex(offset);

        try {
            while (reader.getPointerIndex() < (offset + len)) {
                long address = reader.readNextUnsignedInt();
                long flags = reader.readNextUnsignedInt();
                relocTable.add(
					new UnixAoutRelocationTableEntry(address, flags, reader.isBigEndian()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return relocTable;
    }

    /**
     * Reads all the symbol table entries from the file, returning their
     * representation.
     *
     * @param reader           Source of file data
     * @param offset           File byte offset to the start of the symbol table
     * @param len              Length of the symbol table in bytes
     * @param strTabBaseOffset File byte offset to the start of the string table
     *                         (containing symbol names)
     * @return Vector of symbol table entries
     */
    private Vector<UnixAoutSymbolTableEntry> getSymbolTable(BinaryReader reader, long offset,
		long len, long strTabBaseOffset) {
        Vector<UnixAoutSymbolTableEntry> symtab = new Vector<UnixAoutSymbolTableEntry>();
        reader.setPointerIndex(offset);

        try {
            // read each symbol table entry
            while (reader.getPointerIndex() < (offset + len)) {
                long strOffset = reader.readNextUnsignedInt();
                byte typeByte = reader.readNextByte();
                byte otherByte = reader.readNextByte();
                short desc = reader.readNextShort();
                long value = reader.readNextUnsignedInt();
                symtab.add(
					new UnixAoutSymbolTableEntry(strOffset, typeByte, otherByte, desc, value));
            }

            // lookup and set each string table symbol name
            for (Integer i = 0; i < symtab.size(); i++) {
                String symstr =
					reader.readAsciiString(strTabBaseOffset + symtab.get(i).nameStringOffset);
                symtab.get(i).name = symstr;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return symtab;
    }
}
