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
package ghidra.app.delinker;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTableSynthesizer;
import ghidra.program.model.reloc.RelocationTableSynthesizerObserver;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.DataConverter;

public class MipsElfRelocationTableSynthesizer implements RelocationTableSynthesizer {
	private Map<Register, RegisterTrace> registers = new HashMap<>();

	public MipsElfRelocationTableSynthesizer() {
	}

	public static class SymbolWithOffset {
		public String name;
		public long offset;

		public SymbolWithOffset(String name, long offset) {
			this.name = name;
			this.offset = offset;
		}
	}

	private List<SymbolWithOffset> getSymbolsWithOffset(Program program, Address address) {
		List<SymbolWithOffset> result = new ArrayList<>();

		MemoryBlock memoryBlock = program.getMemory().getBlock(address);
		if (memoryBlock != null) {
			result.add(new SymbolWithOffset(memoryBlock.getName(),
				address.subtract(memoryBlock.getStart())));
		}

		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
		if (codeUnit != null) {
			Address baseAddress = codeUnit.getMinAddress();
			Symbol symbol = codeUnit.getPrimarySymbol();
			if (symbol != null) {
				result.add(new SymbolWithOffset(symbol.getName(true), address.subtract(baseAddress)));
			}
		}

		return result;
	}

	private static class RegisterTrace {
		public enum Kind {
			HIGH_16,
			LOW_16,
			REGISTER_TO_REGISTER,
		}

		public RegisterTrace(Instruction instruction, Register register, Kind kind) {
			this.parents = Collections.emptyList();
			this.instruction = instruction;
			this.register = register;
			this.kind = kind;
		}

		public RegisterTrace(RegisterTrace parent, Instruction instruction, Register register,
				Kind kind) {
			this.parents = List.of(parent);
			this.instruction = instruction;
			this.register = register;
			this.kind = kind;
		}

		public RegisterTrace(List<RegisterTrace> parents, Instruction instruction,
				Register register,
				Kind kind) {
			this.parents = parents;
			this.instruction = instruction;
			this.register = register;
			this.kind = kind;
		}

		List<RegisterTrace> parents;
		Instruction instruction;
		Register register;
		Kind kind;
	}

	@Override
	public void processFunction(Function function, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		registers.clear();

		for (Instruction instruction : function.getProgram()
				.getListing()
				.getInstructions(function.getBody(), true)) {
			switch (instruction.getMnemonicString()) {
				case "lui":
					execute_lui(instruction, observer);
					break;
				case "_addiu":
				case "addiu":
					execute_addiu(instruction, observer);
					break;
				case "lb":
				case "lbu":
				case "lh":
				case "lhu":
				case "lw":
					execute_load(instruction, observer);
					break;
				case "sb":
				case "sh":
				case "sw":
					execute_store(instruction, observer);
					break;
				case "addu":
					execute_addu(instruction, observer);
					break;
				case "j":
				case "jal":
					execute_jump(instruction, observer);
					break;
				default:
					execute_other(instruction, observer);
					break;
			}
		}
	}

	private static class PatternState {
		Register gp;

		RegisterTrace hi16;
		RegisterTrace lo16;
		boolean extraLo16;
		RegisterTrace gprel16;

		public PatternState(Program program) {
			this.gp = program.getRegister("gp");
		}

		public PatternState(PatternState state) {
			this.gp = state.gp;
			this.hi16 = state.hi16;
			this.lo16 = state.lo16;
			this.extraLo16 = state.extraLo16;
			this.gprel16 = state.gprel16;
		}

		public List<PatternState> process(RegisterTrace trace) {
			if (trace.kind == RegisterTrace.Kind.LOW_16) {
				if (gp.equals(trace.register)) {
					gprel16 = trace;
				}
				else {
					if (lo16 != null) {
						extraLo16 = true;
					}
					lo16 = trace;
				}
			}
			else if (trace.kind == RegisterTrace.Kind.HIGH_16) {
				hi16 = trace;
			}

			if (trace.parents.isEmpty()) {
				return List.of(this);
			}

			List<PatternState> parents = new ArrayList<>();
			for (RegisterTrace parent : trace.parents) {
				PatternState forkedState = new PatternState(this);
				parents.addAll(forkedState.process(parent));
			}

			return parents;
		}
	}

	private void evaluateReferences(Instruction instruction, int operandIndex, Register register,
			RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		evaluateReferences(instruction.getProgram(), instruction.getAddress(), operandIndex,
			register, observer);
	}

	private void evaluateReferences(Program program, Address address, int operandIndex,
			Register register, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		RegisterTrace trace = registers.getOrDefault(register, null);
		if (trace == null) {
			return;
		}

		List<PatternState> patterns = new PatternState(program).process(trace);
		for (PatternState pattern : patterns) {
			for (Reference reference : program.getReferenceManager().getReferencesFrom(address)) {
				if (reference.getOperandIndex() == operandIndex) {
					evaluateReference(program, address, reference, pattern, observer);
				}
			}
		}
	}

	private void evaluateReference(Program program, Address address, Reference reference,
			PatternState pattern, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		Address target = reference.getToAddress();
		for (SymbolWithOffset symbol : getSymbolsWithOffset(program, target)) {
			if (pattern.hi16 != null && pattern.lo16 != null) {
				synthetizeMIPS_HI16(pattern.hi16.instruction, target, symbol, observer);
				synthetizeMIPS_LO16(pattern.lo16.instruction, target, symbol, observer);
			}
			else if (pattern.gprel16 != null) {
				synthetizeMIPS_GPREL16(pattern.gprel16.instruction, target, symbol, observer);
			}
			//			else {
			//				log.appendMsg(address.toString(true, true),
			//					"Unrecognized relocation pattern for " + target.toString(true, true));
			//			}
		}
	}

	private void execute_lui(Instruction instruction,
			RelocationTableSynthesizerObserver observer) {
		Register output = (Register) instruction.getOpObjects(0)[0];
		registers.put(output, new RegisterTrace(instruction, output, RegisterTrace.Kind.HIGH_16));
	}

	private void execute_addiu(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Register output = (Register) instruction.getOpObjects(0)[0];
		Register input = (Register) instruction.getOpObjects(1)[0];

		RegisterTrace inputTrace = registers.getOrDefault(input, null);
		if (inputTrace != null) {
			registers.put(output,
				new RegisterTrace(inputTrace, instruction, input, RegisterTrace.Kind.LOW_16));
		}

		evaluateReferences(instruction, 0, output, observer);
	}

	private void execute_load(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Register output = (Register) instruction.getOpObjects(0)[0];
		Register input = (Register) instruction.getOpObjects(1)[1];

		RegisterTrace inputTrace = registers.getOrDefault(input, null);
		if (inputTrace != null) {
			registers.put(input,
				new RegisterTrace(inputTrace, instruction, input, RegisterTrace.Kind.LOW_16));
			evaluateReferences(instruction, 1, input, observer);
		}

		evaluateReferences(instruction, 0, output, observer);
		registers.remove(output);
	}

	private void execute_store(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Register output = (Register) instruction.getOpObjects(1)[1];
		Register input = (Register) instruction.getOpObjects(0)[0];

		RegisterTrace outputTrace = registers.getOrDefault(output, null);
		if (outputTrace != null) {
			registers.put(output,
				new RegisterTrace(outputTrace, instruction, output, RegisterTrace.Kind.LOW_16));
			evaluateReferences(instruction, 1, output, observer);
		}

		evaluateReferences(instruction, 0, input, observer);
	}

	private void execute_addu(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Register output = (Register) instruction.getOpObjects(0)[0];
		Register input1 = (Register) instruction.getOpObjects(1)[0];
		Register input2 = (Register) instruction.getOpObjects(2)[0];

		List<RegisterTrace> inputTraces = new ArrayList<>();
		for (Register input : List.of(input1, input2)) {
			RegisterTrace inputTrace = registers.getOrDefault(input, null);
			if (inputTrace != null) {
				inputTraces.add(inputTrace);
			}
		}

		if (!inputTraces.isEmpty()) {
			registers.put(output, new RegisterTrace(inputTraces, instruction, null,
				RegisterTrace.Kind.REGISTER_TO_REGISTER));
			evaluateReferences(instruction, 0, output, observer);
		}
	}

	private void execute_jump(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Address address = instruction.getAddress();

		for (Reference reference : instruction.getProgram()
				.getReferenceManager()
				.getReferencesFrom(address)) {
			Address target = reference.getToAddress();
			for (SymbolWithOffset symbol : getSymbolsWithOffset(instruction.getProgram(), target)) {
				synthetizeMIPS_26(instruction, target, symbol, observer);
			}
		}
	}

	private void execute_other(Instruction instruction,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		if (instruction.getNumOperands() == 3) {
			int op0 = instruction.getOperandType(0);
			int op1 = instruction.getOperandType(1);
			int op2 = instruction.getOperandType(2);

			if ((op0 & OperandType.REGISTER) != 0 && (op1 & OperandType.REGISTER) != 0 &&
				(op2 & (OperandType.REGISTER | OperandType.SCALAR)) != 0) {
				Register output = (Register) instruction.getOpObjects(0)[0];
				registers.remove(output);
			}
		}
	}

	@Override
	public void processPointer(Data data, byte bytes[],
			RelocationTableSynthesizerObserver observer) {
		Address addr = data.getAddress();
		Address target = (Address) data.getValue();
		List<SymbolWithOffset> symbols = getSymbolsWithOffset(data.getProgram(), target);

		for (SymbolWithOffset symbol : symbols) {
			synthetizeMIPS_32(data, addr, target, symbol, Arrays.copyOf(bytes, bytes.length),
				observer);
		}

		if (symbols.isEmpty()) {
			observer.getLog()
					.appendMsg(addr.toString(),
						"Failed to determine symbol for " + target.toString());
		}
	}

	private void synthetizeMIPS_32(Data data, Address addr, Address target, SymbolWithOffset symbol,
			byte bytes[], RelocationTableSynthesizerObserver observer) {
		if (bytes.length == 4) {
			getDc(data.getProgram()).putInt(bytes, (int) symbol.offset);
		}
		else if (bytes.length == 8) {
			getDc(data.getProgram()).putLong(bytes, symbol.offset);
		}
		else {
			observer.getLog()
					.appendMsg(addr.toString(), "Unsupported data pointer size " + bytes.length);
			return;
		}

		int type = MIPS_ElfRelocationConstants.R_MIPS_32;
		observer.observe(new Relocation(addr, Relocation.Status.APPLIED, type, null, bytes, symbol.name));
	}

	private void synthetizeMIPS_26(Instruction instruction, Address target, SymbolWithOffset symbol,
			RelocationTableSynthesizerObserver observer) throws MemoryAccessException {
		Address addr = instruction.getAddress();
		byte bytes[] = instruction.getBytes();

		if (symbol.offset % 4 != 0) {
			observer.getLog()
					.appendMsg(addr.toString(), "Unaligned fixup for " + target.toString());
			return;
		}

		int value =
			getDc(instruction.getProgram()).getInt(bytes) & ~MIPS_ElfRelocationConstants.MIPS_LOW26;
		value |= symbol.offset >> 2;
		getDc(instruction.getProgram()).putInt(bytes, value);

		int type = MIPS_ElfRelocationConstants.R_MIPS_26;
		observer.observe(new Relocation(addr, Relocation.Status.APPLIED, type, null, bytes, symbol.name));
	}

	private void synthetizeMIPS_HI16(Instruction instruction, Address target,
			SymbolWithOffset symbol, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		Address addr = instruction.getAddress();
		byte bytes[] = instruction.getBytes();

		int value = getDc(instruction.getProgram()).getInt(bytes) & ~0xFFFF;
		getDc(instruction.getProgram()).putInt(bytes, value);

		int type = MIPS_ElfRelocationConstants.R_MIPS_HI16;
		observer.observe(new Relocation(addr, Relocation.Status.APPLIED, type, null, bytes, symbol.name));
	}

	private void synthetizeMIPS_LO16(Instruction instruction, Address target,
			SymbolWithOffset symbol, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		Address addr = instruction.getAddress();
		byte bytes[] = instruction.getBytes();

		int value = getDc(instruction.getProgram()).getInt(bytes) & ~0xFFFF;
		value |= symbol.offset;
		getDc(instruction.getProgram()).putInt(bytes, value);

		int type = MIPS_ElfRelocationConstants.R_MIPS_LO16;
		observer.observe(new Relocation(addr, Relocation.Status.APPLIED, type, null, bytes, symbol.name));
	}

	private void synthetizeMIPS_GPREL16(Instruction instruction, Address target,
			SymbolWithOffset symbol, RelocationTableSynthesizerObserver observer)
			throws MemoryAccessException {
		Address addr = instruction.getAddress();
		byte bytes[] = instruction.getBytes();

		int value = getDc(instruction.getProgram()).getInt(bytes) & ~0xFFFF;
		value |= symbol.offset;
		getDc(instruction.getProgram()).putInt(bytes, value);

		int type = MIPS_ElfRelocationConstants.R_MIPS_GPREL16;
		observer.observe(new Relocation(addr, Relocation.Status.APPLIED, type, null, bytes, symbol.name));
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("PSX"));
	}

	private static DataConverter getDc(Program program) {
		return DataConverter.getInstance(program.getLanguage().isBigEndian());
	}
}
