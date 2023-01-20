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

import java.io.File;
import java.nio.file.AccessMode;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;

/**
 * A command-line utility to display the contents of an ELF format file.
 *
 * This utility is designed to mimic the readelf program from the GNU Binutils
 * project, but using Ghidra's own ELF file parsing implementation. It is there
 * to help checking our code against an external reference implementation.
 *
 * However, just like readelf this is not an ELF loader, therefore this utility
 * cannot help with the verification of the actual loading logic done by
 * ElfProgramBuilder into a Ghidra program.
 *
 * To invoke this utility, use the launch.sh helper script:
 * 		./support/launch.sh fg jdk readelf "" "" ghidra.app.util.bin.format.elf.ReadElf <arguments>
 */
public class ReadElf implements GhidraLaunchable {
	private final static Option OPT_FILE_HEADER =
		new Option("h", "file-header", false, "Display the ELF file header");
	private final static Option OPT_PROGRAM_HEADERS =
		new Option("l", "program-headers", false, "Display the program headers");
	private final static Option OPT_SEGMENTS =
		new Option(null, "segments", false, "An alias for --program-headers");
	private final static Option OPT_SECTION_HEADERS =
		new Option("S", "section-headers", false, "Display the section headers");
	private final static Option OPT_SECTIONS =
		new Option(null, "sections", false, "An alias for --section-headers");
	private final static Option OPT_SYMBOLS =
		new Option("s", "symbols", false, "Display the symbol table");
	private final static Option OPT_USE_DYNAMIC =
		new Option("D", "use-dynamic", false,
			"Use the dynamic section info when displaying symbols");
	private final static Option OPT_WIDE =
		new Option("W", "wide", false, "Allow output width to exceed 80 characters (mandatory)");

	private final static Options OPTIONS = new Options();

	static {
		OPTIONS.addOption(OPT_FILE_HEADER);
		OPTIONS.addOption(OPT_PROGRAM_HEADERS);
		OPTIONS.addOption(OPT_SEGMENTS);
		OPTIONS.addOption(OPT_SECTION_HEADERS);
		OPTIONS.addOption(OPT_SECTIONS);
		OPTIONS.addOption(OPT_SYMBOLS);
		OPTIONS.addOption(OPT_USE_DYNAMIC);
		OPTIONS.addOption(OPT_WIDE);
	}

	private final static Map<Byte, String> ELF_FILE_CLASS = Map.ofEntries(
		Map.entry(ElfConstants.ELF_CLASS_NONE, "none"),
		Map.entry(ElfConstants.ELF_CLASS_32, "ELF32"),
		Map.entry(ElfConstants.ELF_CLASS_64, "ELF64"));

	private final static Map<Byte, String> ELF_FILE_DATA = Map.ofEntries(
		Map.entry(ElfConstants.ELF_DATA_NONE, "none"),
		Map.entry(ElfConstants.ELF_DATA_LE, "2's complement, little endian"),
		Map.entry(ElfConstants.ELF_DATA_BE, "2's complement, big endian"));

	private final static Map<Byte, String> ELF_FILE_VERSION = Map.ofEntries(
		Map.entry(ElfConstants.EV_NONE, ""),
		Map.entry(ElfConstants.EV_CURRENT, " (current)"));

	private final static Map<Byte, String> ELF_FILE_OSABI = Map.ofEntries(
		Map.entry(ElfConstants.ELFOSABI_NONE, "UNIX - System V"),
		Map.entry(ElfConstants.ELFOSABI_HPUX, "UNIX - HP-UX"),
		Map.entry(ElfConstants.ELFOSABI_NETBSD, "UNIX - NetBSD"),
		Map.entry(ElfConstants.ELFOSABI_GNU, "UNIX - GNU"),
		Map.entry(ElfConstants.ELFOSABI_SOLARIS, "UNIX - Solaris"),
		Map.entry(ElfConstants.ELFOSABI_AIX, "UNIX - AIX"),
		Map.entry(ElfConstants.ELFOSABI_IRIX, "UNIX - IRIX"),
		Map.entry(ElfConstants.ELFOSABI_FREEBSD, "UNIX - FreeBSD"),
		Map.entry(ElfConstants.ELFOSABI_TRUE64, "UNIX - TRU64"),
		Map.entry(ElfConstants.ELFOSABI_MODESTO, "Novell - Modesto"),
		Map.entry(ElfConstants.ELFOSABI_OPENBSD, "UNIX - OpenBSD"),
		Map.entry(ElfConstants.ELFOSABI_OPENVMS, "VMS - OpenVMS"),
		Map.entry(ElfConstants.ELFOSABI_NSK, "HP - Non-Stop Kernel"),
		Map.entry(ElfConstants.ELFOSABI_AROS, "AROS"),
		Map.entry(ElfConstants.ELFOSABI_FENIXOS, "FenixOS"),
		Map.entry(ElfConstants.ELFOSABI_CLOUDABI, "Nuxi CloudABI"));

	private final static Map<Short, String> ELF_FILE_TYPE = Map.ofEntries(
		Map.entry(ElfConstants.ET_NONE, "NONE (None)"),
		Map.entry(ElfConstants.ET_REL, "REL (Relocatable file)"),
		Map.entry(ElfConstants.ET_EXEC, "EXEC (Executable file)"),
		Map.entry(ElfConstants.ET_DYN,
			"DYN (Position-Independent Executable file or Shared object file)"),
		Map.entry(ElfConstants.ET_CORE, "CORE (Core file)"));

	private final static Map<Short, String> ELF_FILE_MACHINE_TYPE = Map.ofEntries(
		Map.entry(ElfConstants.EM_NONE, "None"),
		Map.entry(ElfConstants.EM_M32, "WE32100"),
		Map.entry(ElfConstants.EM_SPARC, "Sparc"),
		Map.entry(ElfConstants.EM_386, "Intel 80386"),
		Map.entry(ElfConstants.EM_68K, "MC68000"),
		Map.entry(ElfConstants.EM_88K, "MC88000"),
		Map.entry(ElfConstants.EM_860, "Intel 80860"),
		Map.entry(ElfConstants.EM_MIPS, "MIPS R3000"),
		Map.entry(ElfConstants.EM_S370, "IBM System/370"),
		Map.entry(ElfConstants.EM_MIPS_RS3_LE, "MIPS R4000 big-endian"),
		Map.entry(ElfConstants.EM_PARISC, "HPPA"),
		Map.entry(ElfConstants.EM_SPARC32PLUS, "Sparc v8+"),
		Map.entry(ElfConstants.EM_960, "Intel 80960"),
		Map.entry(ElfConstants.EM_PPC, "PowerPC"),
		Map.entry(ElfConstants.EM_PPC64, "PowerPC64"),
		Map.entry(ElfConstants.EM_SPU, "SPU"),
		Map.entry(ElfConstants.EM_V800, "Renesas V850 (using RH850 ABI)"),
		Map.entry(ElfConstants.EM_FR20, "Fujitsu FR20"),
		Map.entry(ElfConstants.EM_RH32, "TRW RH32"),
		Map.entry(ElfConstants.EM_ARM, "ARM"),
		Map.entry(ElfConstants.EM_SH, "Renesas / SuperH SH"),
		Map.entry(ElfConstants.EM_SPARCV9, "Sparc v9"),
		Map.entry(ElfConstants.EM_TRICORE, "Siemens Tricore"),
		Map.entry(ElfConstants.EM_ARC, "ARC"),
		Map.entry(ElfConstants.EM_H8_300, "Renesas H8/300"),
		Map.entry(ElfConstants.EM_H8_300H, "Renesas H8/300H"),
		Map.entry(ElfConstants.EM_H8S, "Renesas H8S"),
		Map.entry(ElfConstants.EM_H8_500, "Renesas H8/500"),
		Map.entry(ElfConstants.EM_IA_64, "Intel IA-64"),
		Map.entry(ElfConstants.EM_MIPS_X, "Stanford MIPS-X"),
		Map.entry(ElfConstants.EM_COLDFIRE, "Motorola Coldfire"),
		Map.entry(ElfConstants.EM_68HC12, "Motorola MC68HC12 Microcontroller"),
		Map.entry(ElfConstants.EM_MMA, "Fujitsu Multimedia Accelerator"),
		Map.entry(ElfConstants.EM_PCP, "Siemens PCP"),
		Map.entry(ElfConstants.EM_NCPU, "Sony nCPU embedded RISC processor"),
		Map.entry(ElfConstants.EM_NDR1, "Denso NDR1 microprocesspr"),
		Map.entry(ElfConstants.EM_STARCORE, "Motorola Star*Core processor"),
		Map.entry(ElfConstants.EM_ME16, "Toyota ME16 processor"),
		Map.entry(ElfConstants.EM_ST100, "STMicroelectronics ST100 processor"),
		Map.entry(ElfConstants.EM_TINYJ, "Advanced Logic Corp. TinyJ embedded processor"),
		Map.entry(ElfConstants.EM_X86_64, "Advanced Micro Devices X86-64"),
		Map.entry(ElfConstants.EM_PDSP, "Sony DSP processor"),
		Map.entry(ElfConstants.EM_PDP10, "Digital Equipment Corp. PDP-10"),
		Map.entry(ElfConstants.EM_PDP11, "Digital Equipment Corp. PDP-11"),
		Map.entry(ElfConstants.EM_FX66, "Siemens FX66 microcontroller"),
		Map.entry(ElfConstants.EM_ST9PLUS, "STMicroelectronics ST9+ 8/16 bit microcontroller"),
		Map.entry(ElfConstants.EM_ST7, "STMicroelectronics ST7 8-bit microcontroller"),
		Map.entry(ElfConstants.EM_68HC16, "Motorola MC68HC16 Microcontroller"),
		Map.entry(ElfConstants.EM_68HC11, "Motorola MC68HC11 Microcontroller"),
		Map.entry(ElfConstants.EM_68HC08, "Motorola MC68HC08 Microcontroller"),
		Map.entry(ElfConstants.EM_68HC05, "Motorola MC68HC05 Microcontroller"),
		Map.entry(ElfConstants.EM_SVX, "Silicon Graphics SVx"),
		Map.entry(ElfConstants.EM_ST19, "STMicroelectronics ST19 8-bit microcontroller"),
		Map.entry(ElfConstants.EM_VAX, "Digital VAX"),
		Map.entry(ElfConstants.EM_CRIS, "Axis Communications 32-bit embedded processor"),
		Map.entry(ElfConstants.EM_JAVELIN, "Infineon Technologies 32-bit embedded cpu"),
		Map.entry(ElfConstants.EM_FIREPATH, "Element 14 64-bit DSP processor"),
		Map.entry(ElfConstants.EM_ZSP, "LSI Logic's 16-bit DSP processor"),
		Map.entry(ElfConstants.EM_MMIX, "Donald Knuth's educational 64-bit processor"),
		Map.entry(ElfConstants.EM_HUANY, "Harvard Universitys's machine-independent object format"),
		Map.entry(ElfConstants.EM_PRISM, "Vitesse Prism"),
		Map.entry(ElfConstants.EM_PJ, "picoJava"),
		Map.entry(ElfConstants.EM_VIDEOCORE, "Alphamosaic VideoCore processor"),
		Map.entry(ElfConstants.EM_TMM_GPP, "Thompson Multimedia General Purpose Processor"),
		Map.entry(ElfConstants.EM_NS32K, "National Semiconductor 32000 series"),
		Map.entry(ElfConstants.EM_TPC, "Tenor Network TPC processor"),
		Map.entry(ElfConstants.EM_SNP1K, "Trebia SNP 1000 processor"),
		Map.entry(ElfConstants.EM_ST200, "STMicroelectronics ST200 microcontroller"),
		Map.entry(ElfConstants.EM_MAX, "MAX Processor"),
		Map.entry(ElfConstants.EM_CR, "National Semiconductor CompactRISC"),
		Map.entry(ElfConstants.EM_F2MC16, "Fujitsu F2MC16"),
		Map.entry(ElfConstants.EM_MSP430, "Texas Instruments msp430 microcontroller"),
		Map.entry(ElfConstants.EM_BLACKFIN, "Analog Devices Blackfin"),
		Map.entry(ElfConstants.EM_SE_C33, "S1C33 Family of Seiko Epson processors"),
		Map.entry(ElfConstants.EM_SEP, "Sharp embedded microprocessor"),
		Map.entry(ElfConstants.EM_ARCA, "Arca RISC microprocessor"),
		Map.entry(ElfConstants.EM_UNICORE, "Unicore"),
		Map.entry(ElfConstants.EM_EXCESS, "eXcess 16/32/64-bit configurable embedded CPU"),
		Map.entry(ElfConstants.EM_DXP, "Icera Semiconductor Inc. Deep Execution Processor"),
		Map.entry(ElfConstants.EM_ALTERA_NIOS2, "Altera Nios II"),
		Map.entry(ElfConstants.EM_CRX, "National Semiconductor CRX microprocessor"),
		Map.entry(ElfConstants.EM_XGATE, "Motorola XGATE embedded processor"),
		Map.entry(ElfConstants.EM_M16C, "Renesas M16C series microprocessors"),
		Map.entry(ElfConstants.EM_DSPIC30F,
			"Microchip Technology dsPIC30F Digital Signal Controller"),
		Map.entry(ElfConstants.EM_CE, "Freescale Communication Engine RISC core"),
		Map.entry(ElfConstants.EM_M32C, "Renesas M32c"),
		Map.entry(ElfConstants.EM_TSK3000, "Altium TSK3000 core"),
		Map.entry(ElfConstants.EM_RS08, "Freescale RS08 embedded processor"),
		Map.entry(ElfConstants.EM_ECOG2, "Cyan Technology eCOG2 microprocessor"),
		Map.entry(ElfConstants.EM_DSP24, "New Japan Radio (NJR) 24-bit DSP Processor"),
		Map.entry(ElfConstants.EM_VIDEOCORE3, "Broadcom VideoCore III processor"),
		Map.entry(ElfConstants.EM_LATTICEMICO32, "Lattice Mico32"),
		Map.entry(ElfConstants.EM_SE_C17, "Seiko Epson C17 family"),
		Map.entry(ElfConstants.EM_TI_C6000, "Texas Instruments TMS320C6000 DSP family"),
		Map.entry(ElfConstants.EM_TI_C2000, "Texas Instruments TMS320C2000 DSP family"),
		Map.entry(ElfConstants.EM_TI_C5500, "Texas Instruments TMS320C55x DSP family"),
		Map.entry(ElfConstants.EM_MMDSP_PLUS,
			"STMicroelectronics 64bit VLIW Data Signal Processor"),
		Map.entry(ElfConstants.EM_CYPRESS_M8C, "Cypress M8C microprocessor"),
		Map.entry(ElfConstants.EM_R32C, "Renesas R32C series microprocessors"),
		Map.entry(ElfConstants.EM_TRIMEDIA, "NXP Semiconductors TriMedia architecture family"),
		Map.entry(ElfConstants.EM_8051, "Intel 8051 and variants"),
		Map.entry(ElfConstants.EM_STXP7X, "STMicroelectronics STxP7x family"),
		Map.entry(ElfConstants.EM_NDS32,
			"Andes Technology compact code size embedded RISC processor family"),
		Map.entry(ElfConstants.EM_ECOG1X, "Cyan Technology eCOG1X family"),
		Map.entry(ElfConstants.EM_MAXQ30, "Dallas Semiconductor MAXQ30 Core microcontrollers"),
		Map.entry(ElfConstants.EM_XIMO16, "New Japan Radio (NJR) 16-bit DSP Processor"),
		Map.entry(ElfConstants.EM_MANIK, "M2000 Reconfigurable RISC Microprocessor"),
		Map.entry(ElfConstants.EM_CRAYNV2, "Cray Inc. NV2 vector architecture"),
		Map.entry(ElfConstants.EM_RX, "Renesas RX"),
		Map.entry(ElfConstants.EM_METAG, "Imagination Technologies Meta processor architecture"),
		Map.entry(ElfConstants.EM_MCST_ELBRUS, "MCST Elbrus general purpose hardware architecture"),
		Map.entry(ElfConstants.EM_ECOG16, "Cyan Technology eCOG16 family"),
		Map.entry(ElfConstants.EM_CR16, "Xilinx MicroBlaze"),
		Map.entry(ElfConstants.EM_ETPU, "Freescale Extended Time Processing Unit"),
		Map.entry(ElfConstants.EM_SLE9X, "Infineon Technologies SLE9X core"),
		Map.entry(ElfConstants.EM_AARCH64, "AArch64"),
		Map.entry(ElfConstants.EM_AVR32, "Atmel Corporation 32-bit microprocessor"),
		Map.entry(ElfConstants.EM_STM8, "STMicroeletronics STM8 8-bit microcontroller"),
		Map.entry(ElfConstants.EM_TILE64, "Tilera TILE64 multicore architecture family"),
		Map.entry(ElfConstants.EM_TILEPRO, "Tilera TILEPro multicore architecture family"),
		Map.entry(ElfConstants.EM_CUDA, "NVIDIA CUDA architecture"),
		Map.entry(ElfConstants.EM_TILEGX, "Tilera TILE-Gx multicore architecture family"),
		Map.entry(ElfConstants.EM_CLOUDSHIELD, "CloudShield architecture family"),
		Map.entry(ElfConstants.EM_COREA_1ST, "KIPO-KAIST Core-A 1st generation processor family"),
		Map.entry(ElfConstants.EM_COREA_2ND, "KIPO-KAIST Core-A 2nd generation processor family"),
		Map.entry(ElfConstants.EM_ARC_COMPACT2, "ARCv2"),
		Map.entry(ElfConstants.EM_OPEN8, "Open8 8-bit RISC soft processor core"),
		Map.entry(ElfConstants.EM_RL78, "Renesas RL78"),
		Map.entry(ElfConstants.EM_VIDEOCORE5, "Broadcom VideoCore V processor"),
		Map.entry(ElfConstants.EM_56800EX, "Freescale 56800EX Digital Signal Controller (DSC)"),
		Map.entry(ElfConstants.EM_BA1, "Beyond BA1 CPU architecture"),
		Map.entry(ElfConstants.EM_BA2, "Beyond BA2 CPU architecture"),
		Map.entry(ElfConstants.EM_XCORE, "XMOS xCORE processor family"),
		Map.entry(ElfConstants.EM_MCHP_PIC, "Microchip 8-bit PIC(r) family"),
		Map.entry(ElfConstants.EM_KM32, "KM211 KM32 32-bit processor"),
		Map.entry(ElfConstants.EM_KMX32, "KM211 KMX32 32-bit processor"),
		Map.entry(ElfConstants.EM_KMX16, "KM211 KMX16 16-bit processor"),
		Map.entry(ElfConstants.EM_KMX8, "KM211 KMX8 8-bit processor"),
		Map.entry(ElfConstants.EM_KVARC, "KM211 KVARC processor"),
		Map.entry(ElfConstants.EM_CDP, "Paneve CDP architecture family"),
		Map.entry(ElfConstants.EM_COGE, "Cognitive Smart Memory Processor"),
		Map.entry(ElfConstants.EM_COOL, "Bluechip Systems CoolEngine"),
		Map.entry(ElfConstants.EM_NORC, "Nanoradio Optimized RISC"),
		Map.entry(ElfConstants.EM_CSR_KALIMBA, "CSR Kalimba architecture family"),
		Map.entry(ElfConstants.EM_AMDGPU, "AMD GPU"),
		Map.entry(ElfConstants.EM_RISCV, "RISC-V"),
		Map.entry(ElfConstants.EM_LANAI, "Lanai 32-bit processor"),
		Map.entry(ElfConstants.EM_BPF, "Linux BPF"));

	private final static String UNKNOWN = "<unknown>";

	public static String unknownHex(int i) {
		return "<unknown: " + Long.toHexString(i) + ">";
	}

	public ReadElf() {
	}

	private final static String FILE_HEADER_IDENT_FMT =
		"  Magic:   %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x \n";

	private final static String FILE_HEADER_IDENT_PRETTY_FMT =
		"  Class:                             %s\n" +
			"  Data:                              %s\n" +
			"  Version:                           %d%s\n" +
			"  OS/ABI:                            %s\n" +
			"  ABI Version:                       %d\n";

	private final static String FILE_HEADER_BASIC_FMT =
		"  Type:                              %s\n" +
			"  Machine:                           %s\n" +
			"  Version:                           0x%x\n" +
			"  Entry point address:               0x%x\n" +
			"  Start of program headers:          %d (bytes into file)\n" +
			"  Start of section headers:          %d (bytes into file)\n" +
			"  Flags:                             0x%x\n" +
			"  Size of this header:               %d (bytes)\n";

	private final static String FILE_HEADER_HEADERS_FMT =
		"  Size of program headers:           %d (bytes)\n" +
			"  Number of program headers:         %d%s\n" +
			"  Size of section headers:           %d (bytes)\n" +
			"  Number of section headers:         %d%s\n" +
			"  Section header string table index: %d%s\n";

	public static void displayFileHeader(ElfFile elf) {
		ElfHeader header = elf.getHeader();
		int numSections = elf.getSections().size();
		int numProgramHeaders = elf.getSegments().size();
		int shStrNdx = elf.getSectionNameStringTableIndex();

		System.out.print("ELF Header:\n");
		System.out.format(FILE_HEADER_IDENT_FMT,
			header.e_ident_magic_num, (byte) header.e_ident_magic_str.charAt(0),
			(byte) header.e_ident_magic_str.charAt(1),
			(byte) header.e_ident_magic_str.charAt(2),
			header.e_ident_class, header.e_ident_data, header.e_ident_version,
			header.e_ident_osabi, header.e_ident_abiversion, header.e_ident_pad[0],
			header.e_ident_pad[1], header.e_ident_pad[2], header.e_ident_pad[3],
			header.e_ident_pad[4], header.e_ident_pad[5], header.e_ident_pad[6]);

		System.out.format(FILE_HEADER_IDENT_PRETTY_FMT,
			ELF_FILE_CLASS.getOrDefault(header.e_ident_class, unknownHex(header.e_ident_class)),
			ELF_FILE_DATA.getOrDefault(header.e_ident_data, unknownHex(header.e_ident_data)),
			header.e_ident_version,
			ELF_FILE_VERSION.getOrDefault(header.e_ident_version, UNKNOWN),
			ELF_FILE_OSABI.getOrDefault(header.e_ident_osabi, unknownHex(header.e_ident_osabi)),
			header.e_ident_abiversion);

		System.out.format(FILE_HEADER_BASIC_FMT,
			ELF_FILE_TYPE.getOrDefault(header.e_type, unknownHex(header.e_type)),
			ELF_FILE_MACHINE_TYPE.getOrDefault(header.e_machine, unknownHex(header.e_machine)),
			header.e_version, header.e_entry,
			header.e_phoff, header.e_shoff, header.e_flags, header.e_ehsize);

		System.out.format(FILE_HEADER_HEADERS_FMT,
			header.e_phentsize,
			header.e_phnum,
			header.e_phnum != numProgramHeaders ? String.format(" (%d)", numProgramHeaders) : "",
			header.e_shentsize,
			header.e_shnum,
			header.e_shnum != numSections ? String.format(" (%d)", numSections) : "",
			header.e_shstrndx,
			header.e_shstrndx != shStrNdx ? String.format(" (%d)", shStrNdx) : "");
	}

	private final static String SECTION_HEADER_32BITS_HEADER =
		"  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n";

	private final static String SECTION_HEADER_32BITS_FMT =
		"  [%2d] %-17s %-15s %08x %06x %06x %02x %3s %2d %3d %2d\n";

	private final static String SECTION_HEADER_64BITS_HEADER =
		"  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n";

	private final static String SECTION_HEADER_64BITS_FMT =
		"  [%2d] %-17s %-15s %016x %06x %06x %02x %3s %2d %3d %2d\n";

	private final static int[] SECTION_HEADER_FLAGS_VAL = {
		ElfSectionConstants.SHF_WRITE,
		ElfSectionConstants.SHF_ALLOC,
		ElfSectionConstants.SHF_EXECINSTR,
		ElfSectionConstants.SHF_MERGE,
		ElfSectionConstants.SHF_STRINGS,
		ElfSectionConstants.SHF_INFO_LINK,
		ElfSectionConstants.SHF_LINK_ORDER,
		ElfSectionConstants.SHF_OS_NONCONFORMING,
		ElfSectionConstants.SHF_GROUP,
		ElfSectionConstants.SHF_TLS,
		ElfSectionConstants.SHF_EXCLUDE
	};

	private final static Character[] SECTION_HEADER_FLAGS_CHAR = {
		'W',
		'A',
		'X',
		'M',
		'S',
		'I',
		'L',
		'O',
		'G',
		'T',
		'E'
	};

	private final static String SECTION_HEADER_FLAGS_KEYS =
		"Key to Flags:\n" +
			"  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n" +
			"  L (link order), O (extra OS processing required), G (group), T (TLS),\n" +
			"  C (compressed), x (unknown), o (OS specific), E (exclude),\n" +
			"  D (mbind), l (large), p (processor specific)\n";

	public static void displaySectionHeaders(ElfFile elf) {
		String fmt, fmtHeader;
		if (elf.getHeader().is32Bit()) {
			fmt = SECTION_HEADER_32BITS_FMT;
			fmtHeader = SECTION_HEADER_32BITS_HEADER;
		}
		else if (elf.getHeader().is64Bit()) {
			fmt = SECTION_HEADER_64BITS_FMT;
			fmtHeader = SECTION_HEADER_64BITS_HEADER;
		}
		else {
			return;
		}

		System.out.print("\nSection Headers:\n");
		System.out.print(fmtHeader);

		List<ElfSection> sections = elf.getSections();
		for (int i = 0; i < sections.size(); i++) {
			ElfSection section = sections.get(i);

			long flags = section.getFlags();
			StringBuffer sb = new StringBuffer();
			for (int j = 0; j < SECTION_HEADER_FLAGS_VAL.length; j++) {
				if ((flags & SECTION_HEADER_FLAGS_VAL[j]) != 0) {
					sb.append(SECTION_HEADER_FLAGS_CHAR[j]);
				}
			}

			System.out.format(fmt, i, section.getNameAsString(), section.getTypeAsString(),
				section.getVirtualAddress(), section.getFileOffset(), section.getMemorySize(),
				section.getEntrySize(), sb.toString(), section.getLink(), section.getInfo(),
				section.getAddressAlignment());
		}

		System.out.print(SECTION_HEADER_FLAGS_KEYS);
	}

	private final static String PROGRAM_HEADERS_NO_FILE_HEADERS_SUMMARY_FMT =
		"\n" +
			"Elf file type is %s\n" +
			"Entry point 0x%x\n" +
			"There are %d program headers, starting at offset %d\n";

	public static void displayProgramHeadersNoFileHeadersSummary(ElfFile elf) {
		ElfHeader header = elf.getHeader();
		List<ElfSegment> segments = elf.getSegments();

		System.out.format(PROGRAM_HEADERS_NO_FILE_HEADERS_SUMMARY_FMT,
			ELF_FILE_TYPE.getOrDefault(header.e_type, unknownHex(header.e_type)),
			header.e_entry,
			segments.size(), header.e_phoff);
	}

	private final static String PROGRAM_HEADER_32BITS_HEADER =
		"  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n";

	private final static String PROGRAM_HEADER_32BITS_FMT =
		"  %-14s 0x%06x 0x%08x 0x%08x 0x%06x 0x%06x %c%c%c 0x%x\n";

	private final static String PROGRAM_HEADER_64BITS_HEADER =
		"  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n";

	private final static String PROGRAM_HEADER_64BITS_FMT =
		"  %-14s 0x%06x 0x%016x 0x%016x 0x%06x 0x%06x %c%c%c 0x%x\n";

	public static void displayProgramHeaders(ElfFile elf) {
		String fmt, fmtHeader;
		if (elf.getHeader().is32Bit()) {
			fmt = PROGRAM_HEADER_32BITS_FMT;
			fmtHeader = PROGRAM_HEADER_32BITS_HEADER;
		}
		else if (elf.getHeader().is64Bit()) {
			fmt = PROGRAM_HEADER_64BITS_FMT;
			fmtHeader = PROGRAM_HEADER_64BITS_HEADER;
		}
		else {
			return;
		}

		System.out.print("\nProgram Headers:\n");
		System.out.print(fmtHeader);

		for (ElfSegment segment : elf.getSegments()) {
			System.out.format(fmt, segment.getTypeAsString(), segment.getFileOffset(),
				segment.getVirtualAddress(), segment.getPhysicalAddress(),
				segment.getFileSize(), segment.getMemorySize(),
				segment.isRead() ? 'R' : ' ', segment.isWrite() ? 'W' : ' ',
				segment.isExecute() ? 'E' : ' ', segment.getAlign());
		}
	}

	private final static String SECTION_TO_SEGMENT_HEADER =
		"  Segment Sections...\n";

	private final static String SECTION_TO_SEGMENT_FMT =
		"   %02d     %s\n";

	public static void displaySectionToSegmentMapping(ElfFile elf) {
		ElfSection sectionNameStringTable = null;
		int sectionNameStringTableIndex = elf.getSectionNameStringTableIndex();
		if (sectionNameStringTableIndex > 0 &&
			sectionNameStringTableIndex < elf.getSections().size()) {
			sectionNameStringTable = elf.getSections().get(sectionNameStringTableIndex);
		}

		if (!elf.getSections().isEmpty() && sectionNameStringTable != null &&
			sectionNameStringTable.getType() == ElfSectionConstants.SHT_STRTAB) {
			System.out.print("\n Section to Segment mapping:\n");
			System.out.print(SECTION_TO_SEGMENT_HEADER);

			List<ElfSegment> segments = elf.getSegments();
			for (int i = 0; i < segments.size(); i++) {
				ElfSegment segment = segments.get(i);
				long fileStart = segment.getFileOffset();
				long fileEnd = fileStart + segment.getFileSize();
				long memStart = segment.getVirtualAddress();
				long memEnd = memStart + segment.getMemorySize();

				List<ElfSection> sections = elf.getSections(e -> {
					long addr = e.getVirtualAddress();
					long off = e.getVirtualAddress();
					boolean inside = (e.getFlags() & ElfSectionConstants.SHF_ALLOC) != 0;
					inside &= addr >= memStart && (addr + e.getMemorySize()) <= memEnd;

					if (e.getType() != ElfSectionConstants.SHT_NOBITS) {
						inside &= off >= fileStart && (off + e.getFileSize()) <= fileEnd;
					}

					return inside && e.getType() != ElfSectionConstants.SHT_NULL;
				});

				String sectionsInSegment = String.join(" ",
					sections.stream().map(e -> e.getNameAsString()).toList());

				System.out.format(SECTION_TO_SEGMENT_FMT, i, sectionsInSegment);
			}
		}
	}

	private final static String SYMBOL_TABLE_32BITS_HEADER =
		"   Num:    Value  Size Type    Bind   Vis      Ndx Name\n";

	private final static String SYMBOL_TABLE_32BITS_FMT =
		"%6d: %08x %-5x %-7s %-6s %-8s %3s %s\n";

	private final static String SYMBOL_TABLE_64BITS_HEADER =
		"   Num:    Value          Size Type    Bind   Vis      Ndx Name\n";

	private final static String SYMBOL_TABLE_64BITS_FMT =
		"%6d: %016x %-5x %-7s %-6s %-8s %3s %s\n";

	private final static Map<Byte, String> SYMBOL_TYPE = Map.ofEntries(
		Map.entry(ElfSymbol.STT_NOTYPE, "NOTYPE"),
		Map.entry(ElfSymbol.STT_OBJECT, "OBJECT"),
		Map.entry(ElfSymbol.STT_FUNC, "FUNC"),
		Map.entry(ElfSymbol.STT_SECTION, "SECTION"),
		Map.entry(ElfSymbol.STT_FILE, "FILE"),
		Map.entry(ElfSymbol.STT_COMMON, "COMMON"));

	private final static Map<Byte, String> SYMBOL_BIND = Map.ofEntries(
		Map.entry(ElfSymbol.STB_LOCAL, "LOCAL"),
		Map.entry(ElfSymbol.STB_GLOBAL, "GLOBAL"),
		Map.entry(ElfSymbol.STB_WEAK, "WEAK"),
		Map.entry(ElfSymbol.STB_GNU_UNIQUE, "GNU_UNIQUE"));

	private final static Map<Byte, String> SYMBOL_VISIBILITY = Map.ofEntries(
		Map.entry(ElfSymbol.STV_DEFAULT, "DEFAULT"),
		Map.entry(ElfSymbol.STV_INTERNAL, "INTERNAL"),
		Map.entry(ElfSymbol.STV_HIDDEN, "HIDDEN"),
		Map.entry(ElfSymbol.STV_PROTECTED, "PROTECTED"));

	public static void displaySymbolTable(ElfFile elf, ElfSymbolTable symbolTable) {
		String fmt, fmtHeader;
		if (elf.getHeader().is32Bit()) {
			fmt = SYMBOL_TABLE_32BITS_FMT;
			fmtHeader = SYMBOL_TABLE_32BITS_HEADER;
		}
		else if (elf.getHeader().is64Bit()) {
			fmt = SYMBOL_TABLE_64BITS_FMT;
			fmtHeader = SYMBOL_TABLE_64BITS_HEADER;
		}
		else {
			return;
		}

		System.out.print(fmtHeader);

		for (ElfSymbol symbol : symbolTable.getSymbols()) {
			int sectionIndex = symbol.getSectionIndex();
			if (sectionIndex == ElfSectionConstants.SHN_XINDEX) {
				sectionIndex = symbol.getExtendedSectionIndex();
			}

			System.out.format(fmt, symbol.getSymbolTableIndex(), symbol.getValue(),
				symbol.getSize(),
				SYMBOL_TYPE.getOrDefault(symbol.getType(), unknownHex(symbol.getType())),
				SYMBOL_BIND.getOrDefault(symbol.getBind(), unknownHex(symbol.getBind())),
				SYMBOL_VISIBILITY.getOrDefault(symbol.getVisibility(),
					unknownHex(symbol.getVisibility())),
				sectionIndex > 0 ? Integer.toString(sectionIndex) : "UND",
				symbol.getNameAsString());
		}
	}

	private final static String SYMBOL_TABLE_SECTION_HEADER =
		"\nSymbol table '%s' contains %d entries:\n";

	public static void displaySymbolTables(ElfFile elf) {
		for (ElfSection section : elf
				.getSections(e -> e.getType() == ElfSectionConstants.SHT_SYMTAB ||
					e.getType() == ElfSectionConstants.SHT_DYNSYM)) {
			ElfSymbolTable symbolTable = elf.getSymbolTable(section);

			System.out.format(SYMBOL_TABLE_SECTION_HEADER, section.getNameAsString(),
				symbolTable.getSymbols().length);

			displaySymbolTable(elf, symbolTable);
		}
	}

	private final static String SYMBOL_TABLE_DYNAMIC =
		"\nSymbol table for image contains %d entries:\n";

	public static void displayDynamicSymbolTable(ElfFile elf) {
		ElfSymbolTable symbolTable = elf.getDynamicSymbolTable();
		System.out.format(SYMBOL_TABLE_DYNAMIC, symbolTable.getSymbols().length);

		displaySymbolTable(elf, symbolTable);
	}

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmd;

		try {
			cmd = new DefaultParser().parse(OPTIONS, args);
		}
		catch (ParseException e) {
			formatter.printHelp("readelf", OPTIONS);
			return;
		}

		if (!cmd.hasOption(OPT_WIDE)) {
			System.err.println("Wide output (-W/--wide) is mandatory.");
			return;
		}

		for (String path : cmd.getArgList()) {
			try {
				File file = new File(path);
				ByteProvider provider = new FileByteProvider(file, null, AccessMode.READ);
				Consumer<String> errorConsumer = e -> System.err.println(e);

				ElfFile elf = new ElfFile(provider, errorConsumer);

				if (cmd.hasOption(OPT_FILE_HEADER)) {
					displayFileHeader(elf);
				}

				if (cmd.hasOption(OPT_SECTION_HEADERS) || cmd.hasOption(OPT_SECTIONS)) {
					if (elf.getSections().isEmpty()) {
						System.out.print("\nThere are no sections in this file.\n");
					}
					else {
						displaySectionHeaders(elf);
					}
				}

				if (cmd.hasOption(OPT_PROGRAM_HEADERS) || cmd.hasOption(OPT_SEGMENTS)) {
					if (elf.getSegments().isEmpty()) {
						System.out.print("\nThere are no program headers in this file.\n");
					}
					else {
						if (!cmd.hasOption(OPT_FILE_HEADER)) {
							displayProgramHeadersNoFileHeadersSummary(elf);
						}

						displayProgramHeaders(elf);
						displaySectionToSegmentMapping(elf);
					}
				}

				if (cmd.hasOption(OPT_SYMBOLS)) {
					if (cmd.hasOption(OPT_USE_DYNAMIC)) {
						if (elf.getDynamicSymbolTable() == null) {
							System.out.print(
								"\nDynamic symbol information is not available for displaying symbols.\n");
						}
						else {
							displayDynamicSymbolTable(elf);
						}
					}
					else {
						if (elf.getSections(e -> e.getType() == ElfSectionConstants.SHT_SYMTAB ||
							e.getType() == ElfSectionConstants.SHT_DYNSYM).isEmpty()) {
							System.out.print("\nThere are no symbol tables in this file.\n");
						}
						else {
							displaySymbolTables(elf);
						}
					}
				}
			}
			catch (Exception e) {
				System.err.println("readelf: Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
