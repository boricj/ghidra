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

/**
 * Represents the content of a single entry in the symbol table format used by
 * the UNIX a.out executable.
 */
public class UnixAoutSymbolTableEntry {

    enum SymbolType { N_UNDF, N_ABS, N_TEXT, N_DATA, N_BSS, N_FN, N_EXT, UNKNOWN }

    public long nameStringOffset;
    public String name;
    public SymbolType type;
    public byte otherByte;
    public short desc;
    public long value;
    public boolean isExt;

    public UnixAoutSymbolTableEntry(long nameStringOffset, byte typeByte, byte otherByte,
                                    short desc, long value) {
        this.nameStringOffset = nameStringOffset;
        this.otherByte = otherByte;
        this.desc = desc;
        this.value = value;
        this.isExt = (typeByte & 1) == 1;

        switch (typeByte & 0xfe) {
        case 0:
            type = SymbolType.N_UNDF;
            break;
        case 2:
            type = SymbolType.N_ABS;
            break;
        case 4:
            type = SymbolType.N_TEXT;
            break;
        case 6:
            type = SymbolType.N_DATA;
            break;
        case 8:
            type = SymbolType.N_BSS;
            break;
        default:
            type = SymbolType.UNKNOWN;
        }
    }
}
