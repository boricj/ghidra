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

package ghidra.app.util.bin.format.unixaout;

/**
 * Represents the content of a single entry in the relocation table format used
 * by the UNIX a.out executable.
 */
public class UnixAoutRelocationTableEntry {
    public long address;
    public long symbolNum;
    public boolean pcRelativeAddressing;
    public byte pointerLength;
    public boolean extern;
    public boolean baseRelative;
    public boolean jmpTable;
    public boolean relative;
    public boolean copy;

    /**
     * 
     * @param address First of the two words in the table entry (a 32-bit address)
     * @param flags   Second of the two words in the table entry (containing several
     *                bitfields)
     */
    public UnixAoutRelocationTableEntry(long address, long flags, boolean bigEndian) {
        this.address = (0xFFFFFFFF & address);

        if (bigEndian) {
            this.symbolNum = ((flags & 0xFFFFFF00) >> 8);
            this.pcRelativeAddressing = ((flags & 0x80) != 0);
            this.pointerLength = (byte) (1 << ((flags & 0x60) >> 5));
            this.extern = ((flags & 0x10) != 0);
            this.baseRelative = ((flags & 0x8) != 0);
            this.jmpTable = ((flags & 0x4) != 0);
            this.relative = ((flags & 0x2) != 0);
            this.copy = ((flags & 0x1) != 0);
        } else {
            this.symbolNum = (flags & 0x00FFFFFF);
            final byte hibyte = (byte) ((flags & 0xFF000000) >> 24);
            this.pcRelativeAddressing = ((hibyte & 0x01) != 0);
            this.pointerLength = (byte) (1 << ((hibyte & 0x06) >> 1));
            this.extern = ((hibyte & 0x08) != 0);
            this.baseRelative = ((hibyte & 0x10) != 0);
            this.jmpTable = ((hibyte & 0x20) != 0);
            this.relative = ((hibyte & 0x40) != 0);
            this.copy = ((hibyte & 0x80) != 0);
        }
    }
}
