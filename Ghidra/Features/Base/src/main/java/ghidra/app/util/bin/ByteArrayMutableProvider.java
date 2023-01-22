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
package ghidra.app.util.bin;

import java.io.File;
import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class ByteArrayMutableProvider implements MutableByteProvider {
	private byte[] data;

	public ByteArrayMutableProvider() {
		data = new byte[0];
	}

	public ByteArrayMutableProvider(byte[] bytes) {
		data = Arrays.clone(bytes);
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	@Override
	public long length() throws IOException {
		return data.length;
	}

	@Override
	public boolean isValidIndex(long index) {
		return index < data.length;
	}

	@Override
	public void close() throws IOException {
	}

	@Override
	public byte readByte(long index) throws IOException {
		return data[(int) index];
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		return Arrays.copyOfRange(data, (int) index, (int) (index + length));
	}

	@Override
	public void writeByte(long index, byte value) throws IOException {
		byte[] values = new byte[] { value };
		writeBytes(index, values);
	}

	@Override
	public void writeBytes(long index, byte[] values) throws IOException {
		if (index + values.length >= data.length) {
			data = Arrays.copyOf(data, (int) (index + values.length));
		}

		System.arraycopy(values, 0, data, (int) index, values.length);
	}
}