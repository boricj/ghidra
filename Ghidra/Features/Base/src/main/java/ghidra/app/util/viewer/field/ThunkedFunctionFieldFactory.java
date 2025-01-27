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
package ghidra.app.util.viewer.field;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ThunkedFunctionFieldLocation;

/**
  *  Generates Thunked Function Fields.
  */
public class ThunkedFunctionFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Thunked-Function";

	/**
	 * Default Constructor
	 */
	public ThunkedFunctionFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public ThunkedFunctionFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	private Color getThunkedFunctionNameColor(Function thunkedFunction) {
		if (!thunkedFunction.isExternal()) {
			return ListingColors.SEPARATOR;
		}
		ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
		String libName = externalLocation.getLibraryName();
		if (Library.UNKNOWN.equals(libName)) {
			return ListingColors.EXT_REF_UNRESOLVED;
		}
		ExternalManager externalManager = thunkedFunction.getProgram().getExternalManager();
		String path = externalManager.getExternalLibraryPath(libName);
		if (path == null || path.length() == 0) {
			return ListingColors.EXT_REF_UNRESOLVED;
		}
		return ListingColors.EXT_REF_RESOLVED;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}
		Function f = (Function) obj;
		Function thunkedFunction = f.getThunkedFunction(false);
		if (thunkedFunction == null) {
			return null;
		}

		ArrayList<FieldElement> textElements = new ArrayList<>();
		AttributedString as;
		int elementIndex = 0;

		as = new AttributedString("Thunked-Function: ", ListingColors.SEPARATOR, getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		String functionName = simplifyTemplates(thunkedFunction.getName(true));
		as = new AttributedString(functionName, getThunkedFunctionNameColor(thunkedFunction),
			getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		return ListingTextField.createSingleLineTextField(this, proxy,
			new CompositeFieldElement(textElements), startX + varWidth, width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			Function thunkedFunction = function.getThunkedFunction(false);
			return new ThunkedFunctionFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				thunkedFunction != null ? thunkedFunction.getEntryPoint() : null, col);
		}

		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof ThunkedFunctionFieldLocation) {
			ThunkedFunctionFieldLocation thunkFunctionLoc = (ThunkedFunctionFieldLocation) loc;
			return new FieldLocation(index, fieldNum, 0, thunkFunctionLoc.getCharOffset());
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Function.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions pDisplayOptions, ToolOptions fieldOptions) {
		return new ThunkedFunctionFieldFactory(formatModel, provider, pDisplayOptions,
			fieldOptions);
	}
}
