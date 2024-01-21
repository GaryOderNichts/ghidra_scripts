//Find Wii IOS syscalls via undefined instruction
//@author rw, GaryOderNichts
//@category ARM
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Vector;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

public class GhidraWiiSyscallUDF extends GhidraScript {
    private HashMap<Integer, FunctionDefinitionDataType> Syscalls = new HashMap<Integer, FunctionDefinitionDataType>();

	protected final FunctionDefinitionDataType parseSignature(String signature) {
		FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
		try {
			return parser.parse(null, signature);
		} catch (Exception e) {
			println("Failed to parse " + signature);
		}
		return null;
	}

	protected void applyFunctionDefinition(Function fn, FunctionDefinitionDataType definition) {
		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(fn.getEntryPoint(), definition,
			SourceType.USER_DEFINED, true, true);
		runCommand(cmd);
	}

    @Override
    protected void run() throws Exception {
        File file = askFile("Please specify a syscall definition file", "Select syscalls definition");
        println("Using " + file.getName() + " as syscalls description file");

        BufferedReader br = new BufferedReader(new FileReader(file));
        for (String line = br.readLine(); line != null; line = br.readLine()) {
        	String[] fields = line.split(":");
            Syscalls.put(Integer.decode(fields[0]), parseSignature(fields[1]));
        }
    
    	Memory memory = currentProgram.getMemory();
        SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(true);
		while (iter.hasNext()) {
			Symbol symbol = iter.next();

			if (monitor.isCancelled()) {
				break;
			}
			
			Address instrAddr = symbol.getAddress();

			try {
				int instrVal = memory.getInt(instrAddr, true);
				int instr = instrVal & 0xffffe01f;
				if (instr != 0xe6000010) {
					continue;
				}

				int sysnum = (instrVal >>> 5) & 0xff;
				if (!Syscalls.containsKey(sysnum)) {
					continue;
				}

				FunctionDefinitionDataType definition = Syscalls.get(sysnum);
				if (definition == null) {
					continue;
				}

				String fnname = definition.getName();

				Function fn = currentProgram.getFunctionManager().getFunctionAt(instrAddr);
				if (fn != null) {
					println("Applying signature to: " + fn.getName() + " -> " + fnname);
					applyFunctionDefinition(fn, definition);
				} else {
					println("Renaming: " + symbol.getName() + " -> " + fnname);
					symbol.setName(fnname, SourceType.USER_DEFINED);
				}

				// try to also rename thunks for thumb
				if (symbol.hasReferences()) {
					Address fnAddress = symbol.getReferences()[0].getFromAddress();
					fn = currentProgram.getFunctionManager().getFunctionAt(fnAddress);
					if (fn != null) {
						println("Applying signature to: " + fn.getName() + " -> " + fnname);
						applyFunctionDefinition(fn, definition);
					}
				}
			} catch(Exception e) {}
		}
    }
}
