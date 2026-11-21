# Goofyscator V11 Node.js recovery toolkit — unified `deobf.js`

**One command. One output name. No separate trace command.** All existing transport inspection files, both Lua probes, original five depth samples, and `cli.js` remain included. Your new obfuscated GUI sample is at `samples/gui-depth3.lua`.

## Windows / Discord bot usage

```cmd
node deobf.js input.lua -o deobfuscated.lua
```

You can also omit `-o` and it writes `deobfuscated.lua` in the current directory. The CLI returns exit code **0 once it successfully writes the output file**, even when recovery is incomplete. This allows a bot that requires an output file to continue; read the header comments to determine recovery status.

Uses Lua 5.3+ or Lua 5.4 (including your Lua 5.4.6), without needing `bit32` installed. If Lune is on PATH, the default `auto` mode also attempts the Luau host-effect tracer, and chooses whichever trace contains more observed statements. The Lune path has **not** been validated against the protected GUI sample and may be incomplete. No extra npm packages are required.

Optional flags:

```cmd
node deobf.js input.lua -o deobfuscated.lua --engine lua --lua "C:\Users\Bitra\AppData\Local\Programs\Lua\bin\lua.exe"
node deobf.js input.lua -o deobfuscated.lua --engine lune --lune "C:\path\to\lune.exe"
node deobf.js --batch samples/depth-1.lua samples/depth-2.lua -o recovered
```

Batch mode creates `recovered/depth-1/deobfuscated.lua`, etc.

## Output behavior

- **Trace available:** The requested `deobfuscated.lua` contains observed print/warn calls and, if reached and recognized, Roblox GUI instance/property operations and connected callbacks. It starts with `RECOVERY STATUS: PARTIAL DYNAMIC TRACE`. In the provided new GUI sample, the Lua 5.4 execution harness currently reaches only `print("Hello World")` — it does **not** recover the rest of the GUI or the encrypted strings. The earlier five samples reach two prints.
- **No trace available / no Lua or Lune:** The same requested `deobfuscated.lua` is still written, but it contains the original protected Lua code preceded by `RECOVERY STATUS: INCOMPLETE`. It is **not** deobfuscated, and it isn't described as such.
- **Unreadable input / unwritable destination:** The command reports an error and exits nonzero. It refuses to overwrite the input itself.

This is **not** a full Goofyscator V11 VM devirtualizer, and it cannot reconstruct unexecuted branches, unobserved GUI callbacks, source variable names, or encrypted constants merely from a partial execution trace. No source is invented from the separately supplied reference script.

The included `lune_probe.luau` captures effects in a simulated Roblox environment. Only execute trusted samples, ideally inside an isolated OS container/VM; neither mock runtime is a security-grade sandbox. The original `cli.js` + `vm.js` remain available for VM inspection:

```cmd
node cli.js --vm --lua lua -o parsed samples/depth-1.lua
```

## Tests

```cmd
node test.js
node test-output.js
```

Test results here: all five V11 transport tests passed; the output tests confirmed the CLI creates `deobfuscated.lua` for the six samples, and it also creates an explicitly marked fallback output when no supported runtime is present. The genuine protected sample in Lune has not been run in this environment.
