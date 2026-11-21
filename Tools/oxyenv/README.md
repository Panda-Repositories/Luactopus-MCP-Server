# Oxygen OxyEnv Native Host v3.48

v0.16 loads the real L3 core inside the native Luau VM.

The native host injects `__RADIUM_HOST` with:

- `process.args`
- filesystem operations
- `luau.load`
- a native C-forwarder binder
- explicit network/serde placeholders for now

The included `radium.lua` keeps L3's implementation semantics but wraps
detector-sensitive functions with real C closures supplied by the host.

That means `UDim2.new`, for example, still executes L3's UDim2 implementation,
but the function exposed to the target script is genuinely a C closure.

## Build

From your Visual Studio Build Tools developer shell:

```cmd
rmdir /s /q build
cmake -S . -B build -G Ninja
cmake --build build
```

## Run L3

```cmd
.\build\radium-host.exe .\radium.lua .\input.lua .\output.lua
```

Profile options still go after input/output:

```cmd
.\build\radium-host.exe .\radium.lua .\input.lua .\output.lua ^
  --username Player ^
  --display-name Player ^
  --user-id 1 ^
  --place-id 1818 ^
  --game-id 6767 ^
  --place-version 1
```

## Native-forwarded functions in v0.16

- `UDim2.new`
- `Random.new`
- `task.spawn`
- `task.defer`
- `task.delay`
- `task.wait`
- `task.cancel`
- `RunService.IsStudio`
- `RunService.IsClient`
- `RunService.IsServer`
- `EnumType.FromName`
- `EnumType.FromValue`
- `Instance.new`
- `Instance.IsA`
- `Instance.Destroy`
- `Instance.GetChildren`
- `DataModel.GetService`

These are real host C closures that forward into the actual L3 implementation.
`debug.info` is not patched or falsified.

## Native HTTP

On Windows, the native host now exposes a WinHTTP-backed request bridge. This powers
API-dump refreshes, `game:HttpGet`, `HttpService:GetAsync`, `PostAsync`, `RequestAsync`,
and URL-fed `loadstring` loaders. JSON serde remains native through nlohmann/json.

## v0.16 compatibility fixes

- Vector2/Vector3 lowercase `x/y/z` component aliases
- Vector2/Vector3 `Angle`
- fuller `HumanoidStateType`, including `FallingDown = 0`
- `StarterGui` and `LogService` recognized as services in fallback mode
- additional common defaults/signals for Humanoid, GUI, BasePart, Lighting,
  UserInputService, Players, Stats, Fire, RodConstraint and DepthOfFieldEffect
- CatalogSearchParams creator fields
- SharedTable clone/cloneAndFreeze helpers
- DateTime formatting helpers

## v0.16

General compatibility fixes from the latest benchmark:

- GuiObject Position/Size correctly validate as UDim2 instead of Vector3
- Vector2/Vector3 FuzzyEq, Min and Max
- Random:NextUnitVector
- Humanoid:GetState
- SharedTable cloneAndFreeze + table.isfrozen support
- standard sandbox libraries are actually frozen when host table.freeze is available
- printidentity
- SunRaysEffect, Fire, DragDetector, TextLabel, Frame and BasePart defaults
- Lighting.GlobalShadows
- UserInputService.MouseIconEnabled
- Stats.PhysicsStepTime
- CatalogSearchParams.Limit
- fallback ActionType enum

The Gold.cc anti-environment sample is not special-cased; this build only changes
general runtime semantics.

## v0.16

Preserves all v0.5/v3.20 fixes and restores local API dump parsing.

- Native JSON decode/encode via nlohmann/json
- Reads `--api-cache`, `radium_api_dump.json`, or `api_dump.json`
- Prints API decode failures instead of silently hiding them
- Adds MarketplaceItemPurchaseStatus fallback:
  - AlreadyOwned = 3
  - QuantityLimitExceeded = 5
  - NotForSale = 7
- Fallback enum items augment missing API-dump entries
- Includes `test_api_dump_json.luau`

Put `api_dump.json` or `radium_api_dump.json` beside `CMakeLists.txt`.

## v0.16 — native EncodingService Zstd

This version preserves every compatibility fix from v0.1 through v0.6 and adds
the missing native decompression stage used by packed/obfuscated loaders.

Added:
- libzstd v1.5.7 linked into `radium-host`
- `__RADIUM_HOST.serde.compress("Zstd", binary, level)`
- `__RADIUM_HOST.serde.decompress("Zstd", binary)`
- binary-safe Lua strings through `luaL_checklstring` / `lua_pushlstring`
- decompression support for known and unknown frame content sizes
- 256 MiB decompressed-payload safety limit
- `EncodingService:CompressBuffer` and `:DecompressBuffer` now use real Zstd
- `test_zstd_loadstring.luau` verifies:
  1. buffer -> Zstd -> buffer round trip
  2. decompressed source -> `loadstring`
  3. execution of the compiled second stage

Build cleanly after extracting because CMake now fetches zstd.

## v0.16

Fixes a regression found by the native Zstd smoke test:

- `EncodingService` is now always registered as a valid Roblox service even when
  the local API dump does not tag/expose it as a service.
- Adds a fallback `Enum.CompressionAlgorithm` with `Zstd`.
- Includes `<zstd_errors.h>` for current libzstd error-code declarations.
- Replaces the Zstd smoke test with a stronger service + round-trip + loadstring test.
- Includes `test_encoding_service.luau` for a fast service-only check.

This preserves all previous Project Radium compatibility patches.

## v0.16 — truthful native integrity surface

Preserves all v0.1-v0.8 fixes.

New:
- native `iscclosure` backed by Luau's real C-function check
- native `isfunctionhooked`; returns false because Radium installs no hooks
- native `checkcaller`; target execution is not a privileged host call
- native `newcclosure` and `clonefunction` forwarding closures
- stable native forwarding for `getgenv`, `getrenv`, `getreg`, `getfenv`,
  `setfenv`, `loadstring`
- stable native forwarding for sandboxed filesystem APIs
- stable native `game.HttpGet` / `game.HttpGetAsync`
- stable native HttpService GetAsync/PostAsync/RequestAsync surfaces
- generic API-dump function members are now cached and exposed through real
  C forwarding closures instead of returning a fresh Lua closure each lookup
- no fake hook state, debug-hook hiding, or debug.info spoofing

`hookfunction`, `hookmetamethod`, `getgc`, and namecall mutation APIs remain
unimplemented rather than being faked.

## v0.16

Fixes the integrity-check regression where `rawget` and `rawset` were still
Lua closures because Radium wrapped them for Instance argument validation.

They now remain semantically identical but are exposed through genuine native
C forwarding closures. `rawequal` and `rawlen` already use the native Luau
builtins directly.

Also extends native debug-name mapping for the previously added C-forwarded
environment and HTTP functions.

## v0.16 — CoreGui hierarchy

Preserves all previous fixes.

- Persistent CoreGui service through the normal service cache.
- Nested CoreGui hierarchy with more than 10 descendants.
- game.CoreGui and game:GetService("CoreGui") resolve to the same service.
- GetChildren/GetDescendants use the normal instance tree.
- Includes test_coregui.luau.

## v0.16 — EditableMesh stateful surface

Preserves all earlier fixes and expands EditableMesh from the minimal
vertex/triangle stub into a stateful compatibility implementation.

Added:
- UV, normal and color IDs + getters/setters/alpha
- face UV/normal/color arrays
- vertex-face corner attributes
- adjacency and vertex-face queries
- center/size/closest-vertex/sphere queries
- local raycast / closest-point surface results
- batch add/get/set/remove helpers
- merge/remove/clear helpers
- bone creation, lookup, mutation, parent/virtual state
- vertex skinning bone/weight storage
- fallback Enum.MeshAttribute
- removes the noisy `-- missing global: ...` output line entirely

Includes `test_editable_mesh.luau`.

## v0.16 — docs-driven Roblox compatibility pass

Based on Roblox's open-source creator-docs and open-source Luau/Roblox tooling.

Added/fixed:
- EditableMesh:ResetNormal
- EditableMesh:GetFacesWithAttribute
- EditableMesh:GetFacesWithColor
- documented GetBoneParent() = 0 for root bones
- documented FindClosestPointOnSurface return order
- BatchSetValues handling for vertex/normal/UV/color values
- AssetService:CreateEditableMesh receiver/options validation
- CreateEditableMesh always returns FixedSize=false for empty meshes
- extra EditableMesh regression test

Anti-env/anti-tamper projects were used only as compatibility test inspiration;
no detector-specific debug/hook spoofing was added.

## v0.16 — NeoSnapp detector compatibility pass

Implements the supplied checks through persistent runtime behavior, not string
matching or detector-specific bypasses.

Added:
- LocalizationTable SetEntries/GetEntries/GetTranslator
- Translator LocaleId/Translate
- LocalPlayer.PlayerGui
- PlayerGui:GetGuiObjectsAtPosition with nested GUI geometry, visibility and ZIndex
- GuiObject AbsolutePosition / AbsoluteSize calculations
- ContentProvider GetAssetFetchStatus/GetAssetFetchStatusChangedSignal
- stateful PreloadAsync transitions and callbacks
- SoundService ListenerType/ListenerCFrame/ListenerObject/GetListener/GetMixerTime
- MarketplaceService:GetProductInfoAsync with stable cache and network-first lookup
- PolicyService:GetPolicyInfoForPlayerAsync with stable policy dictionary
- fallback ListenerType and InfoType enums
- every supplied NeoSnapp check copied in as a regression script

Existing EditableMesh behavior from v0.13 is preserved.

## v0.16 — register-pressure fix + permanent core filename

- Core file is now permanently named `radium.lua`.
- Wrapped recently-added service compatibility setup in short-lived `do ... end`
  scopes so their setup locals do not remain live across the whole Radium chunk.
- Moved LocalizationTable backing state into the existing `proxyState` storage.
- This specifically fixes Luau's `Out of local registers ... exceeded limit 200`
  compile failure near `safeSetfenv`.
- All prior compatibility work is preserved.
- Future versions should keep the filename `radium.lua`; only the internal version
  string changes.

## v0.16 — clean output + failed-test fixes

The core filename remains permanently `radium.lua`.

- Property reads/writes no longer spam generated output by default.
- `--trace-properties` restores the old verbose property trace when debugging.
- Fixed PlayerGui hit testing: `instanceChildren` is a set, so traversal now uses
  `pairs` instead of `ipairs`.
- Hidden GuiObjects are excluded and overlapping GuiObjects are sorted by ZIndex.
- EditableMesh `RaycastLocal` now performs triangle intersection instead of
  returning a canned hit.
- EditableMesh `FindClosestPointOnSurface` now computes an actual closest point
  and barycentric coordinates.
- EditableMesh `RemoveUnused` now removes unreferenced mesh attributes.
- Exact newly supplied PlayerGui and EditableMesh failures are included as
  regression tests.

## v0.18 — datatype + physics-step fixes

Core remains `radium.lua`.

- Added Vector2/Vector3 scalar division, fixing GUI expressions such as
  `AbsoluteSize / 2`.
- Canonicalized Color3 values so equal RGB values have stable userdata identity;
  this fixes equality checks used by EditableMesh GetColor/SetColor.
- Added stateful RunService:GetPhysicsStepId with an initial current step id of 1.
- Bound GetPhysicsStepId through the native forwarding layer.
- Added exact regression tests for the new NeoSnapp physics-step check plus
  focused Vector2 division and Color3 equality tests.

## v0.18 — value semantics, GUI hit testing, and useful tracing

Core filename remains permanently `radium.lua`.

- Fixed CFrame value equality for the translation-only CFrame model used by
  Radium. EditableMesh bone CFrame mutation now compares by stable value.
- Reworked PlayerGui:GetGuiObjectsAtPosition to traverse the real hierarchy,
  handle ScreenGui.Enabled / GuiObject.Visible, calculate geometry recursively,
  and order overlapping results by ZIndex.
- Added explicit GuiObject-class fallback coverage so hit testing is not
  dependent on quirks in a particular API-dump inheritance chain.
- Property reads remain quiet.
- Target-script property writes are now reconstructed in output.
- Internal bootstrap assignments stay quiet.
- `repr()` now renders Vector2, Vector3, Color3, CFrame, UDim/UDim2 and small
  tables as readable Luau expressions.
- EditableMesh method calls are traced with their real arguments while the
  target script is executing.
- No detector-string matching or fabricated PASS paths were added.

## v0.19 — sandbox directory race fix

Core remains `radium.lua`.

- Native `writeDir` is idempotent.
- Existing directories are treated as success.
- Handles concurrent Radium processes racing to create `radium_l3_fs`.
- Bootstrap calls `writeDir` directly instead of doing check-then-create.
- Real filesystem failures now include the OS error message.

## v0.20 — modern runtime compatibility

Core remains `radium.lua`.

- Added a stateful Path2D implementation including GetMaxControlPoints() = 100,
  control-point mutation, length and basic curve-position sampling.
- Added InputAction state, events, Fire/GetState behavior.
- Added UserInputService navigation-gamepad state and TextBox focus flow.
- Added sandbox-only setclipboard/getclipboard state; this does not touch the
  host OS clipboard.
- Added Animator loaded-track storage and GetTrackByAnimationId().
- Added MaterialService:GetMaterialVariant() using actual descendants.
- Added AudioEmitter/AudioListener interaction-group audibility.
- Added Terrain SetCell/GetCell round-tripping.
- Fixed LocalizationTable GetEntries backing state and added Translator:FormatByKey
  with named/numbered token replacement.
- No detector-string matching or fabricated PASS behavior was added.

## v0.21 — missing global compatibility

Core remains `radium.lua`.

- Added `Game` alias and a real Instance-backed `script`/PlayerScripts context.
- Upgraded CFrame from translation-only storage to a 3x3 rotation matrix model.
- Added CFrame lookAt/lookAlong, Euler constructors, axis-angle,
  fromRotationBetweenVectors, fromMatrix, rotation vectors, transforms,
  multiplication, inverse and component access.
- Added DateTime.fromLocalTime/fromUniversalTime.
- Added Font.fromEnum/fromId.
- Added BrickColor.Random.
- Added Content with fromUri/fromObject/none and ContentSourceType state.
- No detector-specific string matching or forced PASS results.

## v0.22 — bootstrap regression fix

- Fixed the v0.20/v0.21 class-validation regression that could reject
  `Workspace` before the target script even started.
- Supplemental classes such as Path2D/InputAction no longer make Radium think
  a complete API dump is loaded.
- Added real Vector3:Cross(), required by the new CFrame rotation constructors.
- Added ContentSourceType and Font enum fallbacks for no-dump operation.

## v0.23 — Path2D state/curve fix

- Fixed `SelectedControlPointData`: an empty Path2D now returns a default
  Path2DControlPoint instead of nil, matching Roblox behavior.
- Selection follows `SelectedControlPoint` and clamps after control-point edits.
- Added Path2D Transparency, GetSegmentCount, GetBoundingRect,
  GetTangentOnCurve and GetTangentOnCurveArcLength.
- Replaced linear Path2D sampling with cubic Bézier evaluation using each
  Path2DControlPoint's left/right tangents.
- Added approximate arc-length sampling and length calculation.
- Path2D Color3 default is now black and Thickness/Transparency are clamped.

## v0.24 — Path2D dispatch/value fix

- Fixed method dispatch so class-specific implementations win over generic Instance handlers.
- Removed duplicate generic Path2D handlers that maintained stale control-point state.
- UDim and UDim2 now use canonical immutable value semantics.
- Added `test_path2d_debug_v024.luau`.
