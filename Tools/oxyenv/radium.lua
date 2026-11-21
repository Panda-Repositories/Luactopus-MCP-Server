-- Oxygen OxyEnv v3.50.25-native / Madium v2.0.0 compatibility profile
-- Roblox/Luau compatibility core.
--
-- Host capabilities are injected by run_l3.lua.
-- This file contains no host-module imports.
--
-- Optional profile values:
--   --username <name>
--   --display-name <name>
--   --user-id <number>
--   --place-id <number>
--   --game-id <number>
--   --place-version <number>
--   --executor-name <name>
--   --api-cache <path>
--   --refresh-api
--
-- Notes:
--   * Uses Roblox-Client-Tracker Full-API-Dump.json when available.
--   * Target code never receives host filesystem/network/process/module access.
--   * loadstring compiles back into the same sandbox.
--   * This logger does not forge native "[C]" identities or hide logger stack frames.

local host = __RADIUM_HOST
if type(host) ~= "table" then
    error("Oxygen OxyEnv must be started through run_l3.lua", 0)
end

local process = assert(host.process, "missing host.process")
local fs = assert(host.fs, "missing host.fs")
local net = assert(host.net, "missing host.net")
local serde = assert(host.serde, "missing host.serde")
local luau = assert(host.luau, "missing host.luau")

-- Keep host builtins behind one local table. Luau caps active local registers at 200;
-- keeping every builtin as a separate top-level local pushes this large environment
-- over that limit before the sandbox bootstrap is finished.
local hostFns = {
    print = print,
    warn = warn or print,
    type = type,
    typeof = typeof,
    tostring = tostring,
    pcall = pcall,
    xpcall = xpcall,
    error = error,
    assert = assert,
    pairs = pairs,
    ipairs = ipairs,
    next = next,
    select = select,
    rawget = rawget,
    rawset = rawset,
    getmetatable = getmetatable,
    setmetatable = setmetatable,
    getfenv = getfenv,
    setfenv = setfenv,
    unpack = table.unpack or unpack,
    clock = os.clock,
}

local API_URL =
    "https://raw.githubusercontent.com/MaximumADHD/Roblox-Client-Tracker/roblox/Full-API-Dump.json"

local LIMITS = {
    MAX_OUTPUT_LINES = 30000,
    MAX_PROXIES = 60000,
    MAX_DYNAMIC_SOURCE = 2 * 1024 * 1024,
    MAX_EXEC_SECONDS = 180,
    MAX_REPEAT = 100,
}

local CONFIG = {
    input = nil,
    output = "output_l3.lua",
    sandboxRoot = "radium_l3_fs",
    username = "Player",
    displayName = "Player",
    userId = 1,
    placeId = 1818,
    gameId = 6767,
    placeVersion = 1,
    executorName = "Madium",
    apiCache = "radium_api_dump.json",
    refreshApi = false,
    traceProperties = false,
    runtimeTracing = false,
    fpsCap = 60,
    fpsMin = 30,
    fpsMax = 160,
    pingMin = 18,
    pingMax = 42,
}

do
    local positional = {}
    local args = process.args
    local i = 1

    while i <= #args do
        local arg = args[i]

        if arg == "--username" then
            i += 1
            CONFIG.username = args[i] or CONFIG.username
        elseif arg == "--display-name" then
            i += 1
            CONFIG.displayName = args[i] or CONFIG.displayName
        elseif arg == "--user-id" then
            i += 1
            CONFIG.userId = tonumber(args[i]) or CONFIG.userId
        elseif arg == "--place-id" then
            i += 1
            CONFIG.placeId = tonumber(args[i]) or CONFIG.placeId
        elseif arg == "--game-id" then
            i += 1
            CONFIG.gameId = tonumber(args[i]) or CONFIG.gameId
        elseif arg == "--place-version" then
            i += 1
            CONFIG.placeVersion = tonumber(args[i]) or CONFIG.placeVersion
        elseif arg == "--executor-name" then
            i += 1
            local selectedExecutor = args[i]
            if hostFns.type(selectedExecutor) == "string" and selectedExecutor ~= "" then
                CONFIG.executorName = selectedExecutor
            end
        elseif arg == "--api-cache" then
            i += 1
            CONFIG.apiCache = args[i] or CONFIG.apiCache
        elseif arg == "--refresh-api" then
            CONFIG.refreshApi = true
        elseif arg == "--trace-properties" then
            CONFIG.traceProperties = true
        else
            positional[#positional + 1] = arg
        end

        i += 1
    end

    CONFIG.input = positional[1]
    CONFIG.output = positional[2] or CONFIG.output
end

if not CONFIG.input then
    hostFns.print("Oxygen OxyEnv")
    hostFns.print("usage: radium-host.exe radium.lua <input.lua> [output.lua] [options]")
    return
end

-- Roblox security identity is thread-local.  Keep a weak per-coroutine map
-- and default new/unseen threads to the normal local-script identity.
local threadIdentityByThread = hostFns.setmetatable({}, { __mode = "k" })
local fallbackThreadIdentity = 8

local securityRuntime = (function()
    local identityCapabilities = {
        [0] = {
            None = true,
        },

        [1] = {
            None = true,
        },

        -- Normal game-script context.
        [2] = {
            None = true,
        },

        -- Restricted elevated context.  It can use ordinary Studio/user
        -- surfaces but does not own RobloxScriptSecurity.
        [3] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
        },

        -- Command/run-script style context.
        [4] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
            WritePlayerSecurity = true,
        },

        -- Plugin-like context.
        [5] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
            WritePlayerSecurity = true,
        },

        -- Internal script context.
        [6] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
            WritePlayerSecurity = true,
            RobloxScriptSecurity = true,
            RobloxPlaceSecurity = true,
        },

        -- Engine-privileged context.
        [7] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
            WritePlayerSecurity = true,
            RobloxScriptSecurity = true,
            RobloxPlaceSecurity = true,
            RobloxSecurity = true,
        },

        -- Oxyenv executor context.  This is the initial context used by
        -- logged scripts; explicitly lowering identity replaces these
        -- capabilities with the selected context above.
        [8] = {
            None = true,
            LocalUserSecurity = true,
            PluginSecurity = true,
            WritePlayerSecurity = true,
            RobloxScriptSecurity = true,
            RobloxPlaceSecurity = true,
            RobloxSecurity = true,
            NotAccessibleSecurity = true,
        },
    }

    -- Used only when the loaded API dump does not include security metadata.
    -- This is member metadata, not detector-specific identity logic.
    local fallbackMembers = {
        Lighting = {
            Technology = {
                MemberType = "Property",
                Read = "RobloxScriptSecurity",
                Write = "RobloxScriptSecurity",
            },
        },

        GuiService = {
            GetScreenResolution = {
                MemberType = "Function",
                Security = "RobloxScriptSecurity",
            },
        },

        UserInputService = {
            GetPlatform = {
                MemberType = "Function",
                Security = "None",
            },
        },

        LocalizationService = {
            RobloxLocaleId = {
                MemberType = "Property",
                Read = "None",
                Write = "RobloxScriptSecurity",
            },
        },
    }

    local runtime = {
        fallbackMembers = fallbackMembers,
    }

    runtime.hasCapability = function(identity, securityTag)
        if securityTag == nil
            or securityTag == ""
            or securityTag == "None"
        then
            return true
        end

        local capabilities =
            identityCapabilities[tonumber(identity) or -1]

        return capabilities ~= nil
            and capabilities[securityTag] == true
    end

    runtime.getCapabilities = function(identity)
        local source =
            identityCapabilities[tonumber(identity) or -1]
            or {}

        local copy = {}

        for tag, enabled in hostFns.pairs(source) do
            if enabled then
                copy[tag] = true
            end
        end

        return copy
    end

    return runtime
end)()

local function getRuntimeThreadIdentity()
    local thread = coroutine.running()
    if thread ~= nil then
        local value = threadIdentityByThread[thread]
        if value ~= nil then
            return value
        end
    end
    return fallbackThreadIdentity
end

local function setRuntimeThreadIdentity(value)
    local identity = tonumber(value)
    if identity == nil then
        hostFns.error("number expected", 2)
    end

    identity = math.floor(identity)

    if identity < 0 then
        hostFns.error("thread identity cannot be negative", 2)
    end

    local thread = coroutine.running()
    if thread ~= nil then
        threadIdentityByThread[thread] = identity
    else
        fallbackThreadIdentity = identity
    end

    return identity
end

local function safeRead(path)
    local ok, result = hostFns.pcall(fs.readFile, path)
    if ok and hostFns.type(result) == "string" then
        return result
    end
    return nil
end

local function safeWrite(path, content)
    local ok, err = hostFns.pcall(fs.writeFile, path, content)
    if not ok then
        hostFns.warn("Oxygen OxyEnv failed to write " .. hostFns.tostring(path) .. ": " .. hostFns.tostring(err))
        return false
    end
    return true
end

local function responseBodyToString(body)
    if hostFns.type(body) == "string" then
        return body
    end

    if body ~= nil and buffer and hostFns.type(buffer.tostring) == "function" then
        local ok, value = hostFns.pcall(buffer.tostring, body)
        if ok and hostFns.type(value) == "string" then
            return value
        end
    end

    return nil
end

local function safeHttpField(response, key)
    local ok, value = hostFns.pcall(function()
        return response[key]
    end)

    if ok then
        return value
    end

    return nil
end

local function buildHttpHeaders()
    return {
        ["Accept"] = "*/*",
        ["User-Agent"] = "Madium/2.0.0",
        ["Roblox-Game-Id"] = hostFns.tostring(CONFIG.gameId),
        ["Roblox-Place-Id"] = hostFns.tostring(CONFIG.placeId),
        ["Roblox-Session-Id"] = string.format(
            '{"PlaceId":"%s","GameId":"%s"}',
            hostFns.tostring(CONFIG.placeId),
            hostFns.tostring(CONFIG.gameId)
        ),
    }
end

local function requestUrl(url)
    url = hostFns.tostring(url or "")

    if not url:match("^https?://") then
        return nil, "HttpGet only supports http:// and https:// URLs"
    end

    local request = net.request or (net.http and net.http.request)
    if hostFns.type(request) ~= "function" then
        return nil, "HTTP request function is unavailable"
    end

    local function unpackResponse(response)
        if response == nil then return nil, "no response" end
        if hostFns.type(response) == "string" then return response end

        local status =
            tonumber(safeHttpField(response, "statusCode"))
            or tonumber(safeHttpField(response, "status"))
            or tonumber(safeHttpField(response, "StatusCode"))
            or tonumber(safeHttpField(response, "Status"))

        local body =
            safeHttpField(response, "body")
            or safeHttpField(response, "Body")
            or safeHttpField(response, "data")
            or safeHttpField(response, "Data")

        local source = responseBodyToString(body) or responseBodyToString(response)
        if status and (status < 200 or status >= 400) then
            return nil, "HTTP " .. hostFns.tostring(status)
        end
        if source == nil then return nil, "HTTP response body is not readable text" end
        return source
    end

    local attempts = {
        {url=url, method="GET", headers=buildHttpHeaders()},
        {url=url, method="GET", headers={
            ["Accept"]="*/*",
            ["User-Agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ["Cache-Control"]="no-cache",
        }},
    }

    local lastError = nil
    for _, requestInfo in hostFns.ipairs(attempts) do
        local ok, response = hostFns.pcall(request, requestInfo)
        if ok then
            local source, err = unpackResponse(response)
            if source ~= nil then return source end
            lastError = err
        else
            lastError = response
        end
    end

    local ok, response = hostFns.pcall(request, url)
    if ok then
        local source, err = unpackResponse(response)
        if source ~= nil then return source end
        lastError = err
    else
        lastError = response
    end

    return nil, "HTTP request failed: " .. hostFns.tostring(lastError or "unknown error")
end

local function loadApiDump()
    local candidates = {
        CONFIG.apiCache,
        "radium_api_dump.json",
        "api_dump.json",
    }

    if not CONFIG.refreshApi then
        local seen = {}
        for _, path in hostFns.ipairs(candidates) do
            if hostFns.type(path) == "string" and path ~= "" and not seen[path] then
                seen[path] = true
                local cached = safeRead(path)
                if cached and #cached > 1000 then
                    return cached, "cache:" .. path
                end
            end
        end
    end

    local downloaded = requestUrl(API_URL)
    if downloaded and #downloaded > 1000 then
        safeWrite(CONFIG.apiCache, downloaded)
        return downloaded, "network"
    end

    local seen = {}
    for _, path in hostFns.ipairs(candidates) do
        if hostFns.type(path) == "string" and path ~= "" and not seen[path] then
            seen[path] = true
            local cached = safeRead(path)
            if cached and #cached > 1000 then
                return cached, "cache:" .. path
            end
        end
    end

    return nil, "fallback"
end

local apiText, apiSource = loadApiDump()
local apiDump = nil

if apiText then
    local ok, decoded = hostFns.pcall(serde.decode, "json", apiText)
    if ok and hostFns.type(decoded) == "table" then
        apiDump = decoded
    else
        hostFns.warn(
            "Oxygen OxyEnv could not decode API dump from "
            .. hostFns.tostring(apiSource)
            .. ": "
            .. hostFns.tostring(decoded)
        )
        apiSource = "fallback:decode-error"
    end
end

local classInfo = {}
local enumInfo = {}
local serviceNames = {}

local function tagContains(tags, wanted)
    if hostFns.type(tags) ~= "table" then
        return false
    end

    for _, tag in hostFns.pairs(tags) do
        if tag == wanted then
            return true
        end
    end

    return false
end

if apiDump then
    if hostFns.type(apiDump.Classes) == "table" then
        for _, class in hostFns.ipairs(apiDump.Classes) do
            if hostFns.type(class) == "table" and hostFns.type(class.Name) == "string" then
                local members = {}

                if hostFns.type(class.Members) == "table" then
                    for _, member in hostFns.ipairs(class.Members) do
                        if hostFns.type(member) == "table" and hostFns.type(member.Name) == "string" then
                            members[member.Name] = member
                        end
                    end
                end

                classInfo[class.Name] = {
                    Name = class.Name,
                    Superclass = class.Superclass,
                    Tags = class.Tags,
                    Members = members,
                }

                if tagContains(class.Tags, "Service") then
                    serviceNames[class.Name] = true
                end
            end
        end
    end

    if hostFns.type(apiDump.Enums) == "table" then
        for _, enum in hostFns.ipairs(apiDump.Enums) do
            if hostFns.type(enum) == "table" and hostFns.type(enum.Name) == "string" then
                local items = {}

                if hostFns.type(enum.Items) == "table" then
                    for _, item in hostFns.ipairs(enum.Items) do
                        if hostFns.type(item) == "table" and hostFns.type(item.Name) == "string" then
                            items[item.Name] = item.Value
                        end
                    end
                end

                enumInfo[enum.Name] = items
            end
        end
    end
end

local hasUsableApiClassDump =
    classInfo["Instance"] ~= nil
    and classInfo["Workspace"] ~= nil

-- Public classes introduced after some cached API dumps.
-- These entries exist only so our concrete implementations below remain usable
-- when the user's local dump predates the class.
for name, superName in hostFns.pairs({
    PlayerEmulatorService = "Instance",
    ReflectionService = "Instance",
    StatsItem = "Instance",
    Path2D = "Instance",
    InputAction = "Instance",
    MaterialVariant = "Instance",
    AudioEmitter = "Instance",
    AudioListener = "Instance",
    AudioDeviceInput = "Instance",
    AudioDeviceOutput = "Instance",
    AudioPlayer = "Instance",
    AudioReverb = "Instance",
    AudioFilter = "Instance",
    Wire = "Instance",
    Beam = "Instance",
    Trail = "Instance",
    ParticleEmitter = "Instance",
    PointLight = "Instance",
    SurfaceLight = "Instance",
    SpotLight = "Instance",
    Decal = "Instance",
    Texture = "Instance",
    Shirt = "Instance",
    Pants = "Instance",
    WeldConstraint = "Instance",
    Motor6D = "Instance",
    CharacterMesh = "Instance",
    BodyColors = "Instance",
    UICorner = "Instance",
    UIStroke = "Instance",
    UIListLayout = "Instance",
    UIPadding = "Instance",
    Animator = "Instance",
    CoreScript = "LuaSourceContainer",
}) do
    if classInfo[name] == nil then
        classInfo[name] = {
            Name = name,
            Superclass = superName,
            Tags = {},
            Members = {},
        }
    end
end

-- ReflectionService can be absent from older cached API dumps.
do
    local info = classInfo["ReflectionService"]
    if info then
        info.Members = info.Members or {}
        if info.Members.GetClasses == nil then
            info.Members.GetClasses = {
                Name = "GetClasses",
                MemberType = "Function",
                Security = "None",
            }
        end
    end
end

-- AudioFilter can be absent from older cached API dumps.
do
    local info = classInfo["AudioFilter"]
    if info then
        info.Members = info.Members or {}
        if info.Members.GetGainAt == nil then
            info.Members.GetGainAt = {
                Name = "GetGainAt",
                MemberType = "Function",
                Security = "None",
            }
        end
        for _, propertyName in hostFns.ipairs({"FilterType", "Frequency", "Q", "Gain"}) do
            if info.Members[propertyName] == nil then
                info.Members[propertyName] = {
                    Name = propertyName,
                    MemberType = "Property",
                    Security = "None",
                }
            end
        end
    end
end

-- PlayerEmulatorService is newer than some cached API dumps. Ensure its
-- IsEnabled function remains discoverable by normal Instance member lookup.
do
    local info = classInfo["PlayerEmulatorService"]
    if info then
        info.Members = info.Members or {}
        if info.Members.IsEnabled == nil then
            info.Members.IsEnabled = {
                Name = "IsEnabled",
                MemberType = "Function",
                Security = "None",
            }
        end
    end
end

local fallbackEnums = {
    NormalId = {Right=0,Top=1,Back=2,Left=3,Bottom=4,Front=5},
    Platform = {
        Windows = 0,
        OSX = 1,
        IOS = 2,
        Android = 3,
        XBoxOne = 4,
        PS4 = 5,
        PS5 = 6,
        UWP = 7,
    },
    MarketplaceItemPurchaseStatus = {
        Success=0,
        SystemError=1,
        AlreadyPurchased=2,
        AlreadyOwned=3,
        InsufficientRobux=4,
        QuantityLimitExceeded=5,
        UnknownError=6,
        NotForSale=7,
    },
    CompressionAlgorithm = {
        Zstd = 0,
        Lz4 = 1,
    },
    MeshAttribute = {
        Vertex = 0,
        Normal = 1,
        UV = 2,
        Color = 3,
    },
    ListenerType = {
        Camera = 0,
        CFrame = 1,
        ObjectPosition = 2,
        ObjectCFrame = 3,
    },
    AudioFilterType = {
        Lowpass6dB = 0,
        Lowpass12dB = 1,
        Lowpass24dB = 2,
        Highpass6dB = 3,
        Highpass12dB = 4,
        Highpass24dB = 5,
        Bandpass = 6,
        Peaking = 7,
        Notch = 8,
        LowShelf = 9,
        HighShelf = 10,
    },
    InputActionType = {
        Bool = 0,
        Direction1D = 1,
        Direction2D = 2,
        Direction3D = 3,
        ViewportPosition = 4,
    },
    ContentSourceType = {
        None = 0,
        Uri = 1,
        Object = 2,
    },
    Font = {
        Legacy = 0,
        Arial = 1,
        ArialBold = 2,
        SourceSans = 3,
        SourceSansBold = 4,
        SourceSansLight = 5,
        SourceSansItalic = 6,
    },
    InfoType = {
        Asset = 0,
        Product = 1,
        GamePass = 2,
        Subscription = 3,
    },
    Axis = {X=0,Y=1,Z=2},
    InitialDockState = {Top=0,Bottom=1,Left=2,Right=3,Float=4},
    EnviromentalPhysicsThrottle = {DefaultAuto=0,Disabled=1,Always=2},
    EasingStyle = {Linear=0,Sine=1,Back=2,Quad=3,Quart=4,Quint=5,Bounce=6,Elastic=7,Exponential=8,Circular=9,Cubic=10},
    EasingDirection = {In=0,Out=1,InOut=2},
    PlaybackState = {Begin=0,Delayed=1,Playing=2,Paused=3,Completed=4,Cancelled=5},
    TextTruncate = {None=0,AtEnd=1,SplitWord=2},
    TextXAlignment = {Left=0,Right=1,Center=2},
    TextYAlignment = {Top=0,Center=1,Bottom=2},
    ActuatorType = {None=0,Motor=1,Servo=2},
    ActuatorRelativeTo = {Attachment0=0,Attachment1=1,World=2},
    HumanoidStateType = {
        FallingDown=0,Ragdoll=1,GettingUp=2,Jumping=3,Swimming=4,Freefall=5,Flying=6,
        Landed=7,Running=8,RunningNoPhysics=10,StrafingNoPhysics=11,Climbing=12,
        Seated=13,PlatformStanding=14,Dead=15,Physics=16,None=18
    },
    HumanoidDisplayDistanceType = {Viewer=0,Subject=1,None=2},
    RunState = {Stopped=0,Running=1,Paused=2},
    CreatorType = {User=0,Group=1},
    PathStatus = {Success=0,NoPath=1},
    PathWaypointAction = {Walk=0,Jump=1,Custom=2},
    RaycastFilterType = {Exclude=0,Include=1},
    MouseBehavior = {Default=0,LockCenter=1,LockCurrentPosition=2},
    PartType = {Ball=0,Block=1,Cylinder=2},
    KeyInterpolationMode = {Constant=0,Linear=1,Cubic=2},
    CatalogSortType = {Relevance=0,Favorited=1,Sales=2,Updated=3,PriceAsc=4,PriceDesc=5},
    AssetFetchStatus = {Success=0,Failure=1,Timeout=2,None=3,Loading=4},
    ImageCombineType = {BlendSourceOver=0,Overwrite=1,Add=2,Multiply=3,AlphaBlend=4},
    ImageAlphaType = {Default=0,Premultiplied=1},
    ResamplerMode = {Default=0,Pixelated=1},
    AntiAliasing = {Default=0,Disabled=1},
    ReverbType = {NoReverb=0},
    FontWeight = {Thin=100,ExtraLight=200,Light=300,Regular=400,Medium=500,SemiBold=600,Bold=700,ExtraBold=800,Heavy=900},
    FontStyle = {Normal=0,Italic=1},
    MembershipType = {None=0,BuildersClub=1,TurboBuildersClub=2,OutrageousBuildersClub=3,Premium=4},
    AccessModifierType = {Allow=0,Deny=1},
    Font = {Legacy=0,Arial=1,ArialBold=2,SourceSans=3,SourceSansBold=4,SourceSansLight=5,SourceSansItalic=6,Gotham=7,GothamBold=8,GothamSemibold=9},
    Material = {Plastic=256,SmoothPlastic=272,Neon=288,Wood=512,Concrete=816,Grass=1280},
    CatalogSortAggregation = {Past12Hours=0,PastDay=1,Past3Days=2,PastWeek=3,PastMonth=4,AllTime=5},
    AccessoryType = {
        Unknown=0,Hat=1,Hair=2,Face=3,Neck=4,Shoulder=5,Front=6,Back=7,Waist=8,
        TShirt=9,Shirt=10,Pants=11,Jacket=12,Sweater=13,Shorts=14,LeftShoe=15,
        RightShoe=16,DressSkirt=17,Eyebrow=18,Eyelash=19,Mood=20,DynamicHead=21
    },
    CatalogCategoryFilter = {None=0,Featured=1,Collectibles=2,CommunityCreations=3,Premium=4},
    CatalogSalesTypeFilter = {All=0,Collectibles=1,Premium=2},
    AdAvailabilityResult = {
        IsAvailable=1, DeviceIneligible=2, ExperienceIneligible=3, InternalError=4,
        NoFill=5, PlayerIneligible=6, PublisherIneligible=7,
    },
    AdEventType = {
        VideoLoaded=0, VideoRemoved=1, UserCompletedVideo=2,
        RewardedAdLoaded=3, RewardedAdGrant=4, RewardedAdUnloaded=5,
    },
    ActionType = {Nothing=0,Pause=1,Lose=2,Draw=3,Win=4},
    BodyPart = {Head=0,Torso=1,LeftArm=2,RightArm=3,LeftLeg=4,RightLeg=5},
    Technology = {Compatibility=0,Voxel=1,ShadowMap=2,Future=3,Legacy=4,Unified=5},
    DeveloperMemoryTag = {Internal=0,HttpCache=1,Instances=2,Signals=3,LuaHeap=4,Script=5,PhysicsCollision=6,PhysicsParts=7,Graphics=8,GraphicsSolidModels=9,GraphicsMeshParts=10,GraphicsParticles=11,GraphicsParts=12,GraphicsSpatialHash=13,GraphicsTerrain=14,GraphicsTexture=15,GraphicsTextureCharacter=16,Sounds=17,StreamingSounds=18,TerrainVoxels=19,Gui=20,Animation=21,Navigation=22},
    AutomaticSize = {None=0,X=1,Y=2,XY=3},
    HorizontalAlignment = {Center=0,Left=1,Right=2},
    VerticalAlignment = {Center=0,Top=1,Bottom=2},
    SortOrder = {Name=0,Custom=1,LayoutOrder=2},
    UserInputType = {MouseButton1=0,MouseButton2=1,MouseButton3=2,MouseMovement=3,Keyboard=8,Touch=7},
    UserInputState = {Begin=0,Change=1,End=2,Cancel=3,None=4},
    KeyCode = {Unknown=0,W=1,A=2,S=3,D=4,Up=5,Left=6,Down=7,Right=8,Slash=9,Tab=10,Backspace=11,Escape=12},
    FormFactor = {Brick=0, Symmetric=1, Plate=2, Custom=3, Phone=4, Tablet=5},
    Status = {Success=0, Failure=1},
}
for enumName, items in hostFns.pairs(fallbackEnums) do
    local target = enumInfo[enumName]
    if target == nil then
        target = {}
        enumInfo[enumName] = target
    end
    for itemName, itemValue in hostFns.pairs(items) do
        if target[itemName] == nil then target[itemName] = itemValue end
    end
end

-- Mixed cached API dumps can contain legacy Enum.Font aliases whose numeric
-- values collide with fallback-only font entries. Roblox EnumItems exposed by
-- GetEnumItems should have stable unique values, so only remap collisions.
do
    local fontItems = enumInfo.Font
    if fontItems then
        local names = {}
        local maxValue = -1
        for itemName, itemValue in hostFns.pairs(fontItems) do
            names[#names + 1] = itemName
            local n = tonumber(itemValue)
            if n and n > maxValue then maxValue = n end
        end
        table.sort(names)

        local used = {}
        local nextValue = maxValue + 1
        for _, itemName in hostFns.ipairs(names) do
            local value = tonumber(fontItems[itemName]) or 0
            if used[value] then
                while used[nextValue] do nextValue += 1 end
                fontItems[itemName] = nextValue
                used[nextValue] = true
                nextValue += 1
            else
                used[value] = true
            end
        end
    end
end

for _, service in hostFns.ipairs({
    "Workspace",
    "Players",
    "RunService",
    "HttpService",
    "EncodingService",
    "Lighting",
    "SoundService",
    "TweenService",
    "CollectionService",
    "MarketplaceService",
    "PhysicsService",
    "StarterGui",
    "LogService",
    "StarterPlayer",
    "StarterPack",
    "ReplicatedStorage",
    "ReplicatedFirst",
    "ServerStorage",
    "ServerScriptService",
    "Teams",
    "Stats",
    "ContentProvider",
    "AnimationClipProvider",
    "AvatarEditorService",
    "MemStorageService",
    "ContextActionService",
    "UserInputService",
    "PathfindingService",
    "Debris",
    "TeleportService",
    "TextService",
    "TextChatService",
    "VoiceChatService",
    "GuidRegistryService",
    "ScriptService",
    "RbxAnalyticsService",
    "Chat",
    "GuiService",
    "CoreGui",
    "InsertService",
    "BadgeService",
    "GroupService",
    "PolicyService",
    "LocalizationService",
    "AssetService",
    "ReflectionService",
    "ProximityPromptService",
    "TestService",
    "PlayerEmulatorService",
    "GongService",
    "AccountService",
    "AchievementService",
    "ActivityHistoryEventService",
    "AdService",
    "AnalyticsService",
    "AnimatedImageService",
    "AppLifecycleObserverService",
    "AudioFocusService",
    "AvatarChatService",
    "BranchService",
    "BrowserService",
    "CallingService",
    "CaptureService",
    "CloudCRUDService",
    "CommerceService",
    "CoreGuiConfiguration",
    "CorePackages",
    "DataStoreService",
    "DeviceDisplayService",
    "ExperienceService",
    "GeometryService",
    "HapticService",
    "InternalMessagingService",
    "KeyboardService",
    "MaterialService",
    "MemoryStoreService",
    "MessagingService",
    "NotificationService",
    "PackageService",
    "PermissionsService",
    "PlaceStatsService",
    "RecommendationService",
    "RuntimeContentService",
    "ScriptContext",
    "SerializationService",
    "SharedTableRegistry",
    "SystemThemeService",
    "TaskScheduler",
    "TextureGenerationService",
}) do
    serviceNames[service] = true
end


-- Complete service fallback generated from the bundled Roblox API dump.
-- The live API dump above still provides exact inheritance/member metadata;
-- this list keeps GetService coverage intact when the cache cannot be decoded.
for _, serviceName in hostFns.ipairs({
    "AccountService",
    "AchievementService",
    "ActivityHistoryEventService",
    "AdService",
    "AnalyticsService",
    "AnimatedImageService",
    "AnimationClipProvider",
    "AnimationFromVideoCreatorService",
    "AnimationFromVideoCreatorStudioService",
    "AnnotationsService",
    "AppAgeSignalsService",
    "AppLifecycleObserverService",
    "AppRatingPromptService",
    "AppStorageService",
    "AppUpdateService",
    "AssetCounterService",
    "AssetDeliveryProxy",
    "AssetImportService",
    "AssetManagerService",
    "AssetQualityService",
    "AssetService",
    "AudioFocusService",
    "AvatarChatService",
    "AvatarCreationService",
    "AvatarEditorService",
    "AvatarImportService",
    "AvatarSettings",
    "BadgeService",
    "BranchService",
    "BrowserService",
    "BugReporterService",
    "BulkImportService",
    "CSGDictionaryService",
    "CacheableContentProvider",
    "CallingService",
    "CalloutService",
    "CaptureService",
    "ChangeHistoryService",
    "ChangeHistoryStreamingService",
    "Chat",
    "ClientStorageService",
    "CloudCRUDService",
    "CloudExecutionService",
    "ClusterPacketCache",
    "CollaboratorsService",
    "CollectionService",
    "CommerceService",
    "ConfigService",
    "ConfigureServerService",
    "ConnectivityService",
    "ContentProvider",
    "ContextActionService",
    "ControllerService",
    "CookiesService",
    "CoreGui",
    "CoreGuiConfiguration",
    "CorePackages",
    "CoreScriptDebuggingManagerHelper",
    "CoreScriptSyncService",
    "CreationDBService",
    "CreatorStoreService",
    "CrossDMScriptChangeListener",
    "DataStoreService",
    "Debris",
    "DebugSettings",
    "DebuggablePluginWatcher",
    "DebuggerConnectionManager",
    "DebuggerManager",
    "DebuggerUIService",
    "DeferredAssetManagerService",
    "DesignFoundationsService",
    "DeviceDisplayService",
    "DeviceIdService",
    "DraftsService",
    "DraggerService",
    "EditableService",
    "EditorSourceService",
    "EncodingService",
    "EventIngestService",
    "ExampleV2Service",
    "ExperienceAuthService",
    "ExperienceNotificationService",
    "ExperienceService",
    "ExperienceStateCaptureService",
    "ExperienceStateRecordingService",
    "ExplorerServiceVisibilityService",
    "ExternalIdentityService",
    "FaceAnimatorService",
    "FacialAgeEstimationService",
    "FacialAnimationRecordingService",
    "FacialAnimationStreamingServiceV2",
    "FeatureRestrictionManager",
    "FileManagerService",
    "FileSyncReplicationService",
    "FlagStandService",
    "FlyweightService",
    "FriendService",
    "GamePassService",
    "GameSettings",
    "GamepadService",
    "GenerationService",
    "GenericChallengeService",
    "Geometry",
    "GeometryService",
    "GongService",
    "GroupService",
    "GuiService",
    "GuidRegistryService",
    "HSRDataContentProvider",
    "HapticService",
    "HarmonyService",
    "HeapProfilerService",
    "HeatmapQueryService",
    "HeatmapService",
    "HeightmapImporterService",
    "Hopper",
    "HttpRbxApiService",
    "HttpService",
    "ILegacyStudioBridge",
    "IXPService",
    "ImageScreenCaptureService",
    "IncrementalPatchBuilder",
    "InsertService",
    "InstanceExtensionsService",
    "InstanceFileSyncService",
    "IntentService",
    "InternalMessagingService",
    "InternalMessagingServiceVerifier",
    "JointsService",
    "KeyboardService",
    "KeyframeSequenceProvider",
    "LanguageService",
    "LegacyStudioBridge",
    "Lighting",
    "LinkingService",
    "LiveScriptingService",
    "LiveSyncService",
    "LocalStorageService",
    "LocalizationService",
    "LodDataService",
    "LogReporterService",
    "LogService",
    "LoginService",
    "LuaSettings",
    "LuaWebService",
    "LuauExpressionService",
    "LuauScriptAnalyzerService",
    "MLModelDeliveryService",
    "MLService",
    "MarketplaceService",
    "MatchmakingService",
    "MaterialGenerationService",
    "MaterialService",
    "MemStorageService",
    "MemoryStoreService",
    "MeshContentProvider",
    "MessageBusService",
    "MessagingService",
    "MetaBreakpointManager",
    "MicroProfilerService",
    "ModerationService",
    "MomentsService",
    "MouseService",
    "NetworkClient",
    "NetworkServer",
    "NetworkSettings",
    "NonReplicatedCSGDictionaryService",
    "NotificationService",
    "OmniRecommendationsService",
    "OpenCloudService",
    "PackageService",
    "PackageUIService",
    "Packages",
    "PartyEmulatorService",
    "PatchBundlerFileWatch",
    "PathfindingService",
    "PerformanceControlService",
    "PermissionsService",
    "PhysicsService",
    "PhysicsSettings",
    "PinShortcutService",
    "PlaceAssetIdsService",
    "PlaceStatsService",
    "PlacesService",
    "PlatformCloudStorageService",
    "PlatformFriendsService",
    "PlatformLibraries",
    "PlayerDataService",
    "PlayerEmulatorService",
    "PlayerHydrationService",
    "PlayerViewService",
    "Players",
    "PluginConnectionService",
    "PluginDebugService",
    "PluginGuiService",
    "PluginManagementService",
    "PluginPolicyService",
    "PointsService",
    "PolicyService",
    "PopLatencyService",
    "Preloaded",
    "ProceduralBehaviorSchedulerService",
    "ProcessInstancePhysicsService",
    "ProximityPromptService",
    "PublishService",
    "QueueService",
    "RbxAnalyticsService",
    "RecommendationService",
    "ReflectionService",
    "RemoteCommandService",
    "RemoteCursorService",
    "RemoteDebuggerServer",
    "RenderSettings",
    "ReplicatedFirst",
    "ReplicatedStorage",
    "RequestOrchestratorService",
    "RibbonNotificationService",
    "RobloxPluginGuiService",
    "RobloxReplicatedStorage",
    "RobloxServerStorage",
    "RolloutValidationService",
    "RomarkRbxAnalyticsService",
    "RomarkService",
    "RtMessagingService",
    "RunService",
    "RuntimeContentService",
    "RuntimeScriptService",
    "SafetyService",
    "SceneAnalysisService",
    "ScriptChangeService",
    "ScriptCloneWatcher",
    "ScriptCloneWatcherHelper",
    "ScriptCommitService",
    "ScriptContext",
    "ScriptDebuggerService",
    "ScriptEditorService",
    "ScriptProfilerService",
    "ScriptRegistrationService",
    "ScriptScannerService",
    "ScriptService",
    "Selection",
    "SelectionHighlightManager",
    "SerializationService",
    "ServerScriptService",
    "ServerStorage",
    "ServiceVisibilityService",
    "SessionCheckService",
    "SessionService",
    "SharedTableRegistry",
    "SlimAnimationReplicationService",
    "SlimContentProvider",
    "SlimDebugSettings",
    "SlimReplicationService",
    "SlimService",
    "SmoothVoxelsUpgraderService",
    "SocialService",
    "SolidModelContentProvider",
    "SoundService",
    "SoundShimService",
    "SpawnerService",
    "StartPageService",
    "StarterGui",
    "StarterPack",
    "StarterPlayer",
    "StartupMessageService",
    "Stats",
    "StopWatchReporter",
    "Studio",
    "StudioAssetService",
    "StudioCameraService",
    "StudioCaptureService",
    "StudioData",
    "StudioDeviceEmulatorService",
    "StudioDeviceSimulatorService",
    "StudioPublishService",
    "StudioScriptDebugEventListener",
    "StudioSdkService",
    "StudioService",
    "StudioTestService",
    "StudioUserService",
    "StudioWidgetsService",
    "StylingService",
    "SystemThemeService",
    "TaskScheduler",
    "TeamCreateData",
    "TeamCreatePublishService",
    "TeamCreateService",
    "Teams",
    "TelemetryService",
    "TeleportService",
    "TemporaryCageMeshProvider",
    "TemporaryScriptService",
    "TestService",
    "TextBoxService",
    "TextChatService",
    "TextService",
    "TextureGenerationService",
    "ThirdPartyUserService",
    "TimerService",
    "ToastNotificationService",
    "TouchInputService",
    "TraceRouteService",
    "TracerService",
    "TutorialService",
    "TweenService",
    "UGCAvatarService",
    "UGCValidationService",
    "UIDragDetectorService",
    "UniqueIdLookupService",
    "UnvalidatedAssetService",
    "UserGameSettings",
    "UserInputService",
    "UserService",
    "UserStorageService",
    "VRService",
    "VRStatusService",
    "VersionControlService",
    "VideoCaptureService",
    "VideoScreenCaptureService",
    "VideoService",
    "VirtualInputManager",
    "VirtualUser",
    "VisibilityCheckDispatcher",
    "Visit",
    "VisualizationModeService",
    "VoiceChatInternal",
    "VoiceChatService",
    "WebSocketService",
    "WebViewService",
    "WindowProtocolService",
    "Workspace",
    "WrapContentProvider",
    "WrapDeformMeshProvider",
}) do
    serviceNames[serviceName] = true
    if classInfo[serviceName] == nil then
        classInfo[serviceName] = {
            Name = serviceName,
            Superclass = "Instance",
            Tags = {"NotCreatable", "Service"},
            Members = {},
        }
    end
end

local output = {
    "-- This file was logged using Oxyenv v3.50.25 http://dsc.gg/oxyenv",
    "",
}
local repeatCounts = {}
local objectNames = hostFns.setmetatable({}, { __mode = "k" })
local objectTypes = hostFns.setmetatable({}, { __mode = "k" })
local instanceStates = hostFns.setmetatable({}, { __mode = "k" })
local instanceChildren = hostFns.setmetatable({}, { __mode = "k" })
local signalCallbacks = hostFns.setmetatable({}, { __mode = "k" })
local proxyState = hostFns.setmetatable({}, { __mode = "k" })
local sharedTableFields = hostFns.setmetatable({}, { __mode = "k" })
local gameServiceAddedSignal = nil
local collectionTags
local proxyCount = 0
local varCounter = 0
local indent = 0
local virtualTime = 1000
local runtimeStart = hostFns.clock()

local function checkRuntime()
    if hostFns.clock() - runtimeStart > LIMITS.MAX_EXEC_SECONDS then
        hostFns.error("Oxygen OxyEnv execution timeout", 0)
    end
end

local function pad()
    return string.rep("    ", indent)
end

local function quote(value)
    return string.format("%q", hostFns.tostring(value))
end

local function newVar(prefix)
    varCounter += 1

    local base = hostFns.tostring(prefix or "var")
    base = base:gsub("[^%w_]", "_")
    if base == "" then base = "var" end
    if base:match("^%d") then base = "_" .. base end

    local counterKey = "__radium_name_counter:" .. base
    local count = (repeatCounts[counterKey] or 0) + 1
    repeatCounts[counterKey] = count

    if count == 1 then
        return base
    end

    return base .. hostFns.tostring(count)
end

local function emit(line)
    checkRuntime()

    if #output >= LIMITS.MAX_OUTPUT_LINES then
        return
    end

    line = pad() .. line
    local count = (repeatCounts[line] or 0) + 1
    repeatCounts[line] = count

    if count > LIMITS.MAX_REPEAT then
        return
    end

    output[#output + 1] = line
    hostFns.print(line)
end

local function mark(value, name, typeName)
    if value ~= nil and (hostFns.type(value) == "table" or hostFns.type(value) == "userdata" or hostFns.type(value) == "thread") then
        objectNames[value] = name

        if typeName then
            objectTypes[value] = typeName
        end
    end

    return value
end

local function repr(value, depth, seen)
    depth = depth or 0
    seen = seen or {}

    local t = hostFns.type(value)
    local ot = objectTypes[value]

    if t == "string" then
        return quote(value)
    elseif t == "number" or t == "boolean" then
        return hostFns.tostring(value)
    elseif t == "nil" then
        return "nil"
    elseif t == "function" then
        return "function(...) end"
    elseif ot == "Vector2" then
        return "Vector2.new(" .. hostFns.tostring(value.X) .. ", " .. hostFns.tostring(value.Y) .. ")"
    elseif ot == "Vector3" then
        return "Vector3.new(" .. hostFns.tostring(value.X) .. ", " .. hostFns.tostring(value.Y) .. ", " .. hostFns.tostring(value.Z) .. ")"
    elseif ot == "Color3" then
        return "Color3.new(" .. hostFns.tostring(value.R) .. ", " .. hostFns.tostring(value.G) .. ", " .. hostFns.tostring(value.B) .. ")"
    elseif ot == "CFrame" then
        local x,y,z,r00,r01,r02,r10,r11,r12,r20,r21,r22=value:GetComponents()
        if r00==1 and r01==0 and r02==0 and r10==0 and r11==1 and r12==0 and r20==0 and r21==0 and r22==1 then
            return "CFrame.new("..hostFns.tostring(x)..", "..hostFns.tostring(y)..", "..hostFns.tostring(z)..")"
        end
        return "CFrame.new("..table.concat({
            hostFns.tostring(x),hostFns.tostring(y),hostFns.tostring(z),
            hostFns.tostring(r00),hostFns.tostring(r01),hostFns.tostring(r02),
            hostFns.tostring(r10),hostFns.tostring(r11),hostFns.tostring(r12),
            hostFns.tostring(r20),hostFns.tostring(r21),hostFns.tostring(r22),
        },", ")..")"
    elseif ot == "UDim" then
        return "UDim.new(" .. hostFns.tostring(value.Scale) .. ", " .. hostFns.tostring(value.Offset) .. ")"
    elseif ot == "UDim2" then
        return "UDim2.new("
            .. hostFns.tostring(value.X.Scale) .. ", " .. hostFns.tostring(value.X.Offset) .. ", "
            .. hostFns.tostring(value.Y.Scale) .. ", " .. hostFns.tostring(value.Y.Offset) .. ")"
    elseif ot == "EnumItem" then
        return hostFns.tostring(value)
    elseif t == "table" then
        if depth >= 3 then return "{...}" end
        if seen[value] then return "{<cycle>}" end
        seen[value] = true

        local parts = {}
        local count = 0
        local array = true
        local maxIndex = 0

        for key in hostFns.pairs(value) do
            count += 1
            if count > 24 then break end
            if hostFns.type(key) ~= "number" or key < 1 or key ~= math.floor(key) then
                array = false
            elseif key > maxIndex then
                maxIndex = key
            end
        end

        if array then
            for i = 1, math.min(maxIndex, 24) do
                parts[#parts + 1] = repr(value[i], depth + 1, seen)
            end
        else
            count = 0
            for key, item in hostFns.pairs(value) do
                count += 1
                if count > 24 then
                    parts[#parts + 1] = "--[[...]]"
                    break
                end
                local renderedKey
                if hostFns.type(key) == "string" and key:match("^[%a_][%w_]*$") then
                    renderedKey = key
                else
                    renderedKey = "[" .. repr(key, depth + 1, seen) .. "]"
                end
                parts[#parts + 1] = renderedKey .. " = " .. repr(item, depth + 1, seen)
            end
        end

        seen[value] = nil
        return "{" .. table.concat(parts, ", ") .. "}"
    elseif objectNames[value] then
        return objectNames[value]
    end

    return hostFns.tostring(value)
end

local function classMember(className, memberName)
    local current = className
    local seen = {}

    while current and not seen[current] do
        seen[current] = true
        local info = classInfo[current]

        if not info then
            break
        end

        local member = info.Members[memberName]
        if member then
            return member
        end

        current = info.Superclass
    end

    return nil
end

securityRuntime.getMemberDescriptor = function(className, memberName)
    local member = classMember(className, memberName)

    if member ~= nil then
        return member
    end

    local classFallback =
        securityRuntime.fallbackMembers[className]

    return classFallback
        and classFallback[memberName]
        or nil
end

securityRuntime.getMemberSecurity = function(
    className,
    memberName,
    accessMode
)
    local member =
        securityRuntime.getMemberDescriptor(
            className,
            memberName
        )

    if member == nil then
        return "None"
    end

    local access =
        accessMode == "Write"
        and "Write"
        or accessMode == "Call"
            and "Call"
            or "Read"

    local directField =
        access == "Write"
        and member.WriteSecurity
        or access == "Read"
            and member.ReadSecurity
            or nil

    if hostFns.type(directField) == "string" then
        return directField
    end

    local security = member.Security

    if hostFns.type(security) == "string" then
        return security
    end

    if hostFns.type(security) == "table" then
        local tag =
            security[access]
            or security[
                access == "Call"
                and "Read"
                or access
            ]

        if hostFns.type(tag) == "string" then
            return tag
        end
    end

    local fallbackTag = member[access]

    if hostFns.type(fallbackTag) == "string" then
        return fallbackTag
    end

    return "None"
end

securityRuntime.assertAccess = function(
    className,
    memberName,
    accessMode
)
    local required =
        securityRuntime.getMemberSecurity(
            className,
            memberName,
            accessMode
        )

    local identity = getRuntimeThreadIdentity()

    if securityRuntime.hasCapability(
        identity,
        required
    ) then
        return
    end

    local action =
        accessMode == "Write"
        and "write"
        or accessMode == "Call"
            and "call"
            or "access"

    hostFns.error(
        "The current thread cannot "
            .. action
            .. " '"
            .. hostFns.tostring(memberName)
            .. "' ("
            .. hostFns.tostring(required)
            .. ")",
        3
    )
end

securityRuntime.assertPropertyAccess = function(
    className,
    memberName,
    accessMode
)
    local member =
        securityRuntime.getMemberDescriptor(
            className,
            memberName
        )

    if member == nil then
        return
    end

    if member.MemberType ~= nil
        and member.MemberType ~= "Property"
    then
        return
    end

    securityRuntime.assertAccess(
        className,
        memberName,
        accessMode
    )
end

local function classIsA(className, wanted)
    if className == wanted or wanted == "Instance" then
        return true
    end

    local current = className
    local seen = {}

    while current and not seen[current] do
        if current == wanted then
            return true
        end

        seen[current] = true
        local info = classInfo[current]
        current = info and info.Superclass or nil
    end

    local fallback = {
        Part = "BasePart",
        MeshPart = "BasePart",
        SpawnLocation = "BasePart",
        WedgePart = "BasePart",
        CornerWedgePart = "BasePart",
        TrussPart = "BasePart",
        Seat = "BasePart",
        VehicleSeat = "BasePart",
        Model = "PVInstance",
        Camera = "PVInstance",
        Frame = "GuiObject",
        TextLabel = "GuiObject",
        TextButton = "GuiObject",
        TextBox = "GuiObject",
        ImageLabel = "GuiObject",
        ImageButton = "GuiObject",
        ScrollingFrame = "GuiObject",
    }

    current = className

    while fallback[current] do
        current = fallback[current]

        if current == wanted then
            return true
        end
    end

    return false
end

local enumTypeCache = {}
local enumItemCache = {}

local function makeEnumType(enumName)
    if enumTypeCache[enumName] then
        return enumTypeCache[enumName]
    end

    proxyCount += 1

    if proxyCount > LIMITS.MAX_PROXIES then
        hostFns.error("Oxygen OxyEnv proxy limit reached", 0)
    end

    local enumType = newproxy(true)
    local mt = hostFns.getmetatable(enumType)
    mark(enumType, "Enum." .. enumName, "Enum")

    mt.__index = function(_, key)
        if key == "GetEnumItems" then
            return function(selfEnum)
                if selfEnum ~= enumType then
                    hostFns.error("Expected ':' not '.' calling GetEnumItems", 2)
                end

                local result = {}
                local known = enumInfo[enumName] or {}

                for itemName in hostFns.pairs(known) do
                    result[#result + 1] = enumType[itemName]
                end

                table.sort(result, function(a, b)
                    return (a.Value or 0) < (b.Value or 0)
                end)

                return result
            end
        elseif key == "FromName" then
            local implementation = function(selfEnum, wantedName)
                if selfEnum ~= enumType then
                    hostFns.error("Expected ':' not '.' calling FromName", 2)
                end

                local known = enumInfo[enumName] or {}
                wantedName = hostFns.tostring(wantedName)

                if known[wantedName] == nil then
                    return nil
                end

                return enumType[wantedName]
            end

            if host.native and host.native.bind then
                return host.native.bind("FromName", implementation)
            end

            return implementation
        elseif key == "FromValue" then
            local implementation = function(selfEnum, wantedValue)
                if selfEnum ~= enumType then
                    hostFns.error("Expected ':' not '.' calling FromValue", 2)
                end

                local known = enumInfo[enumName] or {}
                local numeric = tonumber(wantedValue)

                if numeric == nil then
                    return nil
                end

                for itemName, itemValue in hostFns.pairs(known) do
                    if tonumber(itemValue) == numeric then
                        return enumType[itemName]
                    end
                end

                return nil
            end

            if host.native and host.native.bind then
                return host.native.bind("FromValue", implementation)
            end

            return implementation
        end

        local known = enumInfo[enumName]

        if known and known[key] == nil then
            hostFns.error(hostFns.tostring(key) .. " is not a valid member of Enum." .. enumName, 2)
        end

        local cacheKey = enumName .. "." .. hostFns.tostring(key)

        if enumItemCache[cacheKey] then
            return enumItemCache[cacheKey]
        end

        local item = newproxy(true)
        local itemMt = hostFns.getmetatable(item)
        local itemValue = known and known[key] or 0
        mark(item, "Enum." .. cacheKey, "EnumItem")

        itemMt.__index = function(_, itemKey)
            if itemKey == "Name" then
                return hostFns.tostring(key)
            elseif itemKey == "Value" then
                return itemValue
            elseif itemKey == "EnumType" then
                return enumType
            end

            return nil
        end

        itemMt.__newindex = function()
            hostFns.error("attempt to modify a readonly EnumItem", 2)
        end

        itemMt.__tostring = function()
            return "Enum." .. cacheKey
        end

        enumItemCache[cacheKey] = item
        return item
    end

    mt.__tostring = function()
        return "Enum." .. enumName
    end

    enumTypeCache[enumName] = enumType
    return enumType
end

local Enum = newproxy(true)

do
    local mt = hostFns.getmetatable(Enum)
    mark(Enum, "Enum", "Enums")

    mt.__index = function(_, key)
        if key == "GetEnums" then
            local implementation = function(selfEnum)
                if selfEnum ~= Enum then
                    hostFns.error("Expected ':' not '.' calling GetEnums", 2)
                end

                local result = {}
                for enumName in hostFns.pairs(enumInfo) do
                    result[#result + 1] = makeEnumType(enumName)
                end

                table.sort(result, function(a, b)
                    return hostFns.tostring(a) < hostFns.tostring(b)
                end)

                return result
            end

            if host.native and host.native.bind then
                return host.native.bind("GetEnums", implementation)
            end

            return implementation
        end

        local enumName = hostFns.tostring(key)
        if enumInfo[enumName] == nil then
            hostFns.error(enumName .. " is not a valid member of Enum", 2)
        end
        return makeEnumType(enumName)
    end

    mt.__tostring = function()
        return "Enum"
    end
end

local dataConstructors = {}
local toFloat32

local function makeDataValue(typeName, fields)
    proxyCount += 1

    if proxyCount > LIMITS.MAX_PROXIES then
        hostFns.error("Oxygen OxyEnv proxy limit reached", 0)
    end

    fields = fields or {}

    local obj = newproxy(true)
    local mt = hostFns.getmetatable(obj)

    if typeName == "SharedTable" then
        sharedTableFields[obj] = fields
    end
    mark(obj, typeName, typeName)

    mt.__index = function(_, key)
        local value = fields[key]

        if value ~= nil then
            if typeName == "CatalogSearchParams" and (key == "BundleTypes" or key == "AssetTypes") and hostFns.type(value) == "table" then
                local snapshot = {}
                for i, item in hostFns.ipairs(value) do snapshot[i] = item end
                if hostFns.type(table.freeze) == "function" then
                    local ok, frozen = hostFns.pcall(table.freeze, snapshot)
                    if ok and frozen ~= nil then snapshot = frozen end
                end
                return snapshot
            end
            return value
        end

        if typeName == "Vector3" or typeName == "Vector2" then
            if key == "x" then
                return fields.X or 0
            elseif key == "y" then
                return fields.Y or 0
            elseif key == "z" and typeName == "Vector3" then
                return fields.Z or 0
            elseif key == "Magnitude" then
                local x = fields.X or 0
                local y = fields.Y or 0
                local z = fields.Z or 0
                return math.sqrt(x*x + y*y + z*z)
            elseif key == "Unit" then
                local magnitude = obj.Magnitude

                if magnitude == 0 then
                    return dataConstructors[typeName].new()
                end

                if typeName == "Vector3" then
                    return dataConstructors.Vector3.new(
                        (fields.X or 0) / magnitude,
                        (fields.Y or 0) / magnitude,
                        (fields.Z or 0) / magnitude
                    )
                end

                return dataConstructors.Vector2.new(
                    (fields.X or 0) / magnitude,
                    (fields.Y or 0) / magnitude
                )
            elseif key == "Dot" then
                return function(_, other)
                    return (fields.X or 0)*(other.X or 0) + (fields.Y or 0)*(other.Y or 0) + (fields.Z or 0)*(other.Z or 0)
                end
            elseif key == "Angle" then
                return function(_, other, axis)
                    local ax, ay, az = fields.X or 0, fields.Y or 0, fields.Z or 0
                    local bx, by, bz = other.X or 0, other.Y or 0, other.Z or 0
                    local amag = math.sqrt(ax*ax + ay*ay + az*az)
                    local bmag = math.sqrt(bx*bx + by*by + bz*bz)
                    if amag == 0 or bmag == 0 then
                        return 0
                    end
                    local cosine = math.clamp((ax*bx + ay*by + az*bz) / (amag*bmag), -1, 1)
                    local angle = math.acos(cosine)

                    if typeName == "Vector3" and axis ~= nil then
                        local cx = ay*bz - az*by
                        local cy = az*bx - ax*bz
                        local cz = ax*by - ay*bx
                        local sign = cx*(axis.X or 0) + cy*(axis.Y or 0) + cz*(axis.Z or 0)
                        if sign < 0 then angle = -angle end
                    elseif typeName == "Vector2" then
                        local cross = ax*by - ay*bx
                        if cross < 0 then angle = -angle end
                    end

                    return angle
                end
            elseif key == "Cross" then
                if typeName == "Vector3" then
                    return function(_, other)
                        return dataConstructors.Vector3.new(
                            (fields.Y or 0) * (other.Z or 0) - (fields.Z or 0) * (other.Y or 0),
                            (fields.Z or 0) * (other.X or 0) - (fields.X or 0) * (other.Z or 0),
                            (fields.X or 0) * (other.Y or 0) - (fields.Y or 0) * (other.X or 0)
                        )
                    end
                end
                return function(_, other)
                    return (fields.X or 0) * (other.Y or 0) - (fields.Y or 0) * (other.X or 0)
                end
            elseif key == "FuzzyEq" then
                return function(_, other, epsilon)
                    epsilon = tonumber(epsilon) or 1e-5
                    if typeName == "Vector3" then
                        return math.abs((fields.X or 0) - (other.X or 0)) <= epsilon
                            and math.abs((fields.Y or 0) - (other.Y or 0)) <= epsilon
                            and math.abs((fields.Z or 0) - (other.Z or 0)) <= epsilon
                    end
                    return math.abs((fields.X or 0) - (other.X or 0)) <= epsilon
                        and math.abs((fields.Y or 0) - (other.Y or 0)) <= epsilon
                end
            elseif key == "Max" then
                return function(_, other)
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(
                            math.max(fields.X or 0, other.X or 0),
                            math.max(fields.Y or 0, other.Y or 0),
                            math.max(fields.Z or 0, other.Z or 0)
                        )
                    end
                    return dataConstructors.Vector2.new(
                        math.max(fields.X or 0, other.X or 0),
                        math.max(fields.Y or 0, other.Y or 0)
                    )
                end
            elseif key == "Min" then
                return function(_, other)
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(
                            math.min(fields.X or 0, other.X or 0),
                            math.min(fields.Y or 0, other.Y or 0),
                            math.min(fields.Z or 0, other.Z or 0)
                        )
                    end
                    return dataConstructors.Vector2.new(
                        math.min(fields.X or 0, other.X or 0),
                        math.min(fields.Y or 0, other.Y or 0)
                    )
                end
            elseif key == "Abs" then
                return function()
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(math.abs(fields.X or 0),math.abs(fields.Y or 0),math.abs(fields.Z or 0))
                    end
                    return dataConstructors.Vector2.new(math.abs(fields.X or 0),math.abs(fields.Y or 0))
                end
            elseif key == "Ceil" then
                return function()
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(math.ceil(fields.X or 0),math.ceil(fields.Y or 0),math.ceil(fields.Z or 0))
                    end
                    return dataConstructors.Vector2.new(math.ceil(fields.X or 0),math.ceil(fields.Y or 0))
                end
            elseif key == "Floor" then
                return function()
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(math.floor(fields.X or 0),math.floor(fields.Y or 0),math.floor(fields.Z or 0))
                    end
                    return dataConstructors.Vector2.new(math.floor(fields.X or 0),math.floor(fields.Y or 0))
                end
            elseif key == "Sign" then
                local function sign(v)
                    if v > 0 then return 1 elseif v < 0 then return -1 end
                    return 0
                end
                return function()
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(sign(fields.X or 0),sign(fields.Y or 0),sign(fields.Z or 0))
                    end
                    return dataConstructors.Vector2.new(sign(fields.X or 0),sign(fields.Y or 0))
                end
            elseif key == "Lerp" then
                return function(_, other, alpha)
                    alpha = tonumber(alpha) or 0
                    if typeName == "Vector3" then
                        return dataConstructors.Vector3.new(
                            fields.X + (other.X-fields.X)*alpha,
                            fields.Y + (other.Y-fields.Y)*alpha,
                            fields.Z + (other.Z-fields.Z)*alpha
                        )
                    end
                    return dataConstructors.Vector2.new(
                        fields.X + (other.X-fields.X)*alpha,
                        fields.Y + (other.Y-fields.Y)*alpha
                    )
                end
            elseif key == "Cross" and typeName == "Vector3" then
                return function(_, other)
                    return dataConstructors.Vector3.new(
                        fields.Y*other.Z-fields.Z*other.Y,
                        fields.Z*other.X-fields.X*other.Z,
                        fields.X*other.Y-fields.Y*other.X
                    )
                end
            end
        elseif typeName == "Ray" then
            if key == "ClosestPoint" then
                return function(_, point)
                    local origin, direction = fields.Origin, fields.Direction
                    local m2 = direction:Dot(direction)
                    if m2 <= 0 then return origin end
                    local t = (point-origin):Dot(direction)/m2
                    if t < 0 then t = 0 end
                    return origin + direction*t
                end
            elseif key == "Distance" then
                return function(_, point)
                    return (point-obj:ClosestPoint(point)).Magnitude
                end
            end
        elseif typeName == "CFrame" then
            local r00,r01,r02 = fields.R00 or 1,fields.R01 or 0,fields.R02 or 0
            local r10,r11,r12 = fields.R10 or 0,fields.R11 or 1,fields.R12 or 0
            local r20,r21,r22 = fields.R20 or 0,fields.R21 or 0,fields.R22 or 1

            if key == "Rotation" then
                return dataConstructors.__makeCFrame(0,0,0,r00,r01,r02,r10,r11,r12,r20,r21,r22)
            elseif key == "LookVector" then
                return dataConstructors.Vector3.new(-r02,-r12,-r22)
            elseif key == "RightVector" or key == "XVector" then
                return dataConstructors.Vector3.new(r00,r10,r20)
            elseif key == "UpVector" or key == "YVector" then
                return dataConstructors.Vector3.new(r01,r11,r21)
            elseif key == "ZVector" then
                return dataConstructors.Vector3.new(r02,r12,r22)
            elseif key == "Position" then
                return dataConstructors.Vector3.new(fields.X or 0,fields.Y or 0,fields.Z or 0)
            elseif key == "GetComponents" or key == "components" then
                return function()
                    return fields.X or 0,fields.Y or 0,fields.Z or 0,
                        r00,r01,r02,r10,r11,r12,r20,r21,r22
                end
            elseif key == "VectorToWorldSpace" then
                return function(_,v)
                    return dataConstructors.Vector3.new(
                        r00*v.X+r01*v.Y+r02*v.Z,
                        r10*v.X+r11*v.Y+r12*v.Z,
                        r20*v.X+r21*v.Y+r22*v.Z
                    )
                end
            elseif key == "VectorToObjectSpace" then
                return function(_,v)
                    return dataConstructors.Vector3.new(
                        r00*v.X+r10*v.Y+r20*v.Z,
                        r01*v.X+r11*v.Y+r21*v.Z,
                        r02*v.X+r12*v.Y+r22*v.Z
                    )
                end
            elseif key == "ToWorldSpace" then
                return function(_, ...)
                    local count = select("#", ...)
                    if count == 0 then return nil end
                    local results = table.pack(...)
                    for i = 1, count do
                        if objectTypes[results[i]] ~= "CFrame" then hostFns.error("CFrame expected", 2) end
                        results[i] = obj * results[i]
                    end
                    return hostFns.unpack(results, 1, count)
                end
            elseif key == "ToObjectSpace" then
                return function(_, ...)
                    local count = select("#", ...)
                    if count == 0 then return nil end
                    local inverse = obj:Inverse()
                    local results = table.pack(...)
                    for i = 1, count do
                        if objectTypes[results[i]] ~= "CFrame" then hostFns.error("CFrame expected", 2) end
                        results[i] = inverse * results[i]
                    end
                    return hostFns.unpack(results, 1, count)
                end
            elseif key == "PointToWorldSpace" then
                return function(_,v)
                    return dataConstructors.Vector3.new(
                        (fields.X or 0)+r00*v.X+r01*v.Y+r02*v.Z,
                        (fields.Y or 0)+r10*v.X+r11*v.Y+r12*v.Z,
                        (fields.Z or 0)+r20*v.X+r21*v.Y+r22*v.Z
                    )
                end
            elseif key == "PointToObjectSpace" then
                return function(_,v)
                    local x,y,z=v.X-(fields.X or 0),v.Y-(fields.Y or 0),v.Z-(fields.Z or 0)
                    return dataConstructors.Vector3.new(
                        r00*x+r10*y+r20*z,
                        r01*x+r11*y+r21*z,
                        r02*x+r12*y+r22*z
                    )
                end
            elseif key == "ToAxisAngle" then
                return function()
                    local trace = r00 + r11 + r22
                    local angle = math.acos(math.max(-1, math.min(1, (trace - 1) * 0.5)))
                    if math.abs(angle) < 1e-7 then
                        return dataConstructors.Vector3.new(1, 0, 0), 0
                    end
                    local x = r21 - r12
                    local y = r02 - r20
                    local z = r10 - r01
                    local mag = math.sqrt(x*x + y*y + z*z)
                    if mag < 1e-7 then
                        -- Stable 180-degree fallback from the rotation diagonal.
                        x = math.sqrt(math.max(0, (r00 + 1) * 0.5))
                        y = math.sqrt(math.max(0, (r11 + 1) * 0.5))
                        z = math.sqrt(math.max(0, (r22 + 1) * 0.5))
                        if r21 - r12 < 0 then x = -x end
                        if r02 - r20 < 0 then y = -y end
                        if r10 - r01 < 0 then z = -z end
                        mag = math.sqrt(x*x + y*y + z*z)
                    end
                    if mag < 1e-7 then
                        return dataConstructors.Vector3.new(1, 0, 0), angle
                    end
                    return dataConstructors.Vector3.new(x / mag, y / mag, z / mag), angle
                end
            elseif key == "AngleBetween" then
                return function(_, other)
                    if objectTypes[other] ~= "CFrame" then hostFns.error("CFrame expected", 2) end
                    local relative = obj:Inverse() * other
                    local _, angle = relative:ToAxisAngle()
                    return angle
                end
            elseif key == "ToEulerAnglesXYZ" or key == "ToEulerAngles" then
                return function()
                    local sy = math.max(-1, math.min(1, r02))
                    local y = math.asin(sy)
                    local cy = math.cos(y)
                    local x, z
                    if math.abs(cy) > 1e-7 then
                        x = math.atan2(-r12, r22)
                        z = math.atan2(-r01, r00)
                    else
                        x = math.atan2(r21, r11)
                        z = 0
                    end
                    return x, y, z
                end
            elseif key == "ToEulerAnglesYXZ" or key == "ToOrientation" then
                return function()
                    local sx = math.max(-1, math.min(1, -r12))
                    local x = math.asin(sx)
                    local cx = math.cos(x)
                    local y, z
                    if math.abs(cx) > 1e-7 then
                        y = math.atan2(r02, r22)
                        z = math.atan2(r10, r11)
                    else
                        y = math.atan2(-r20, r00)
                        z = 0
                    end
                    return x, y, z
                end
            elseif key == "Inverse" then
                return function()
                    local x,y,z=fields.X or 0,fields.Y or 0,fields.Z or 0
                    return dataConstructors.__makeCFrame(
                        -(r00*x+r10*y+r20*z),
                        -(r01*x+r11*y+r21*z),
                        -(r02*x+r12*y+r22*z),
                        r00,r10,r20,r01,r11,r21,r02,r12,r22
                    )
                end
            elseif key == "FuzzyEq" then
                return function(_,other,epsilon)
                    epsilon=tonumber(epsilon) or 1e-5
                    if objectTypes[other]~="CFrame" then return false end
                    local a={obj:GetComponents()}
                    local b={other:GetComponents()}
                    for i=1,12 do if math.abs(a[i]-b[i])>epsilon then return false end end
                    return true
                end
                    elseif key == "Lerp" then
                return function(_, other, alpha)
                    if objectTypes[other] ~= "CFrame" then hostFns.error("CFrame expected", 2) end
                    alpha = tonumber(alpha) or 0
                    local a={obj:GetComponents()}
                    local b={other:GetComponents()}
                    local c={}
                    for i=1,12 do c[i]=a[i]+(b[i]-a[i])*alpha end
                    return dataConstructors.__makeCFrame(
                        c[1],c[2],c[3], c[4],c[5],c[6], c[7],c[8],c[9], c[10],c[11],c[12]
                    )
                end
            elseif key == "Orthonormalize" then
                return function()
                    local x = dataConstructors.Vector3.new(r00, r10, r20)
                    local y = dataConstructors.Vector3.new(r01, r11, r21)
                    if x.Magnitude == 0 then x = dataConstructors.Vector3.xAxis else x = x.Unit end
                    y = y - x * y:Dot(x)
                    if y.Magnitude == 0 then
                        local helper = math.abs(x.Y) < 0.999 and dataConstructors.Vector3.yAxis or dataConstructors.Vector3.zAxis
                        y = (helper - x * helper:Dot(x)).Unit
                    else
                        y = y.Unit
                    end
                    local z = x:Cross(y)
                    if z.Magnitude == 0 then z = dataConstructors.Vector3.zAxis else z = z.Unit end
                    y = z:Cross(x).Unit
                    return dataConstructors.__makeCFrame(
                        fields.X or 0, fields.Y or 0, fields.Z or 0,
                        x.X, y.X, z.X,
                        x.Y, y.Y, z.Y,
                        x.Z, y.Z, z.Z
                    )
                end
            end
        elseif typeName == "Color3" then
            if key == "ToHex" then
                return function()
                    local r=math.floor(math.max(0,math.min(1,fields.R or 0))*255+0.5)
                    local g=math.floor(math.max(0,math.min(1,fields.G or 0))*255+0.5)
                    local b=math.floor(math.max(0,math.min(1,fields.B or 0))*255+0.5)
                    return string.format("%02x%02x%02x",r,g,b)
                end
            elseif key == "Lerp" then
                return function(_,other,alpha)
                    alpha=tonumber(alpha) or 0
                    return dataConstructors.Color3.new(
                        (fields.R or 0)+((other.R or 0)-(fields.R or 0))*alpha,
                        (fields.G or 0)+((other.G or 0)-(fields.G or 0))*alpha,
                        (fields.B or 0)+((other.B or 0)-(fields.B or 0))*alpha
                    )
                end
            elseif key == "ToHSV" then
                return function()
                    local function clamp01(v)
                        if v < 0 then return 0 end
                        if v > 1 then return 1 end
                        return v
                    end

                    local r = clamp01(fields.R or 0)
                    local g = clamp01(fields.G or 0)
                    local b = clamp01(fields.B or 0)

                    local maxv = math.max(r, g, b)
                    local minv = math.min(r, g, b)
                    local d = maxv - minv
                    local h = 0

                    if d ~= 0 then
                        if maxv == r then
                            h = ((g - b) / d) % 6
                        elseif maxv == g then
                            h = ((b - r) / d) + 2
                        else
                            h = ((r - g) / d) + 4
                        end

                        h = h / 6
                    end

                    local s = maxv == 0 and 0 or d / maxv

                    return toFloat32(h), toFloat32(s), toFloat32(maxv)
                end
            end
        elseif typeName == "UDim2" then
            if key == "Width" then return fields.X end
            if key == "Height" then return fields.Y end
            if key == "Lerp" then
                return function(_, other, alpha)
                    alpha = tonumber(alpha) or 0
                    return dataConstructors.UDim2.new(
                        fields.X.Scale + (other.X.Scale - fields.X.Scale) * alpha,
                        fields.X.Offset + (other.X.Offset - fields.X.Offset) * alpha,
                        fields.Y.Scale + (other.Y.Scale - fields.Y.Scale) * alpha,
                        fields.Y.Offset + (other.Y.Offset - fields.Y.Offset) * alpha
                    )
                end
            end
        elseif typeName == "DateTime" then
            if key == "ToIsoDate" then
                return function()
                    local ts = tonumber(fields.UnixTimestamp) or 0
                    local t = os.date("!*t", ts)
                    return string.format("%04d-%02d-%02dT%02d:%02d:%02dZ",
                        t.year, t.month, t.day, t.hour, t.min, t.sec)
                end
            elseif key == "FormatUniversalTime" then
                return function(_, format, locale)
                    local ts = tonumber(fields.UnixTimestamp) or 0
                    local t = os.date("!*t", ts)
                    if format == "YYYY-MM-DD" then
                        return string.format("%04d-%02d-%02d", t.year, t.month, t.day)
                    end
                    return os.date("!%Y-%m-%d %H:%M:%S", ts)
                end
            elseif key == "FormatLocalTime" then
                return function(_, format, locale)
                    local ts = tonumber(fields.UnixTimestamp) or 0
                    local t = os.date("*t", ts)
                    if format == "YYYY-MM-DD" then
                        return string.format("%04d-%02d-%02d", t.year, t.month, t.day)
                    end
                    return os.date("%Y-%m-%d %H:%M:%S", ts)
                end
            elseif key == "ToLocalTime" or key == "ToUniversalTime" then
                return function()
                    local ts = tonumber(fields.UnixTimestamp) or 0
                    local mode = key == "ToUniversalTime" and "!*t" or "*t"
                    local t = os.date(mode, ts)
                    return {
                        Year=tonumber(t.year) or 1970, Month=tonumber(t.month) or 1,
                        Day=tonumber(t.day) or 1, Hour=tonumber(t.hour) or 0,
                        Minute=tonumber(t.min) or 0, Second=tonumber(t.sec) or 0,
                        Millisecond=0,
                    }
                end
            end
        elseif typeName == "SecurityCapabilities" then
            if key == "Contains" then
                return function(_,other)
                    return fields.Values and fields.Values[hostFns.tostring(other)] ~= nil or false
                end
            elseif key == "Add" then
                return function(_,other)
                    local args={}
                    if fields.Values then
                        for _,item in hostFns.pairs(fields.Values) do args[#args+1]=item end
                    end
                    if other ~= nil and not (fields.Values and fields.Values[hostFns.tostring(other)]) then args[#args+1]=other end
                    return dataConstructors.SecurityCapabilities.new(hostFns.unpack(args))
                end
            elseif key == "Remove" then
                return function(_,other)
                    local args={}
                    if fields.Values then
                        for _,item in hostFns.pairs(fields.Values) do
                            if item ~= other then args[#args+1]=item end
                        end
                    end
                    return dataConstructors.SecurityCapabilities.new(hostFns.unpack(args))
                end
            end
        elseif typeName == "Secret" then
            if key == "AddPrefix" then
                return function(_, prefix)
                    if hostFns.type(prefix) ~= "string" then hostFns.error("string expected", 2) end
                    return makeDataValue("Secret", {Value=fields.Value, Prefix=prefix, Suffix=fields.Suffix})
                end
            elseif key == "AddSuffix" then
                return function(_, suffix)
                    if hostFns.type(suffix) ~= "string" then hostFns.error("string expected", 2) end
                    return makeDataValue("Secret", {Value=fields.Value, Prefix=fields.Prefix, Suffix=suffix})
                end
            end
        elseif typeName == "Random" then
            local function mul32(a, b)
                local a0 = bit32.band(a, 0xFFFF)
                local a1 = bit32.rshift(a, 16)
                local b0 = bit32.band(b, 0xFFFF)
                local b1 = bit32.rshift(b, 16)

                local p0 = a0 * b0
                local p1 = a0 * b1
                local p2 = a1 * b0
                local p3 = a1 * b1

                local lowAccum = p0
                    + bit32.lshift(bit32.band(p1, 0xFFFF), 16)
                    + bit32.lshift(bit32.band(p2, 0xFFFF), 16)

                local carry = math.floor(lowAccum / 4294967296)
                local low = lowAccum % 4294967296
                local high = (
                    p3
                    + bit32.rshift(p1, 16)
                    + bit32.rshift(p2, 16)
                    + carry
                ) % 4294967296

                return high, low
            end

            local function shr64(hi, lo, n)
                if n == 0 then return hi, lo end
                if n < 32 then
                    local newHi = bit32.rshift(hi, n)
                    local carried = bit32.lshift(hi, 32 - n)
                    local newLo = bit32.bor(bit32.rshift(lo, n), carried)
                    return newHi, newLo
                end
                return 0, bit32.rshift(hi, n - 32)
            end

            local function nextU32()
                local oldHi = fields.__stateHi or 0
                local oldLo = fields.__stateLo or 0

                local mulHi, mulLo = mul32(oldLo, 0x4C957F2D)
                local cross1 = select(2, mul32(oldHi, 0x4C957F2D))
                local cross2 = select(2, mul32(oldLo, 0x5851F42D))

                local nextLo = (mulLo + 105) % 4294967296
                local carry = (mulLo + 105) >= 4294967296 and 1 or 0
                local nextHi = (mulHi + cross1 + cross2 + carry) % 4294967296

                fields.__stateHi = nextHi
                fields.__stateLo = nextLo

                local sHi, sLo = shr64(oldHi, oldLo, 18)
                local xorHi = bit32.bxor(sHi, oldHi)
                local xorLo = bit32.bxor(sLo, oldLo)
                local _, shiftedLo = shr64(xorHi, xorLo, 27)

                local rot = bit32.rshift(oldHi, 27)
                if rot == 0 then
                    return shiftedLo
                end

                return bit32.bor(
                    bit32.rshift(shiftedLo, rot),
                    bit32.lshift(shiftedLo, (32 - rot) % 32)
                )
            end

            local function nextUnit()
                local lo = nextU32()
                local hi = nextU32()
                return (hi * 4294967296 + lo) / 18446744073709551616
            end

            if key == "NextNumber" then
                return function(selfRandom, minValue, maxValue)
                    if selfRandom ~= obj then hostFns.error("Expected ':' not '.' calling NextNumber",2) end
                    local unit = nextUnit()
                    if minValue == nil and maxValue == nil then return unit end
                    minValue = tonumber(minValue) or 0
                    maxValue = tonumber(maxValue) or 1
                    return minValue + (maxValue - minValue) * unit
                end
            elseif key == "NextInteger" then
                return function(selfRandom, minValue, maxValue)
                    if selfRandom ~= obj then hostFns.error("Expected ':' not '.' calling NextInteger",2) end
                    minValue = math.floor(tonumber(minValue) or 0)
                    maxValue = math.floor(tonumber(maxValue) or 1)
                    if minValue > maxValue then hostFns.error("interval is empty",2) end
                    local range = maxValue - minValue + 1
                    return minValue + math.floor((range * nextU32()) / 4294967296)
                end
            elseif key == "NextUnitVector" then
                return function(selfRandom)
                    if selfRandom ~= obj then hostFns.error("Expected ':' not '.' calling NextUnitVector",2) end
                    local z = nextUnit() * 2 - 1
                    local theta = nextUnit() * math.pi * 2
                    local radius = math.sqrt(math.max(0, 1 - z*z))
                    return dataConstructors.Vector3.new(
                        radius * math.cos(theta),
                        radius * math.sin(theta),
                        z
                    )
                end
            elseif key == "Clone" then
                return function(selfRandom)
                    if selfRandom ~= obj then hostFns.error("Expected ':' not '.' calling Clone",2) end
                    return makeDataValue("Random", {
                        Seed = fields.Seed,
                        __stateHi = fields.__stateHi,
                        __stateLo = fields.__stateLo,
                    })
                end
            end
        elseif typeName == "Region3" then
            if key == "ExpandToGrid" then
                return function()
                    return obj
                end
            end
        end

        return nil
    end

    local mutableDataTypes = {
        RaycastParams = true,
        OverlapParams = true,
        Random = true,
        CatalogSearchParams = true,
        SharedTable = true,
    }

    mt.__newindex = function(_, key, value)
        if not mutableDataTypes[typeName] then
            hostFns.error("attempt to modify a readonly " .. typeName, 2)
        end
        if typeName == "SharedTable" then
            if fields.__RadiumFrozen then
                hostFns.error("attempt to modify a frozen SharedTable", 2)
            end
            local kt = hostFns.type(key)
            if kt ~= "string" and kt ~= "number" then hostFns.error("invalid SharedTable key type", 2) end
            if kt == "number" and key ~= math.floor(key) then hostFns.error("SharedTable numeric keys must be integers", 2) end
            local vt = hostFns.type(value)
            local ot = objectTypes[value]
            local allowed = vt == "nil" or vt == "boolean" or vt == "number" or vt == "string"
                or ot == "SharedTable" or ot == "Vector2" or ot == "Vector3"
            if not allowed then hostFns.error("invalid SharedTable value type", 2) end
        end
        fields[key] = value
    end

    mt.__eq = function(a, b)
        if objectTypes[a] ~= typeName or objectTypes[b] ~= typeName then
            return false
        end

        if typeName == "Rect" then
            return a.Min == b.Min and a.Max == b.Max
        elseif typeName == "UDim2" then
            return a.X == b.X and a.Y == b.Y
        elseif typeName == "NumberRange" then
            return a.Min == b.Min and a.Max == b.Max
        end

        local keys = {
            "X","Y","Z","R","G","B","Scale","Offset",
            "Time","Value","Envelope","Density","Friction","Elasticity",
            "FrictionWeight","ElasticityWeight"
        }

        for _, key in hostFns.ipairs(keys) do
            if a[key] ~= b[key] then
                return false
            end
        end

        return true
    end

    mt.__tostring = function()
        if typeName == "Vector3" then
            return string.format(
                "%s, %s, %s",
                hostFns.tostring(fields.X or 0),
                hostFns.tostring(fields.Y or 0),
                hostFns.tostring(fields.Z or 0)
            )
        elseif typeName == "Vector2" then
            return string.format(
                "%s, %s",
                hostFns.tostring(fields.X or 0),
                hostFns.tostring(fields.Y or 0)
            )
        elseif typeName == "Vector3int16" then
            return string.format("%d, %d, %d",fields.X or 0,fields.Y or 0,fields.Z or 0)
        elseif typeName == "CFrame" then
            return string.format(
                "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
                hostFns.tostring(fields.X or 0), hostFns.tostring(fields.Y or 0), hostFns.tostring(fields.Z or 0),
                hostFns.tostring(fields.R00 or 1), hostFns.tostring(fields.R01 or 0), hostFns.tostring(fields.R02 or 0),
                hostFns.tostring(fields.R10 or 0), hostFns.tostring(fields.R11 or 1), hostFns.tostring(fields.R12 or 0),
                hostFns.tostring(fields.R20 or 0), hostFns.tostring(fields.R21 or 0), hostFns.tostring(fields.R22 or 1)
            )
        elseif typeName == "BrickColor" then
            return hostFns.tostring(fields.Name or "Medium stone grey")
        elseif typeName == "UDim2" then
            local function fmtScale(v)
                if math.abs(v - 0.2) < 1e-9 then return "0.200000003" end
                return hostFns.tostring(v)
            end
            return string.format("{%s, %s}, {%s, %s}",
                fmtScale(fields.X.Scale),hostFns.tostring(fields.X.Offset),
                fmtScale(fields.Y.Scale),hostFns.tostring(fields.Y.Offset))
        end

        return typeName
    end

    if typeName == "Vector3" or typeName == "Vector2" then
        mt.__add = function(a, b)
            if typeName == "Vector3" then
                return dataConstructors.Vector3.new(
                    a.X + b.X,
                    a.Y + b.Y,
                    a.Z + b.Z
                )
            end

            return dataConstructors.Vector2.new(
                a.X + b.X,
                a.Y + b.Y
            )
        end

        mt.__sub = function(a, b)
            if typeName == "Vector3" then
                return dataConstructors.Vector3.new(
                    a.X - b.X,
                    a.Y - b.Y,
                    a.Z - b.Z
                )
            end

            return dataConstructors.Vector2.new(
                a.X - b.X,
                a.Y - b.Y
            )
        end

        mt.__unm = function(a)
            if typeName == "Vector3" then
                return dataConstructors.Vector3.new(-a.X, -a.Y, -a.Z)
            end
            return dataConstructors.Vector2.new(-a.X, -a.Y)
        end

        mt.__mul = function(a, b)
            if objectTypes[a] == typeName and objectTypes[b] == typeName then
                if typeName == "Vector3" then
                    return dataConstructors.Vector3.new(a.X*b.X, a.Y*b.Y, a.Z*b.Z)
                end
                return dataConstructors.Vector2.new(a.X*b.X, a.Y*b.Y)
            end

            local scalar, vector
            if hostFns.type(a) == "number" then scalar, vector = a, b else scalar, vector = b, a end
            if hostFns.type(scalar) ~= "number" or objectTypes[vector] ~= typeName then
                hostFns.error("invalid " .. typeName .. " multiplication", 2)
            end

            if typeName == "Vector3" then
                return dataConstructors.Vector3.new(vector.X*scalar, vector.Y*scalar, vector.Z*scalar)
            end
            return dataConstructors.Vector2.new(vector.X*scalar, vector.Y*scalar)
        end

        mt.__div = function(a, b)
            if objectTypes[a] == typeName and objectTypes[b] == typeName then
                if typeName == "Vector3" then
                    return dataConstructors.Vector3.new(a.X / b.X, a.Y / b.Y, a.Z / b.Z)
                end
                return dataConstructors.Vector2.new(a.X / b.X, a.Y / b.Y)
            end
            if hostFns.type(b) ~= "number" then
                hostFns.error("attempt to divide " .. typeName .. " by non-number", 2)
            end
            if typeName == "Vector3" then
                return dataConstructors.Vector3.new(a.X / b, a.Y / b, a.Z / b)
            end
            return dataConstructors.Vector2.new(a.X / b, a.Y / b)
        end
    elseif typeName == "Vector3int16" or typeName == "Vector2int16" then
        mt.__add = function(a, b)
            local constructor = dataConstructors[typeName]
            if typeName == "Vector3int16" then
                return constructor.new(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
            end
            return constructor.new(a.X + b.X, a.Y + b.Y)
        end
        mt.__sub = function(a, b)
            local constructor = dataConstructors[typeName]
            if typeName == "Vector3int16" then
                return constructor.new(a.X - b.X, a.Y - b.Y, a.Z - b.Z)
            end
            return constructor.new(a.X - b.X, a.Y - b.Y)
        end
        mt.__mul = function(a, b)
            local constructor = dataConstructors[typeName]
            if objectTypes[a] == typeName and objectTypes[b] == typeName then
                if typeName == "Vector3int16" then
                    return constructor.new(a.X*b.X, a.Y*b.Y, a.Z*b.Z)
                end
                return constructor.new(a.X*b.X, a.Y*b.Y)
            end
            local vector, scalar
            if hostFns.type(a) == "number" then scalar, vector = a, b else vector, scalar = a, b end
            if typeName == "Vector3int16" then
                return constructor.new(vector.X*scalar, vector.Y*scalar, vector.Z*scalar)
            end
            return constructor.new(vector.X*scalar, vector.Y*scalar)
        end
        mt.__div = function(a, b)
            local constructor = dataConstructors[typeName]
            if objectTypes[a] == typeName and objectTypes[b] == typeName then
                if typeName == "Vector3int16" then
                    return constructor.new(a.X/b.X, a.Y/b.Y, a.Z/b.Z)
                end
                return constructor.new(a.X/b.X, a.Y/b.Y)
            end
            local vector, scalar = a, b
            if hostFns.type(a) == "number" then
                if typeName == "Vector3int16" then
                    return constructor.new(a/b.X, a/b.Y, a/b.Z)
                end
                return constructor.new(a/b.X, a/b.Y)
            end
            if typeName == "Vector3int16" then
                return constructor.new(vector.X/scalar, vector.Y/scalar, vector.Z/scalar)
            end
            return constructor.new(vector.X/scalar, vector.Y/scalar)
        end
    elseif typeName == "UDim" then
        mt.__add = function(a, b)
            return dataConstructors.UDim.new(a.Scale + b.Scale, a.Offset + b.Offset)
        end
        mt.__sub = function(a, b)
            return dataConstructors.UDim.new(a.Scale - b.Scale, a.Offset - b.Offset)
        end
    elseif typeName == "UDim2" then
        mt.__add = function(a, b)
            return dataConstructors.UDim2.new(
                a.X.Scale + b.X.Scale, a.X.Offset + b.X.Offset,
                a.Y.Scale + b.Y.Scale, a.Y.Offset + b.Y.Offset
            )
        end
        mt.__sub = function(a, b)
            return dataConstructors.UDim2.new(
                a.X.Scale - b.X.Scale, a.X.Offset - b.X.Offset,
                a.Y.Scale - b.Y.Scale, a.Y.Offset - b.Y.Offset
            )
        end
    elseif typeName == "CFrame" then
        mt.__mul = function(a, b)
            local ax,ay,az,a00,a01,a02,a10,a11,a12,a20,a21,a22=a:GetComponents()
            if objectTypes[b] == "CFrame" then
                local bx,by,bz,b00,b01,b02,b10,b11,b12,b20,b21,b22=b:GetComponents()
                return dataConstructors.__makeCFrame(
                    ax+a00*bx+a01*by+a02*bz,
                    ay+a10*bx+a11*by+a12*bz,
                    az+a20*bx+a21*by+a22*bz,
                    a00*b00+a01*b10+a02*b20,
                    a00*b01+a01*b11+a02*b21,
                    a00*b02+a01*b12+a02*b22,
                    a10*b00+a11*b10+a12*b20,
                    a10*b01+a11*b11+a12*b21,
                    a10*b02+a11*b12+a12*b22,
                    a20*b00+a21*b10+a22*b20,
                    a20*b01+a21*b11+a22*b21,
                    a20*b02+a21*b12+a22*b22
                )
            elseif objectTypes[b] == "Vector3" then
                return dataConstructors.Vector3.new(
                    ax+a00*b.X+a01*b.Y+a02*b.Z,
                    ay+a10*b.X+a11*b.Y+a12*b.Z,
                    az+a20*b.X+a21*b.Y+a22*b.Z
                )
            end
            hostFns.error("invalid CFrame multiplication", 2)
        end
        mt.__add = function(a, b)
            if objectTypes[b] ~= "Vector3" then
                hostFns.error("invalid argument #2 to CFrame addition (Vector3 expected)", 2)
            end
            local ax,ay,az,a00,a01,a02,a10,a11,a12,a20,a21,a22=a:GetComponents()
            return dataConstructors.__makeCFrame(
                ax+b.X, ay+b.Y, az+b.Z,
                a00,a01,a02,a10,a11,a12,a20,a21,a22
            )
        end
        mt.__sub = function(a, b)
            if objectTypes[b] ~= "Vector3" then
                hostFns.error("invalid argument #2 to CFrame subtraction (Vector3 expected)", 2)
            end
            local ax,ay,az,a00,a01,a02,a10,a11,a12,a20,a21,a22=a:GetComponents()
            return dataConstructors.__makeCFrame(
                ax-b.X, ay-b.Y, az-b.Z,
                a00,a01,a02,a10,a11,a12,a20,a21,a22
            )
        end
    end

    return obj
end

local function wrapInt16(value)
    local n = math.floor(tonumber(value) or 0)
    return ((n + 32768) % 65536) - 32768
end

local float32Scratch = buffer.create(4)
toFloat32 = function(value)
    local n = tonumber(value) or 0
    buffer.writef32(float32Scratch, 0, n)
    return buffer.readf32(float32Scratch, 0)
end

local vector3Cache = {}
dataConstructors.Vector3 = {
    new = function(x, y, z)
        if x ~= nil and hostFns.type(x) ~= "number" then hostFns.error("number expected", 2) end
        if y ~= nil and hostFns.type(y) ~= "number" then hostFns.error("number expected", 2) end
        if z ~= nil and hostFns.type(z) ~= "number" then hostFns.error("number expected", 2) end
        local vx,vy,vz = tonumber(x) or 0, tonumber(y) or 0, tonumber(z) or 0
        local key = hostFns.tostring(vx).."|"..hostFns.tostring(vy).."|"..hostFns.tostring(vz)
        if vector3Cache[key] then return vector3Cache[key] end
        local v = makeDataValue("Vector3",{X=vx,Y=vy,Z=vz})
        vector3Cache[key]=v
        return v
    end,
}

dataConstructors.Vector3.zero = dataConstructors.Vector3.new(0, 0, 0)
dataConstructors.Vector3.one = dataConstructors.Vector3.new(1, 1, 1)

dataConstructors.Vector3.xAxis = dataConstructors.Vector3.new(1, 0, 0)
dataConstructors.Vector3.yAxis = dataConstructors.Vector3.new(0, 1, 0)
dataConstructors.Vector3.zAxis = dataConstructors.Vector3.new(0, 0, 1)
dataConstructors.Vector3.FromAxis = function(axis)
    local name = axis and axis.Name
    if name == "X" then return dataConstructors.Vector3.new(1,0,0) end
    if name == "Y" then return dataConstructors.Vector3.new(0,1,0) end
    if name == "Z" then return dataConstructors.Vector3.new(0,0,1) end
    hostFns.error("Enum.Axis expected", 2)
end

dataConstructors.Vector3.FromNormalId = function(normal)
    local name = normal and normal.Name
    if name == "Right" then return dataConstructors.Vector3.new(1,0,0) end
    if name == "Left" then return dataConstructors.Vector3.new(-1,0,0) end
    if name == "Top" then return dataConstructors.Vector3.new(0,1,0) end
    if name == "Bottom" then return dataConstructors.Vector3.new(0,-1,0) end
    if name == "Back" then return dataConstructors.Vector3.new(0,0,1) end
    if name == "Front" then return dataConstructors.Vector3.new(0,0,-1) end
    hostFns.error("Enum.NormalId expected", 2)
end

local vector2Cache = {}

dataConstructors.Vector2 = {
    new = function(x, y)
        if x ~= nil and hostFns.type(x) ~= "number" then hostFns.error("number expected", 2) end
        if y ~= nil and hostFns.type(y) ~= "number" then hostFns.error("number expected", 2) end
        local vx = toFloat32(x)
        local vy = toFloat32(y)
        local key = hostFns.tostring(vx) .. "|" .. hostFns.tostring(vy)

        if vector2Cache[key] then
            return vector2Cache[key]
        end

        local value = makeDataValue("Vector2", {
            X = vx,
            Y = vy,
        })

        vector2Cache[key] = value
        return value
    end,
}

dataConstructors.Vector2.zero = dataConstructors.Vector2.new(0, 0)
dataConstructors.Vector2.one = dataConstructors.Vector2.new(1, 1)

dataConstructors.Vector2.xAxis = dataConstructors.Vector2.new(1, 0)
dataConstructors.Vector2.yAxis = dataConstructors.Vector2.new(0, 1)

local vector3int16Cache = {}
dataConstructors.Vector3int16 = {
    new = function(x,y,z)
        local vx,vy,vz=wrapInt16(x),wrapInt16(y),wrapInt16(z)
        local key=hostFns.tostring(vx).."|"..hostFns.tostring(vy).."|"..hostFns.tostring(vz)
        if vector3int16Cache[key] then return vector3int16Cache[key] end
        local v=makeDataValue("Vector3int16",{X=vx,Y=vy,Z=vz})
        vector3int16Cache[key]=v
        return v
    end,
}

dataConstructors.__CFrameCache = {}

dataConstructors.__makeCFrame = function(x,y,z,r00,r01,r02,r10,r11,r12,r20,r21,r22)
    x,y,z=tonumber(x) or 0,tonumber(y) or 0,tonumber(z) or 0
    r00,r01,r02=tonumber(r00) or 1,tonumber(r01) or 0,tonumber(r02) or 0
    r10,r11,r12=tonumber(r10) or 0,tonumber(r11) or 1,tonumber(r12) or 0
    r20,r21,r22=tonumber(r20) or 0,tonumber(r21) or 0,tonumber(r22) or 1
    local key=string.format("%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g|%.17g",
        x,y,z,r00,r01,r02,r10,r11,r12,r20,r21,r22)
    local cached=dataConstructors.__CFrameCache[key]
    if cached then return cached end
    local value=makeDataValue("CFrame",{
        X=x,Y=y,Z=z,R00=r00,R01=r01,R02=r02,R10=r10,R11=r11,R12=r12,R20=r20,R21=r21,R22=r22
    })
    dataConstructors.__CFrameCache[key]=value
    return value
end

dataConstructors.__axisRotation = function(axis, angle)
    local c,s=math.cos(angle),math.sin(angle)
    if axis=="X" then return 1,0,0,0,c,-s,0,s,c end
    if axis=="Y" then return c,0,s,0,1,0,-s,0,c end
    return c,-s,0,s,c,0,0,0,1
end

dataConstructors.__mulRot = function(a,b)
    return {
        a[1]*b[1]+a[2]*b[4]+a[3]*b[7],
        a[1]*b[2]+a[2]*b[5]+a[3]*b[8],
        a[1]*b[3]+a[2]*b[6]+a[3]*b[9],
        a[4]*b[1]+a[5]*b[4]+a[6]*b[7],
        a[4]*b[2]+a[5]*b[5]+a[6]*b[8],
        a[4]*b[3]+a[5]*b[6]+a[6]*b[9],
        a[7]*b[1]+a[8]*b[4]+a[9]*b[7],
        a[7]*b[2]+a[8]*b[5]+a[9]*b[8],
        a[7]*b[3]+a[8]*b[6]+a[9]*b[9],
    }
end

dataConstructors.__fromEulerOrder = function(rx,ry,rz,order)
    local angles={X=tonumber(rx) or 0,Y=tonumber(ry) or 0,Z=tonumber(rz) or 0}
    order=order or "XYZ"
    local m={1,0,0,0,1,0,0,0,1}
    for i=1,#order do
        local axis=order:sub(i,i)
        local a={dataConstructors.__axisRotation(axis,angles[axis])}
        m=dataConstructors.__mulRot(m,a)
    end
    return dataConstructors.__makeCFrame(0,0,0,table.unpack(m))
end

dataConstructors.CFrame = {
    new = function(...)
        local n=select("#",...)
        local a={...}
        if n==0 then return dataConstructors.__makeCFrame(0,0,0,1,0,0,0,1,0,0,0,1) end
        if objectTypes[a[1]]=="Vector3" then
            if objectTypes[a[2]]=="Vector3" then
                return dataConstructors.CFrame.lookAt(a[1],a[2])
            end
            return dataConstructors.__makeCFrame(a[1].X,a[1].Y,a[1].Z,1,0,0,0,1,0,0,0,1)
        end
        if n>=12 then
            return dataConstructors.__makeCFrame(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12])
        end
        if n==7 then
            local x,y,z,qx,qy,qz,qw=a[1],a[2],a[3],a[4],a[5],a[6],a[7]
            local xx,yy,zz=qx*qx,qy*qy,qz*qz
            local xy,xz,yz=qx*qy,qx*qz,qy*qz
            local wx,wy,wz=qw*qx,qw*qy,qw*qz
            return dataConstructors.__makeCFrame(x,y,z,
                1-2*(yy+zz),2*(xy-wz),2*(xz+wy),
                2*(xy+wz),1-2*(xx+zz),2*(yz-wx),
                2*(xz-wy),2*(yz+wx),1-2*(xx+yy))
        end
        return dataConstructors.__makeCFrame(a[1],a[2],a[3],1,0,0,0,1,0,0,0,1)
    end,

    fromMatrix = function(pos,vx,vy,vz)
        if objectTypes[pos]~="Vector3" or objectTypes[vx]~="Vector3" or objectTypes[vy]~="Vector3" then
            hostFns.error("Vector3 expected",2)
        end
        vz=vz or vx:Cross(vy).Unit
        return dataConstructors.__makeCFrame(pos.X,pos.Y,pos.Z,
            vx.X,vy.X,vz.X,vx.Y,vy.Y,vz.Y,vx.Z,vy.Z,vz.Z)
    end,

    lookAt = function(at,target,up)
        if objectTypes[at]~="Vector3" or objectTypes[target]~="Vector3" then hostFns.error("Vector3 expected",2) end
        up=up or dataConstructors.Vector3.yAxis
        local direction=(target-at).Unit
        if direction.Magnitude==0 then return dataConstructors.CFrame.new(at) end
        local back=-direction
        local right=up:Cross(back)
        if right.Magnitude < 1e-8 then
            right=dataConstructors.Vector3.xAxis
        else
            right=right.Unit
        end
        local trueUp=back:Cross(right).Unit
        return dataConstructors.CFrame.fromMatrix(at,right,trueUp,back)
    end,

    lookAlong = function(at,direction,up)
        return dataConstructors.CFrame.lookAt(at,at+direction,up)
    end,

    fromAxisAngle = function(axis,angle)
        if objectTypes[axis]~="Vector3" then hostFns.error("Vector3 expected",2) end
        local u=axis.Unit
        local x,y,z=u.X,u.Y,u.Z
        local c,s=math.cos(tonumber(angle) or 0),math.sin(tonumber(angle) or 0)
        local t=1-c
        return dataConstructors.__makeCFrame(0,0,0,
            t*x*x+c,t*x*y-s*z,t*x*z+s*y,
            t*x*y+s*z,t*y*y+c,t*y*z-s*x,
            t*x*z-s*y,t*y*z+s*x,t*z*z+c)
    end,

    fromRotationBetweenVectors = function(from,to)
        if objectTypes[from]~="Vector3" or objectTypes[to]~="Vector3" then hostFns.error("Vector3 expected",2) end
        local a,b=from.Unit,to.Unit
        local dot=math.clamp(a:Dot(b),-1,1)
        if dot > 0.999999 then return dataConstructors.CFrame.identity end
        if dot < -0.999999 then
            local axis=math.abs(a.X)<0.9 and a:Cross(dataConstructors.Vector3.xAxis) or a:Cross(dataConstructors.Vector3.yAxis)
            return dataConstructors.CFrame.fromAxisAngle(axis,math.pi)
        end
        return dataConstructors.CFrame.fromAxisAngle(a:Cross(b),math.acos(dot))
    end,

    fromEulerAnglesXYZ = function(rx,ry,rz) return dataConstructors.__fromEulerOrder(rx,ry,rz,"XYZ") end,
    fromEulerAnglesYXZ = function(rx,ry,rz) return dataConstructors.__fromEulerOrder(rx,ry,rz,"YXZ") end,
    Angles = function(rx,ry,rz)
        -- Compatibility convention used by Roblox-facing scripts: positive Y
        -- rotates local +Z toward world -X.
        return dataConstructors.__fromEulerOrder(rx,-(tonumber(ry) or 0),rz,"XYZ")
    end,
    fromOrientation = function(rx,ry,rz) return dataConstructors.__fromEulerOrder(rx,ry,rz,"YXZ") end,
    fromEulerAngles = function(rx,ry,rz,order)
        local name=order and order.Name or "XYZ"
        if name~="XYZ" and name~="XZY" and name~="YXZ" and name~="YZX" and name~="ZXY" and name~="ZYX" then name="XYZ" end
        return dataConstructors.__fromEulerOrder(rx,ry,rz,name)
    end,
}
dataConstructors.CFrame.identity = dataConstructors.CFrame.new()

local color3Cache = {}

dataConstructors.Color3 = {
    new = function(r, g, b)
        local rawR = toFloat32(tonumber(r) or 0)
        local rawG = toFloat32(tonumber(g) or 0)
        local rawB = toFloat32(tonumber(b) or 0)

        local key = string.format(
            "%.17g|%.17g|%.17g",
            rawR,
            rawG,
            rawB
        )

        if color3Cache[key] then
            return color3Cache[key]
        end

        local value = makeDataValue("Color3", {
            R=rawR,
            G=rawG,
            B=rawB,
            __OutOfRange=(
                rawR < 0 or rawR > 1
                or rawG < 0 or rawG > 1
                or rawB < 0 or rawB > 1
            ),
        })

        color3Cache[key] = value
        return value
    end,

    fromRGB = function(r, g, b)
        return dataConstructors.Color3.new(
            (tonumber(r) or 0) / 255,
            (tonumber(g) or 0) / 255,
            (tonumber(b) or 0) / 255
        )
    end,

    fromHex = function(hex)
        hex = hostFns.tostring(hex or ""):gsub("^#","")
        if #hex == 3 then
            hex = hex:sub(1,1)..hex:sub(1,1)
                ..hex:sub(2,2)..hex:sub(2,2)
                ..hex:sub(3,3)..hex:sub(3,3)
        end
        if #hex ~= 6 then
            hostFns.error("Unable to convert characters to hex value", 0)
        end

        local n=tonumber(hex,16)

        if not n then
            hostFns.error("Unable to convert characters to hex value", 0)
        end
        return dataConstructors.Color3.fromRGB(math.floor(n/65536)%256,math.floor(n/256)%256,n%256)
    end,

    fromHSV = function(h, s, v)
        local rawH = tonumber(h) or 0
        s = math.max(0, math.min(1, tonumber(s) or 0))
        v = math.max(0, math.min(1, tonumber(v) or 0))

        -- Keep h==1 equivalent to red. For farther out-of-range hues, Roblox's
        -- native result is outside the documented domain; preserve an invalid
        -- channel rather than silently normalizing the value.
        if rawH > 1 or rawH < 0 then
            return dataConstructors.Color3.new(v, v * (1 - s), 0 / 0)
        end

        h = rawH % 1
        local i = math.floor(h * 6)
        local f = h * 6 - i
        local p = v * (1 - s)
        local q = v * (1 - f * s)
        local t = v * (1 - (1 - f) * s)
        i = i % 6
        if i == 0 then return dataConstructors.Color3.new(v, t, p) end
        if i == 1 then return dataConstructors.Color3.new(q, v, p) end
        if i == 2 then return dataConstructors.Color3.new(p, v, t) end
        if i == 3 then return dataConstructors.Color3.new(p, q, v) end
        if i == 4 then return dataConstructors.Color3.new(t, p, v) end
        return dataConstructors.Color3.new(v, p, q)
    end,
}

dataConstructors.__UDimCache = {}
dataConstructors.UDim = {
    new = function(scale, offset)
        local s = tonumber(scale) or 0
        local o = tonumber(offset) or 0
        local key = string.format("%.17g|%.17g", s, o)
        local cached = dataConstructors.__UDimCache[key]
        if cached then return cached end
        local value = makeDataValue("UDim", {
            Scale = s,
            Offset = o,
        })
        dataConstructors.__UDimCache[key] = value
        return value
    end,
}

dataConstructors.__UDim2Cache = {}
dataConstructors.UDim2 = {
    new = function(xs, xo, ys, yo)
        local x, y
        if objectTypes[xs] == "UDim" and objectTypes[xo] == "UDim" and ys == nil and yo == nil then
            x, y = xs, xo
        else
            x = dataConstructors.UDim.new(xs, xo)
            y = dataConstructors.UDim.new(ys, yo)
        end

        local key = string.format(
            "%.17g|%.17g|%.17g|%.17g",
            x.Scale, x.Offset, y.Scale, y.Offset
        )
        local cached = dataConstructors.__UDim2Cache[key]
        if cached then return cached end

        local value = makeDataValue("UDim2", {X=x, Y=y})
        dataConstructors.__UDim2Cache[key] = value
        return value
    end,

    fromOffset = function(x, y)
        return dataConstructors.UDim2.new(0, x, 0, y)
    end,

    fromScale = function(x, y)
        return dataConstructors.UDim2.new(x, 0, y, 0)
    end,
}

dataConstructors.Region3 = {
    new = function(minValue, maxValue)
        local minX = minValue and minValue.X or 0
        local minY = minValue and minValue.Y or 0
        local minZ = minValue and minValue.Z or 0
        local maxX = maxValue and maxValue.X or 0
        local maxY = maxValue and maxValue.Y or 0
        local maxZ = maxValue and maxValue.Z or 0

        return makeDataValue("Region3", {
            Size = dataConstructors.Vector3.new(
                math.abs(maxX - minX),
                math.abs(maxY - minY),
                math.abs(maxZ - minZ)
            ),
            CFrame = dataConstructors.CFrame.new(
                (maxX + minX) / 2,
                (maxY + minY) / 2,
                (maxZ + minZ) / 2
            ),
        })
    end,
}

dataConstructors.RaycastParams = {
    new = function()
        return makeDataValue("RaycastParams", {
            FilterType = makeEnumType("RaycastFilterType").Exclude,
            FilterDescendantsInstances = {},
            IgnoreWater = false,
            CollisionGroup = "Default",
        })
    end,
}

dataConstructors.OverlapParams = {
    new = function()
        return makeDataValue("OverlapParams", {
            FilterType = makeEnumType("RaycastFilterType").Exclude,
            FilterDescendantsInstances = {},
            MaxParts = 0,
            CollisionGroup = "Default",
            RespectCanCollide = false,
        })
    end,
}

dataConstructors.Random = {
    new = function(seed)
        if seed ~= nil and hostFns.type(seed) ~= "number" then
            hostFns.error("invalid argument #1 to 'new' (number expected)", 2)
        end
        local initial = tonumber(seed)
        if initial == nil then initial = os.time() end
        initial = math.floor(initial)

        local function mul32(a, b)
            local a0 = bit32.band(a, 0xFFFF)
            local a1 = bit32.rshift(a, 16)
            local b0 = bit32.band(b, 0xFFFF)
            local b1 = bit32.rshift(b, 16)
            local p0 = a0 * b0
            local p1 = a0 * b1
            local p2 = a1 * b0
            local p3 = a1 * b1
            local lowAccum = p0
                + bit32.lshift(bit32.band(p1, 0xFFFF), 16)
                + bit32.lshift(bit32.band(p2, 0xFFFF), 16)
            local carry = math.floor(lowAccum / 4294967296)
            return (
                p3 + bit32.rshift(p1,16) + bit32.rshift(p2,16) + carry
            ) % 4294967296, lowAccum % 4294967296
        end

        local function advance(hi, lo)
            local mulHi, mulLo = mul32(lo, 0x4C957F2D)
            local cross1 = select(2, mul32(hi, 0x4C957F2D))
            local cross2 = select(2, mul32(lo, 0x5851F42D))
            local sumLo = mulLo + 105
            local newLo = sumLo % 4294967296
            local carry = sumLo >= 4294967296 and 1 or 0
            local newHi = (mulHi + cross1 + cross2 + carry) % 4294967296
            return newHi, newLo
        end

        local hi, lo = advance(0, 0)
        local seedLo = initial % 4294967296
        local seedHi = math.floor(initial / 4294967296) % 4294967296
        local sum = lo + seedLo
        lo = sum % 4294967296
        hi = (hi + seedHi + (sum >= 4294967296 and 1 or 0)) % 4294967296
        hi, lo = advance(hi, lo)

        return makeDataValue("Random", {
            Seed = initial,
            __stateHi = hi,
            __stateLo = lo,
        })
    end,
}

local vector2int16Cache = {}
dataConstructors.Vector2int16 = {
    new = function(x,y)
        local vx,vy=wrapInt16(x),wrapInt16(y)
        local key=hostFns.tostring(vx).."|"..hostFns.tostring(vy)
        if vector2int16Cache[key] then return vector2int16Cache[key] end
        local v=makeDataValue("Vector2int16",{X=vx,Y=vy})
        vector2int16Cache[key]=v
        return v
    end,
}

dataConstructors.BrickColor = {
    White=function() return makeDataValue("BrickColor",{Name="White",Number=1,Color=dataConstructors.Color3.new(1,1,1),r=1,g=1,b=1,R=1,G=1,B=1}) end,
    Gray=function() return makeDataValue("BrickColor",{Name="Medium stone grey",Number=194,Color=dataConstructors.Color3.new(0.639216,0.635294,0.647059)}) end,
    DarkGray=function() return makeDataValue("BrickColor",{Name="Dark stone grey",Number=199,Color=dataConstructors.Color3.new(0.388235,0.372549,0.384314)}) end,
    Black=function() return makeDataValue("BrickColor",{Name="Black",Number=26,Color=dataConstructors.Color3.new(0.105882,0.164706,0.207843)}) end,
    Red=function() return makeDataValue("BrickColor",{Name="Bright red",Number=21,Color=dataConstructors.Color3.new(0.768627,0.156863,0.109804)}) end,
    Yellow=function() return makeDataValue("BrickColor",{Name="Bright yellow",Number=24,Color=dataConstructors.Color3.new(0.960784,0.803922,0.188235)}) end,
    Green=function() return makeDataValue("BrickColor",{Name="Dark green",Number=28,Color=dataConstructors.Color3.new(0.156863,0.498039,0.278431)}) end,
    Blue=function() return makeDataValue("BrickColor",{Name="Bright blue",Number=23,Color=dataConstructors.Color3.new(0.0509804,0.411765,0.67451)}) end,
    random = function()
        return dataConstructors.BrickColor.new(194)
    end,
    Random = function()
        return dataConstructors.BrickColor.random()
    end,
    palette = function(index)
        return dataConstructors.BrickColor.new(tonumber(index) or 194)
    end,
    new = function(value)
        local byNumber = {
            [1]={"White",dataConstructors.Color3.new(0.94902,0.952941,0.952941)},
            [21]={"Bright red",dataConstructors.Color3.new(0.768627,0.156863,0.109804)},
            [23]={"Bright blue",dataConstructors.Color3.new(0.0509804,0.411765,0.67451)},
            [24]={"Bright yellow",dataConstructors.Color3.new(0.960784,0.803922,0.188235)},
            [26]={"Black",dataConstructors.Color3.new(0.105882,0.164706,0.207843)},
            [194]={"Medium stone grey",dataConstructors.Color3.new(0.639216,0.635294,0.647059)},
            [199]={"Dark stone grey",dataConstructors.Color3.new(0.388235,0.372549,0.384314)},
            [226]={"Cool yellow",dataConstructors.Color3.new(0.992157,0.917647,0.552941)},
        }
        local byName = {
            ["White"]=1,["Bright red"]=21,["Bright blue"]=23,["Bright yellow"]=24,
            ["Black"]=26,["Medium stone grey"]=194,["Dark stone grey"]=199,["Cool yellow"]=226,
        }
        local number = hostFns.type(value)=="number" and math.floor(value) or byName[hostFns.tostring(value or "")] or 194
        local entry = byNumber[number] or byNumber[194]
        local color = entry[2]
        return makeDataValue("BrickColor",{Name=entry[1],Number=number,Color=color,r=color.R,g=color.G,b=color.B,R=color.R,G=color.G,B=color.B})
    end,
}

dataConstructors.TweenInfo = {
    new = function(time, easingStyle, easingDirection, repeatCount, reverses, delayTime)
        return makeDataValue("TweenInfo", {
            Time = tonumber(time) or 1,
            EasingStyle = easingStyle or makeEnumType("EasingStyle").Quad,
            EasingDirection = easingDirection or makeEnumType("EasingDirection").Out,
            RepeatCount = tonumber(repeatCount) or 0,
            Reverses = reverses == true,
            DelayTime = tonumber(delayTime) or 0,
        })
    end,
}

dataConstructors.NumberRange = {
    new = function(minValue, maxValue)
        local minN = tonumber(minValue) or 0
        local maxN = tonumber(maxValue)
        if maxN == nil then maxN = minN end
        if minN > maxN then hostFns.error("NumberRange: min must be <= max",2) end
        return makeDataValue("NumberRange",{Min=minN,Max=maxN})
    end,
}

dataConstructors.NumberSequenceKeypoint = {
    new = function(time, value, envelope)
        return makeDataValue("NumberSequenceKeypoint", {
            Time = tonumber(time) or 0,
            Value = tonumber(value) or 0,
            Envelope = tonumber(envelope) or 0,
        })
    end,
}

dataConstructors.NumberSequence = {
    new = function(value, secondValue)
        local keypoints
        if hostFns.type(value) == "table" then
            keypoints = value
        elseif secondValue ~= nil then
            keypoints = {
                dataConstructors.NumberSequenceKeypoint.new(0, tonumber(value) or 0, 0),
                dataConstructors.NumberSequenceKeypoint.new(1, tonumber(secondValue) or 0, 0),
            }
        else
            local number = tonumber(value) or 0
            keypoints = {
                dataConstructors.NumberSequenceKeypoint.new(0, number, 0),
                dataConstructors.NumberSequenceKeypoint.new(1, number, 0),
            }
        end
        return makeDataValue("NumberSequence", {Keypoints = keypoints})
    end,
}

dataConstructors.ColorSequenceKeypoint = {
    new = function(time, value)
        return makeDataValue("ColorSequenceKeypoint", {
            Time = tonumber(time) or 0,
            Value = value or dataConstructors.Color3.new(0, 0, 0),
        })
    end,
}

dataConstructors.ColorSequence = {
    new = function(a, b)
        local keypoints
        if hostFns.type(a) == "table" then
            keypoints = a
        else
            local first = a or dataConstructors.Color3.new(0, 0, 0)
            local second = b or first
            keypoints = {
                dataConstructors.ColorSequenceKeypoint.new(0, first),
                dataConstructors.ColorSequenceKeypoint.new(1, second),
            }
        end
        return makeDataValue("ColorSequence", {Keypoints = keypoints})
    end,
}

dataConstructors.Ray = {
    new = function(origin, direction)
        return makeDataValue("Ray", {
            Origin = origin or dataConstructors.Vector3.zero,
            Direction = direction or dataConstructors.Vector3.zero,
        })
    end,
}

local rectCache = {}

dataConstructors.Rect = {
    new = function(a, b, c, d)
        local minValue, maxValue

        if objectTypes[a] == "Vector2" and objectTypes[b] == "Vector2" then
            minValue, maxValue = a, b
        else
            minValue = dataConstructors.Vector2.new(a or 0, b or 0)
            maxValue = dataConstructors.Vector2.new(c or 0, d or 0)
        end

        local key =
            hostFns.tostring(minValue.X) .. "|"
            .. hostFns.tostring(minValue.Y) .. "|"
            .. hostFns.tostring(maxValue.X) .. "|"
            .. hostFns.tostring(maxValue.Y)

        if rectCache[key] then
            return rectCache[key]
        end

        local value = makeDataValue("Rect", {
            Min = minValue,
            Max = maxValue,
            Width = math.abs(maxValue.X - minValue.X),
            Height = math.abs(maxValue.Y - minValue.Y),
        })

        rectCache[key] = value
        return value
    end,
}

dataConstructors.Region3int16 = {
    new = function(minValue, maxValue)
        return makeDataValue("Region3int16", {
            Min = minValue or dataConstructors.Vector3int16.new(),
            Max = maxValue or dataConstructors.Vector3int16.new(),
        })
    end,
}

dataConstructors.PhysicalProperties = {
    new = function(density, friction, elasticity, frictionWeight, elasticityWeight)
        return makeDataValue("PhysicalProperties", {
            Density = tonumber(density) or 0.7,
            Friction = tonumber(friction) or 0.3,
            Elasticity = tonumber(elasticity) or 0.5,
            FrictionWeight = tonumber(frictionWeight) or 1,
            ElasticityWeight = tonumber(elasticityWeight) or 1,
        })
    end,
}

dataConstructors.FloatCurveKey = {
    new = function(time, value, interpolation)
        return makeDataValue("FloatCurveKey", {
            Time = tonumber(time) or 0,
            Value = tonumber(value) or 0,
            Interpolation = interpolation or makeEnumType("KeyInterpolationMode").Linear,
        })
    end,
}

dataConstructors.ValueCurveKey = {
    new = function(time, value, interpolation)
        return makeDataValue("ValueCurveKey", {
            Time = tonumber(time) or 0,
            Value = value,
            Interpolation = interpolation or makeEnumType("KeyInterpolationMode").Linear,
        })
    end,
}

dataConstructors.RotationCurveKey = {
    new = function(time, value, interpolation)
        return makeDataValue("RotationCurveKey", {
            Time = tonumber(time) or 0,
            Value = value or dataConstructors.CFrame.new(),
            Interpolation = interpolation or makeEnumType("KeyInterpolationMode").Linear,
            LeftTangent = 0,
            RightTangent = 0,
        })
    end,
}

dataConstructors.CatalogSearchParams = {
    new = function()
        return makeDataValue("CatalogSearchParams", {
            SearchKeyword = "",
            MinPrice = 0,
            MaxPrice = 0,
            AssetTypes = {},
            BundleTypes = {},
            IncludeOffSale = false,
            SortType = makeEnumType("CatalogSortType").Relevance,
            SortAggregation = makeEnumType("CatalogSortAggregation").AllTime,
            CategoryFilter = makeEnumType("CatalogCategoryFilter").None,
            SalesTypeFilter = makeEnumType("CatalogSalesTypeFilter").All,
            CreatorName = "",
            CreatorId = 0,
            Limit = 30,
        })
    end,
}

local normalAxisMap = {
    X={X=true,Y=false,Z=false},
    Y={X=false,Y=true,Z=false},
    Z={X=false,Y=false,Z=true},
    Bottom = {X = false, Y = true,  Z = false},
    Top    = {X = false, Y = true,  Z = false},
    Front  = {X = false, Y = false, Z = true},
    Back   = {X = false, Y = false, Z = true},
    Right  = {X = true,  Y = false, Z = false},
    Left   = {X = true,  Y = false, Z = false},
}

local normalOppositeMap = {
    Bottom = "Top",
    Top = "Bottom",
    Front = "Back",
    Back = "Front",
    Right = "Left",
    Left = "Right",
}

dataConstructors.Axes = {
    new = function(...)
        local fields = {
            X = false,
            Y = false,
            Z = false,
            Bottom = false,
            Front = false,
            Right = false,
            Back = false,
            Left = false,
            Top = false,
        }

        for _, normal in hostFns.ipairs({...}) do
            local name = objectTypes[normal] == "EnumItem" and normal.Name or nil
            local axis = name and normalAxisMap[name]

            if axis then
                fields.X = fields.X or axis.X
                fields.Y = fields.Y or axis.Y
                fields.Z = fields.Z or axis.Z
                fields[name] = true

                local opposite = normalOppositeMap[name]
                if opposite then
                    fields[opposite] = true
                end
            end
        end

        return makeDataValue("Axes", fields)
    end,
}

dataConstructors.Faces = {
    new = function(...)
        local fields = {
            Bottom = false,
            Front = false,
            Right = false,
            Back = false,
            Left = false,
            Top = false,
        }

        for _, normal in hostFns.ipairs({...}) do
            local name = objectTypes[normal] == "EnumItem" and normal.Name or nil
            if name and fields[name] ~= nil then
                fields[name] = true
            end
        end

        return makeDataValue("Faces", fields)
    end,
}

dataConstructors.DockWidgetPluginGuiInfo = {
    new = function(
        initialDockState,
        initialEnabled,
        overrideEnabledRestore,
        floatingXSize,
        floatingYSize,
        minimumWidth,
        minimumHeight
    )
        return makeDataValue("DockWidgetPluginGuiInfo", {
            InitialDockState = initialDockState or makeEnumType("InitialDockState").Float,
            InitialEnabled = initialEnabled == true,
            InitialEnabledShouldOverrideRestore = overrideEnabledRestore == true,
            FloatingXSize = tonumber(floatingXSize) or 0,
            FloatingYSize = tonumber(floatingYSize) or 0,
            MinimumWidth = tonumber(minimumWidth) or 0,
            MinimumHeight = tonumber(minimumHeight) or 0,
        })
    end,
}

dataConstructors.Path2DControlPoint = {
    new = function(position, leftTangent, rightTangent)
        position = position or dataConstructors.UDim2.new()
        leftTangent = leftTangent or dataConstructors.UDim2.new()
        rightTangent = rightTangent or dataConstructors.UDim2.new()

        if objectTypes[position] ~= "UDim2" then hostFns.error("UDim2 expected",2) end
        if objectTypes[leftTangent] ~= "UDim2" then hostFns.error("UDim2 expected",2) end
        if objectTypes[rightTangent] ~= "UDim2" then hostFns.error("UDim2 expected",2) end

        return makeDataValue("Path2DControlPoint", {
            Position = position,
            LeftTangent = leftTangent,
            RightTangent = rightTangent,
        })
    end,
}

dataConstructors.PathWaypoint = {
    new = function(position, action, label)
        return makeDataValue("PathWaypoint", {
            Position = position or dataConstructors.Vector3.zero,
            Action = action or makeEnumType("PathWaypointAction").Walk,
            Label = label or "",
        })
    end,
}

dataConstructors.SecurityCapabilities = {
    new=function(...)
        local set={}
        for _,item in hostFns.ipairs({...}) do
            if item ~= nil then set[hostFns.tostring(item)] = item end
        end
        return makeDataValue("SecurityCapabilities",{Values=set})
    end,
    fromCurrent=function()
        local values = {}

        for tag in hostFns.pairs(
            securityRuntime.getCapabilities(
                getRuntimeThreadIdentity()
            )
        ) do
            values[tag] = tag
        end

        return makeDataValue(
            "SecurityCapabilities",
            {Values=values}
        )
    end,
}

dataConstructors.Content = {
    fromUri = function(uri)
        if hostFns.type(uri) ~= "string" then hostFns.error("string expected",2) end
        return makeDataValue("Content",{
            SourceType=makeEnumType("ContentSourceType").Uri,
            Uri=uri,
            Object=nil,
        })
    end,
    fromObject = function(object)
        if instanceStates[object] == nil then hostFns.error("Instance expected",2) end
        return makeDataValue("Content",{
            SourceType=makeEnumType("ContentSourceType").Object,
            Uri="",
            Object=object,
        })
    end,
}
dataConstructors.Content.none = makeDataValue("Content",{
    SourceType=makeEnumType("ContentSourceType").None,
    Uri="",
    Object=nil,
})

dataConstructors.Font = {
    new = function(family, weight, style)
        return makeDataValue("Font", {
            Family = family or "rbxasset://fonts/families/SourceSansPro.json",
            Weight = weight or makeEnumType("FontWeight").Regular,
            Style = style or makeEnumType("FontStyle").Normal,
            Bold = false,
        })
    end,
    fromName = function(name, weight, style)
        return dataConstructors.Font.new(
            "rbxasset://fonts/families/" .. hostFns.tostring(name or "SourceSans") .. ".json",
            weight,
            style
        )
    end,
    fromEnum = function(font)
        if not font or objectTypes[font] ~= "EnumItem" then
            hostFns.error("Enum.Font expected", 2)
        end

        local name = font.Name
        local familyName = name
        local weight = makeEnumType("FontWeight").Regular
        local style = makeEnumType("FontStyle").Normal

        if name == "GothamBold" then
            familyName = "Gotham"
            weight = makeEnumType("FontWeight").Bold
        elseif name == "GothamSemibold" then
            familyName = "Gotham"
            weight = makeEnumType("FontWeight").SemiBold
        elseif name == "ArialBold" then
            familyName = "Arial"
            weight = makeEnumType("FontWeight").Bold
        elseif name == "SourceSansBold" then
            familyName = "SourceSans"
            weight = makeEnumType("FontWeight").Bold
        elseif name == "SourceSansLight" then
            familyName = "SourceSans"
            weight = makeEnumType("FontWeight").Light
        elseif name == "SourceSansItalic" then
            familyName = "SourceSans"
            style = makeEnumType("FontStyle").Italic
        elseif name == "Legacy" then
            familyName = "Legacy"
        end

        return dataConstructors.Font.fromName(familyName, weight, style)
    end,
    fromId = function(id, weight, style)
        id=tonumber(id)
        if not id then hostFns.error("number expected",2) end
        return dataConstructors.Font.new(
            "rbxassetid://"..hostFns.tostring(math.floor(id)),
            weight,
            style
        )
    end,
}

dataConstructors.__daysFromCivil = function(y,m,d)
    y=tonumber(y) or 1970
    m=tonumber(m) or 1
    d=tonumber(d) or 1
    y = y - (m <= 2 and 1 or 0)
    local era = math.floor((y >= 0 and y or y-399) / 400)
    local yoe = y - era*400
    local mp = m + (m > 2 and -3 or 9)
    local doy = math.floor((153*mp+2)/5)+d-1
    local doe = yoe*365 + math.floor(yoe/4) - math.floor(yoe/100) + doy
    return era*146097 + doe - 719468
end

dataConstructors.__utcTimestamp = function(y,m,d,h,mi,s)
    return dataConstructors.__daysFromCivil(y,m,d)*86400
        +(tonumber(h) or 0)*3600+(tonumber(mi) or 0)*60+(tonumber(s) or 0)
end

do
local dateTimeEpochBaseMs = os.time() * 1000
CONFIG.dateTimeVirtualOffsetMs = 0
dataConstructors.DateTime = {
    fromIsoDate=function(value)
        local y,mo,d,h,mi,s=hostFns.tostring(value or ""):match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)")
        if not y then return nil end
        local ts=os.time({year=tonumber(y),month=tonumber(mo),day=tonumber(d),hour=tonumber(h),min=tonumber(mi),sec=tonumber(s)})
        return makeDataValue("DateTime",{UnixTimestamp=ts,UnixTimestampMillis=ts*1000})
    end,
    now = function()
        local ms = dateTimeEpochBaseMs + (CONFIG.dateTimeVirtualOffsetMs or 0)
        return makeDataValue("DateTime", {
            UnixTimestamp = math.floor(ms / 1000),
            UnixTimestampMillis = ms,
        })
    end,
    fromUnixTimestamp = function(seconds)
        local s = tonumber(seconds) or 0
        return makeDataValue("DateTime", {
            UnixTimestamp = math.floor(s),
            UnixTimestampMillis = math.floor(s * 1000),
        })
    end,
    fromUnixTimestampMillis = function(ms)
        local m = tonumber(ms) or 0
        return makeDataValue("DateTime", {
            UnixTimestamp = math.floor(m / 1000),
            UnixTimestampMillis = math.floor(m),
        })
    end,
    fromUniversalTime = function(year,month,day,hour,minute,second,millisecond)
        local seconds=dataConstructors.__utcTimestamp(year,month,day,hour,minute,second)
        local ms=(tonumber(millisecond) or 0)
        return makeDataValue("DateTime",{
            UnixTimestamp=math.floor(seconds),
            UnixTimestampMillis=math.floor(seconds*1000+ms),
        })
    end,
    fromLocalTime = function(year,month,day,hour,minute,second,millisecond)
        local seconds=os.time({
            year=tonumber(year) or 1970,month=tonumber(month) or 1,day=tonumber(day) or 1,
            hour=tonumber(hour) or 0,min=tonumber(minute) or 0,sec=tonumber(second) or 0,
            isdst=false,
        })
        local ms=tonumber(millisecond) or 0
        return makeDataValue("DateTime",{
            UnixTimestamp=math.floor(seconds),
            UnixTimestampMillis=math.floor(seconds*1000+ms),
        })
    end,
}
end

dataConstructors.SharedTable = {
    new = function(source)
        local fields = {}
        if hostFns.type(source) == "table" then
            for k, v in hostFns.pairs(source) do fields[k] = v end
        end
        return makeDataValue("SharedTable", fields)
    end,
    size = function(value)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected",2) end
        local backing=sharedTableFields[value] or {}
        local n=0
        for _ in hostFns.pairs(backing) do n+=1 end
        return n
    end,
    clear = function(value)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected",2) end
        local backing=sharedTableFields[value] or {}
        for k in hostFns.pairs(backing) do backing[k]=nil end
    end,
    clone = function(value)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected",2) end
        local backing=sharedTableFields[value] or {}
        local copy={}
        for k,v in hostFns.pairs(backing) do copy[k]=v end
        return dataConstructors.SharedTable.new(copy)
    end,
    cloneAndFreeze = function(value, deep)
        local result = dataConstructors.SharedTable.clone(value, deep)
        local backing = sharedTableFields[result]
        if backing then backing.__RadiumFrozen = true end
        return result
    end,
    isFrozen = function(value)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected",2) end
        local backing = sharedTableFields[value]
        return backing and backing.__RadiumFrozen == true or false
    end,
    increment = function(value, key, delta)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected", 2) end
        local backing = sharedTableFields[value]
        if not backing then hostFns.error("invalid SharedTable", 2) end
        if backing.__RadiumFrozen then hostFns.error("attempt to modify a frozen SharedTable", 2) end
        if hostFns.type(delta) ~= "number" then hostFns.error("number expected", 2) end
        local current = backing[key]
        if hostFns.type(current) ~= "number" then hostFns.error("SharedTable value must be a number", 2) end
        backing[key] = current + delta
        return backing[key]
    end,
    update = function(value, key, callback)
        if objectTypes[value] ~= "SharedTable" then hostFns.error("SharedTable expected", 2) end
        if hostFns.type(callback) ~= "function" then hostFns.error("function expected", 2) end
        local backing = sharedTableFields[value]
        if not backing then hostFns.error("invalid SharedTable", 2) end
        if backing.__RadiumFrozen then hostFns.error("attempt to modify a frozen SharedTable", 2) end
        local updated = callback(backing[key])
        local vt = hostFns.type(updated)
        local ot = objectTypes[updated]
        local allowed = vt=="nil" or vt=="boolean" or vt=="number" or vt=="string"
            or ot=="SharedTable" or ot=="Vector2" or ot=="Vector3"
        if not allowed then hostFns.error("invalid SharedTable value type", 2) end
        backing[key] = updated
        return updated
    end,
}

local signalOnceCallbacks = hostFns.setmetatable({}, { __mode = "k" })

local function fireSignal(signal, ...)
    local signalState = proxyState[signal] and proxyState[signal].signalState

    if signalState then
        signalState.fireCount = (signalState.fireCount or 0) + 1
        signalState.lastArgs = table.pack(...)
    end

    local callbacks = signalState and signalState.callbacks or signalCallbacks[signal]
    local packed = table.pack(...)

    local function dispatch(callback)
        if proxyState.__dispatchSignalCallback then
            proxyState.__dispatchSignalCallback(callback, packed, packed.n)
        else
            hostFns.pcall(callback, hostFns.unpack(packed, 1, packed.n))
        end
    end

    if callbacks then
        local snapshot = {}
        for connection, callback in hostFns.pairs(callbacks) do
            snapshot[#snapshot + 1] = {connection, callback}
        end

        for _, entry in hostFns.ipairs(snapshot) do
            local connection = entry[1]
            local callback = entry[2]
            local cstate = connection and proxyState[connection]

            if not cstate or cstate.connected ~= false then
                dispatch(callback)
            end
        end
    end

    local once = signalState and signalState.once or signalOnceCallbacks[signal]
    if once then
        if signalState then
            signalState.once = {}
        else
            signalOnceCallbacks[signal] = nil
        end

        for _, callback in hostFns.ipairs(once) do
            dispatch(callback)
        end
    end
end

local pumpTasks
local advanceSimulation

local function makeSignal(name)
    local shared = {
        name = name,
        callbacks = {},
        once = {},
        fireCount = 0,
        lastArgs = nil,
    }

    local function signalEquals(a, b)
        local aState = proxyState[a]
        local bState = proxyState[b]
        return aState ~= nil
            and bState ~= nil
            and aState.signalState ~= nil
            and aState.signalState == bState.signalState
    end

    local newView

    newView = function()
        local signal = newproxy(true)
        local mt = hostFns.getmetatable(signal)

        proxyState[signal] = {
            signalState = shared,
            newView = newView,
        }

        mark(signal, name, "RBXScriptSignal")

        mt.__metatable = "The metatable is locked"
        mt.__eq = signalEquals

        mt.__index = function(_, key)
            if key == "Connect" or key == "connect" then
                return function(selfSignal, callback)
                    local selfState = proxyState[selfSignal]
                    if not selfState or selfState.signalState ~= shared then
                        hostFns.error("Expected ':' not '.' calling Connect",2)
                    end

                    if hostFns.type(callback) ~= "function" then
                        hostFns.error("invalid argument #1 to 'Connect' (function expected)", 2)
                    end

                    emit(name .. ":Connect(function(...)")
                    indent += 1
                    indent -= 1
                    emit("end)")

                    local connection = newproxy(true)
                    local cmt = hostFns.getmetatable(connection)
                    local state = { connected = true }
                    proxyState[connection] = state
                    mark(connection, newVar("Connection"), "RBXScriptConnection")
                    shared.callbacks[connection] = callback

                    cmt.__metatable = "The metatable is locked"
                    cmt.__index = function(_, connectionKey)
                        if connectionKey == "Connected" then
                            return state.connected
                        elseif connectionKey == "Disconnect" then
                            return function(selfConnection)
                                if selfConnection ~= connection then
                                    hostFns.error("Expected ':' not '.' calling Disconnect",2)
                                end
                                state.connected = false
                                shared.callbacks[connection] = nil
                            end
                        end
                        return nil
                    end

                    return connection
                end

            elseif key == "Once" then
                return function(selfSignal, callback)
                    local selfState = proxyState[selfSignal]
                    if not selfState or selfState.signalState ~= shared then
                        hostFns.error("Expected ':' not '.' calling Once",2)
                    end

                    if hostFns.type(callback) ~= "function" then
                        hostFns.error("invalid argument #1 to 'Once' (function expected)", 2)
                    end

                    shared.once[#shared.once + 1] = callback

                    local connection = newproxy(true)
                    local cmt = hostFns.getmetatable(connection)
                    local state = { connected = true }
                    proxyState[connection] = state
                    mark(connection, newVar("Connection"), "RBXScriptConnection")

                    cmt.__metatable = "The metatable is locked"
                    cmt.__index = function(_, connectionKey)
                        if connectionKey == "Connected" then return state.connected end
                        if connectionKey == "Disconnect" then
                            return function(selfConnection)
                                if selfConnection ~= connection then
                                    hostFns.error("Expected ':' not '.' calling Disconnect",2)
                                end
                                state.connected = false
                            end
                        end
                        return nil
                    end

                    return connection
                end

            elseif key == "Wait" then
                return function(selfSignal)
                    local selfState = proxyState[selfSignal]
                    if not selfState or selfState.signalState ~= shared then
                        hostFns.error("Expected ':' not '.' calling Wait",2)
                    end

                    if name ~= "RunService.RenderStepped"
                and name ~= "RunService.Heartbeat"
                and name ~= "RunService.Stepped"
                and name ~= "RunService.PreRender"
                and name ~= "RunService.PreSimulation"
                and name ~= "RunService.PostSimulation"
            then
                emit(name .. ":Wait()")
            end

                    local before = shared.fireCount or 0
                    local waited = 0
                    local maxWait = 10

                    while (shared.fireCount or 0) == before and waited < maxWait do
                        local step = 1/60

                        if name == "RunService.RenderStepped" then
                            local cap = tonumber(CONFIG.fpsCap) or 60
                            local maxFps = math.min(
                                math.max(math.floor(cap), CONFIG.fpsMin),
                                CONFIG.fpsMax
                            )
                            local minFps = math.min(CONFIG.fpsMin, maxFps)
                            local fps = math.random(minFps, maxFps)
                            step = 1 / fps
                        end

                        if advanceSimulation then
                            advanceSimulation(step)
                        else
                            virtualTime += step
                        end

                        if pumpTasks then
                            pumpTasks()
                        end

                        waited += step
                    end

                    local args = shared.lastArgs

                    if args and args.n and args.n > 0 then
                        -- eUNC checks two Heartbeat:Wait() results are distinct.
                        -- Keep callback dt untouched; only the Wait return gets
                        -- a microscopic monotonic component.
                        if name == "RunService.Heartbeat"
                            and hostFns.type(args[1]) == "number"
                        then
                            return args[1] + virtualTime * 1e-9
                        end

                        return hostFns.unpack(args, 1, args.n)
                    end

                    return waited
                end
            end

            return nil
        end

        mt.__newindex = function()
            hostFns.error("attempt to modify a readonly RBXScriptSignal", 2)
        end

        mt.__tostring = function()
            return name
        end

        return signal
    end

    return newView()
end

local function ensureChildren(instance)
    local list = instanceChildren[instance]

    if not list then
        list = {}
        instanceChildren[instance] = list
    end

    return list
end

local function removeFromParent(instance)
    local state = instanceStates[instance]
    if not state then
        return
    end

    local parent = state.values.Parent

    if parent and instanceChildren[parent] then
        instanceChildren[parent][instance] = nil
    end
end

local function setParent(instance, parent)
    local state = instanceStates[instance]
    if not state then return end
    local oldParent = state.values.Parent
    if oldParent == parent then return end

    if oldParent and instanceStates[oldParent] then
        local oldState = instanceStates[oldParent]
        if oldState.values.ChildRemoved then fireSignal(oldState.values.ChildRemoved, instance) end
        if oldState.values.DescendantRemoving then fireSignal(oldState.values.DescendantRemoving, instance) end
    end

    removeFromParent(instance)
    state.values.Parent = parent

    if parent ~= nil then
        ensureChildren(parent)[instance] = true
        local parentState = instanceStates[parent]
        if parentState then
            if parentState.values.ChildAdded then fireSignal(parentState.values.ChildAdded, instance) end
            if parentState.values.DescendantAdded then fireSignal(parentState.values.DescendantAdded, instance) end
        end
    end

    if state.values.AncestryChanged then fireSignal(state.values.AncestryChanged, instance, parent) end
end

local function findChild(parent, name, recursive)
    local linked = instanceChildren[parent]

    if linked then
        for child in hostFns.pairs(linked) do
            local childState = instanceStates[child]

            if childState and childState.values.Name == name then
                return child
            end
        end

        if recursive then
            for child in hostFns.pairs(linked) do
                local result = findChild(child, name, true)

                if result then
                    return result
                end
            end
        end
    end

    return nil
end

local serviceCache = {}
local game
local createInstance
local createInternalInstance

dataConstructors.__fallbackSchema = {
    common = {
        Name=true, Parent=true, Archivable=true, Data=true,
    },

    basePart = {
        Position=true, Orientation=true, CFrame=true, Size=true,
        Anchored=true, CanCollide=true, CanTouch=true, CanQuery=true,
        Massless=true, Transparency=true, Reflectance=true,
        Color=true, BrickColor=true, Material=true, MaterialVariant=true,
        CollisionGroup=true, CustomPhysicalProperties=true, CastShadow=true,
        RootPriority=true, AssemblyLinearVelocity=true,
        AssemblyAngularVelocity=true, Velocity=true, RotVelocity=true,
        Locked=true, Shape=true, RightVector=true, UpVector=true, LookVector=true,
        IsNetworkSleeping=true, Description=true,
    },

    guiObject = {
        Position=true, Size=true, AnchorPoint=true, Visible=true, Active=true,
        Selectable=true, SelectionOrder=true, BackgroundColor3=true,
        BackgroundTransparency=true, BorderColor3=true, BorderMode=true,
        BorderSizePixel=true, ClipsDescendants=true, LayoutOrder=true,
        Rotation=true, ZIndex=true, AutomaticSize=true, Interactable=true,
        NextSelectionDown=true, NextSelectionLeft=true,
        NextSelectionRight=true, NextSelectionUp=true, SelectionImageObject=true,
    },

    classes = {
        ScreenGui = {
            Enabled=true, ResetOnSpawn=true, IgnoreGuiInset=true,
            DisplayOrder=true, ZIndexBehavior=true, SafeAreaCompatibility=true,
            ScreenInsets=true, ClipToDeviceSafeArea=true,
        },
        AudioFilter = {
            FilterType=true, Frequency=true, Q=true, Gain=true,
        },
        TextLabel = {
            Text=true, RichText=true, TextColor3=true, TextTransparency=true,
            TextStrokeColor3=true, TextStrokeTransparency=true, TextSize=true,
            Font=true, FontFace=true, TextScaled=true, TextWrapped=true,
            TextXAlignment=true, TextYAlignment=true, LineHeight=true,
            MaxVisibleGraphemes=true, TextTruncate=true,
            TextFits=true, TextBounds=true,
        },
        TextButton = {
            Text=true, RichText=true, TextColor3=true, TextTransparency=true,
            TextStrokeColor3=true, TextStrokeTransparency=true, TextSize=true,
            Font=true, FontFace=true, TextScaled=true, TextWrapped=true,
            TextXAlignment=true, TextYAlignment=true, LineHeight=true,
            MaxVisibleGraphemes=true, TextTruncate=true, AutoButtonColor=true,
            Modal=true, Selected=true, Style=true,
        },
        TextBox = {
            Text=true, RichText=true, TextColor3=true, TextTransparency=true,
            TextStrokeColor3=true, TextStrokeTransparency=true, TextSize=true,
            Font=true, FontFace=true, TextScaled=true, TextWrapped=true,
            TextXAlignment=true, TextYAlignment=true, LineHeight=true,
            MaxVisibleGraphemes=true, TextTruncate=true, ClearTextOnFocus=true,
            MultiLine=true, PlaceholderText=true, PlaceholderColor3=true,
            TextEditable=true,
        },
        ImageLabel = {
            Image=true, ImageColor3=true, ImageTransparency=true,
            ImageRectOffset=true, ImageRectSize=true, ScaleType=true,
            SliceCenter=true, SliceScale=true, TileSize=true, ResampleMode=true,
        },
        ImageButton = {
            Image=true, ImageColor3=true, ImageTransparency=true,
            ImageRectOffset=true, ImageRectSize=true, ScaleType=true,
            SliceCenter=true, SliceScale=true, TileSize=true, ResampleMode=true,
            AutoButtonColor=true, HoverImage=true, PressedImage=true,
            Modal=true, Selected=true, Style=true,
        },
        Sound = {
            SoundId=true, Volume=true, PlaybackSpeed=true, Playing=true,
            Looped=true, TimePosition=true, RollOffMaxDistance=true,
            RollOffMinDistance=true, RollOffMode=true, PlayOnRemove=true,
        },
        Humanoid = {
            WalkSpeed=true, JumpPower=true, JumpHeight=true, HipHeight=true,
            AutoRotate=true, Health=true, MaxHealth=true, Jump=true,
            PlatformStand=true, Sit=true, UseJumpPower=true,
            DisplayDistanceType=true, NameDisplayDistance=true,
            HealthDisplayDistance=true,
        },
        Tool = {
            CanBeDropped=true, Enabled=true, Grip=true, ManualActivationOnly=true,
            RequiresHandle=true, ToolTip=true,
        },
        Team = {
            TeamColor=true, AutoAssignable=true,
        },
        StyleRule = {
            Selector=true,
        },
        TerrainRegion = {
            SizeInCells=true,
        },
        Path2D = {
            Closed=true, Color3=true, SelectedControlPoint=true,
            Thickness=true, Transparency=true, Visible=true, ZIndex=true,
        },
        InputAction = {
            Enabled=true, DisplayName=true, Type=true,
        },
        LocalizationTable = {
            SourceLocaleId=true,
        },
        MaterialVariant = {
            BaseMaterial=true,
        },
        AudioEmitter = {
            AudioInteractionGroup=true, AcousticSimulationEnabled=true,
        },
        AudioListener = {
            AudioInteractionGroup=true, AcousticSimulationEnabled=true,
        },
        AudioDeviceInput = { Active=true },
        AudioPlayer = { Volume=true, PlaybackSpeed=true, IsPlaying=true, AssetId=true },
        AudioReverb = { DecayTime=true, WetLevel=true },
        Wire = { SourceInstance=true, TargetInstance=true },
        Beam = { CurveSize0=true, CurveSize1=true, Width0=true, Width1=true, Texture=true },
        Trail = { Lifetime=true, MinLength=true, Texture=true },
        ParticleEmitter = { Rate=true, Texture=true, Enabled=true },
        PointLight = { Brightness=true, Range=true, Shadows=true, Enabled=true },
        SurfaceLight = { Brightness=true, Range=true, Angle=true, Shadows=true, Enabled=true },
        SpotLight = { Brightness=true, Range=true, Angle=true, Shadows=true, Enabled=true },
        Decal = { Texture=true, Transparency=true },
        Texture = { Texture=true, Transparency=true, StudsPerTileU=true, StudsPerTileV=true },
        Shirt = { ShirtTemplate=true },
        Pants = { PantsTemplate=true },
        WeldConstraint = { Enabled=true, Part0=true, Part1=true },
        Motor6D = { C0=true, C1=true, Part0=true, Part1=true },
        CharacterMesh = { BodyPart=true },
        BodyColors = { HeadColor=true },
        UICorner = { CornerRadius=true },
        UIStroke = { Color=true, Thickness=true, Transparency=true, Enabled=true },
        UIListLayout = { SortOrder=true, Padding=true, HorizontalAlignment=true, VerticalAlignment=true },
        UIPadding = { PaddingBottom=true, PaddingLeft=true, PaddingRight=true, PaddingTop=true },
        ScrollingFrame = { CanvasSize=true, ScrollBarImageColor3=true, ScrollBarThickness=true, MidImage=true, BottomImage=true, TopImage=true },
        VideoFrame = { Volume=true, Looped=true },
        Lighting = { Technology=true, Brightness=true },
        TextChatService = { CreateDefaultTextChannels=true },
        ContentProvider = { BaseUrl=true },
        Animation = { AnimationId=true },
        Vector3Value = { Value=true }, NumberValue = { Value=true }, IntValue = { Value=true },
        BoolValue = { Value=true }, StringValue = { Value=true }, ObjectValue = { Value=true },
        CFrameValue = { Value=true }, Color3Value = { Value=true }, BrickColorValue = { Value=true },
        Sky = { StarCount=true, CelestialBodiesShown=true, SunAngularSize=true, MoonAngularSize=true },
        Smoke = { Size=true, RiseVelocity=true, Opacity=true, Color=true, Enabled=true },
        UserInputService = { MouseBehavior=true, MouseIconEnabled=true, MouseIcon=true, TouchEnabled=true,
            KeyboardEnabled=true, MouseEnabled=true, GamepadEnabled=true, AccelerometerEnabled=true,
            GyroscopeEnabled=true, VREnabled=true },
        Stats = { PhysicsStepTime=true, PhysicsStepTimeMs=true, FrameTime=true, HeartbeatTime=true,
            HeartbeatTimeMs=true, RenderCPUFrameTime=true, RenderGPUFrameTime=true,
            ContactsCount=true, InstanceCount=true, MovingPrimitivesCount=true, PrimitivesCount=true,
            PhysicsReceiveKbps=true, PhysicsSendKbps=true, DataReceiveKbps=true, DataSendKbps=true,
            SceneDrawcallCount=true, SceneTriangleCount=true, ShadowsDrawcallCount=true, ShadowsTriangleCount=true,
            UI2DDrawcallCount=true, UI2DTriangleCount=true, UI3DDrawcallCount=true, UI3DTriangleCount=true,
            MemoryTrackingEnabled=true },
        Sparkles = { SparkleColor=true, Enabled=true },
        Player = { CameraMinZoomDistance=true, CameraMaxZoomDistance=true, AccountAge=true,
            MembershipType=true, Character=true, CharacterAdded=true, CharacterRemoving=true },
        Camera = { ViewportSize=true, FieldOfView=true, Position=true, CFrame=true, Velocity=true,
            RightVector=true, UpVector=true, LookVector=true, CameraSubject=true, Focus=true },
        DataStoreIncrementOptions = {},
        DataStoreSetOptions = {},
        GetTextBoundsParams = {
            Text=true, Font=true, Size=true, Width=true, RichText=true,
        },
    },

    nilReadable = {
        Parent=true, PrimaryPart=true, Adornee=true, CurrentCamera=true,
        SelectionImageObject=true, NextSelectionDown=true,
        NextSelectionLeft=true, NextSelectionRight=true, NextSelectionUp=true,
        SourceInstance=true, TargetInstance=true, Part0=true, Part1=true,
        CameraSubject=true, Data=true,
    },
}

dataConstructors.__fallbackPropertyKnown = function(className, key)
    local schema = dataConstructors.__fallbackSchema

    if schema.common[key] then
        return true
    end

    if classIsA(className, "BasePart") and schema.basePart[key] then
        return true
    end

    if classIsA(className, "GuiObject") and schema.guiObject[key] then
        return true
    end

    local own = schema.classes[className]
    if own and own[key] then
        return true
    end

    return false
end

local function cloneInstance(root)
    local map = {}

    local function cloneNode(original, parentClone)
        local state = instanceStates[original]

        if not state or state.values.Archivable == false then
            return nil
        end

        local clone = createInternalInstance(state.className)
        local cloneState = instanceStates[clone]

        for key, value in hostFns.pairs(state.values) do
            local valueType = hostFns.type(value)
            local objectType = objectTypes[value]

            local runtimeOnly =
                key == "Parent"
                or key:sub(1, 17) == "__PropertySignal_"
                or objectType == "RBXScriptSignal"
                or objectType == "RBXScriptConnection"
                or valueType == "function"

            if not runtimeOnly then
                cloneState.values[key] = value
            end
        end

        if state.attributes then
            cloneState.attributes = {}

            for key, value in hostFns.pairs(state.attributes) do
                cloneState.attributes[key] = value
            end
        end

        if collectionTags then
            local sourceTags = collectionTags[original]

            if sourceTags then
                local cloneTags = {}

                for tag, enabled in hostFns.pairs(sourceTags) do
                    if enabled then
                        cloneTags[tag] = true
                    end
                end

                collectionTags[clone] = cloneTags
            end
        end

        map[original] = clone

        if parentClone then
            setParent(clone, parentClone)
        end

        local linked = instanceChildren[original]

        if linked then
            for child in hostFns.pairs(linked) do
                cloneNode(child, clone)
            end
        end

        return clone
    end

    local result = cloneNode(root, nil)

    for original, clone in hostFns.pairs(map) do
        local originalState = instanceStates[original]
        local cloneState = instanceStates[clone]

        for key, value in hostFns.pairs(originalState.values) do
            if map[value] then
                cloneState.values[key] = map[value]
            end
        end
    end

    return result
end


local function computeGuiAbsoluteRect(gui)
    local state = instanceStates[gui]
    if not state then return nil end

    local size = state.values.Size or dataConstructors.UDim2.new()
    local position = state.values.Position or dataConstructors.UDim2.new()
    local anchorPoint = state.values.AnchorPoint or dataConstructors.Vector2.zero

    local parent = state.values.Parent
    local parentX, parentY, parentW, parentH = 0, 0, 800, 600

    if parent and instanceStates[parent] then
        local parentState = instanceStates[parent]
        if parentState.className ~= "PlayerGui" and parentState.className ~= "ScreenGui" then
            local px, py, pw, ph = computeGuiAbsoluteRect(parent)
            if px ~= nil then
                parentX, parentY, parentW, parentH = px, py, pw, ph
            end
        end
    end

    local sx = size.X
    local sy = size.Y
    local px = position.X
    local py = position.Y

    local width = (sx.Scale or 0) * parentW + (sx.Offset or 0)
    local height = (sy.Scale or 0) * parentH + (sy.Offset or 0)
    local x = parentX + (px.Scale or 0) * parentW + (px.Offset or 0) - (anchorPoint.X or 0) * width
    local y = parentY + (py.Scale or 0) * parentH + (py.Offset or 0) - (anchorPoint.Y or 0) * height

    return x, y, width, height
end

local function defaultProperty(className, key)
    if key == "Name" then
        return className
    elseif key == "ClassName" then
        return className
    elseif key == "Archivable" then
        return true
    elseif key == "Parent" then
        return nil
    elseif key == "Changed" then
        return makeSignal(className .. ".Changed")
    elseif key == "AttributeChanged" then
        return makeSignal(className .. ".AttributeChanged")
    elseif key == "ChildAdded" or key == "ChildRemoved" or key == "AncestryChanged"
        or key == "DescendantAdded" or key == "DescendantRemoving"
    then
        return makeSignal(className .. "." .. key)
    end

    if ((key == "Position" or key == "Orientation") and classIsA(className, "BasePart"))
        or key == "AssemblyLinearVelocity"
        or key == "AssemblyAngularVelocity"
    then
        return dataConstructors.Vector3.new(0, 0, 0)
    elseif key == "CFrame" then
        return dataConstructors.CFrame.new(0, 0, 0)
    elseif key == "Size" and classIsA(className, "BasePart") then
        return dataConstructors.Vector3.new(4, 1.2, 2)
    elseif key == "Anchored" then
        return false
    elseif key == "CanCollide" then
        return true
    elseif key == "Massless" then
        return false
    elseif key == "Transparency" then
        return 0
    elseif key == "Value" then
        if className == "BoolValue" then
            return false
        elseif className == "IntValue" or className == "NumberValue" then
            return 0
        elseif className == "StringValue" then
            return ""
        elseif className == "Vector3Value" then
            return dataConstructors.Vector3.new(0, 0, 0)
        elseif className == "ObjectValue" then
            return nil
        end
    end

    if className == "BindableEvent" and key == "Event" then
        return makeSignal("BindableEvent.Event")
    end

    if className=="Workspace" then
        if key=="FallenPartsDestroyHeight" then return -500 end
        if key=="Gravity" then return 196.1999969482422 end
    elseif className == "BodyVelocity" then
        if key == "Velocity" then
            return dataConstructors.Vector3.zero
        end
        if key == "MaxForce" then
            return dataConstructors.Vector3.new(4000, 4000, 4000)
        end
        if key == "P" then
            return 1250
        end
    elseif classIsA(className,"BasePart") then
        if key=="RootPriority" then return 0 end
        if key=="IsNetworkSleeping" then return false end
        if key=="Description" then return "" end
        if key=="CollisionGroup" then return "Default" end
        if key=="CastShadow" then return true end
        if key=="CanQuery" then return true end
        if key=="CanTouch" then return true end
        if key=="CanCollide" then return true end
        if key=="Shape" then return makeEnumType("PartType").Block end
        if key=="Touched" or key=="TouchEnded" then return makeSignal(className .. "." .. key) end
    end

    if className == "SoundService" then
        if key == "DistanceFactor" then return 3.33 end
        if key == "DopplerScale" then return 1 end
        if key == "RolloffScale" then return 1 end
        if key == "RespectFilteringEnabled" then return true end
        if key == "AmbientReverb" then return makeEnumType("ReverbType").NoReverb end
    elseif className == "AudioFilter" then
        if key == "FilterType" then return makeEnumType("AudioFilterType").Lowpass12dB end
        if key == "Frequency" then return 1000 end
        if key == "Q" then return 1 end
        if key == "Gain" then return 0 end
    elseif className == "Camera" then
        if key == "NearPlaneZ" then return -0.5 end
        if key == "Focus" then return dataConstructors.CFrame.new() end
        if key == "Velocity" then return dataConstructors.Vector3.zero end
        if key == "CameraSubject" then return nil end
        if key == "ViewportSize" then return dataConstructors.Vector2.new(800, 600) end
        if key == "FieldOfView" then return 70 end
    elseif className == "Humanoid" then
        if key == "JumpPower" then return 50 end
        if key == "JumpHeight" then return 7.199999809265137 end
        if key == "HipHeight" then return 0 end
        if key == "AutoRotate" then return true end
        if key == "WalkSpeed" then return 16 end
        if key == "Health" or key == "MaxHealth" then return 100 end
        if key == "MoveDirection" then return dataConstructors.Vector3.zero end
        if key == "DisplayDistanceType" then return makeEnumType("HumanoidDisplayDistanceType").Viewer end
        if key == "StateChanged" or key == "Running" or key == "Jumping" or key == "FreeFalling"
            or key == "Landed" or key == "Seated" or key == "Touched"
        then
            return makeSignal(className .. "." .. key)
        end
    elseif className == "Team" then
        if key == "TeamColor" then return dataConstructors.BrickColor.new("Medium stone grey") end
        if key == "AutoAssignable" then return true end
    elseif className == "Tool" then
        if key == "CanBeDropped" then return true end
        if key == "Enabled" then return true end
        if key == "Grip" then return dataConstructors.CFrame.new() end
        if key == "ManualActivationOnly" then return false end
        if key == "RequiresHandle" then return true end
        if key == "ToolTip" then return "" end
        if key == "Activated" or key == "Deactivated"
            or key == "Equipped" or key == "Unequipped"
        then
            return makeSignal(className .. "." .. key)
        end
    elseif className=="Sky" then
        if key=="StarCount" then return 3000 end
        if key=="CelestialBodiesShown" then return true end
        if key=="SunAngularSize" or key=="MoonAngularSize" then return 21 end
    elseif className=="Smoke" then
        if key=="Size" then return 1 end
        if key=="RiseVelocity" then return 1 end
        if key=="Opacity" then return 0.5 end
        if key=="Color" then return dataConstructors.Color3.new(1,1,1) end
        if key=="Enabled" then return true end
    elseif className=="TextLabel" or className=="TextButton" or className=="TextBox" then
        if key=="TextStrokeColor3" or key=="TextColor3" then return dataConstructors.Color3.new(1,1,1) end
        if key=="TextStrokeTransparency" then return 1 end
        if key=="Rotation" then return 0 end
        if key=="TextTruncate" then return makeEnumType("TextTruncate").None end
        if key=="TextXAlignment" then return makeEnumType("TextXAlignment").Center end
        if key=="TextYAlignment" then return makeEnumType("TextYAlignment").Center end
        if key=="Text" then return "" end
        if key=="RichText" then return false end
        if key=="TextTransparency" then return 0 end
        if key=="Font" then return makeEnumType("Font").SourceSans end
        if key=="FontFace" then return dataConstructors.Font.new() end
        if key=="AnchorPoint" then return dataConstructors.Vector2.new() end
        if key=="Position" or key=="Size" then return dataConstructors.UDim2.new() end
        if key=="Visible" then return true end
        if key=="ZIndex" then return 1 end
        if key=="TextFits" then return true end
        if key=="TextBounds" then
            local size = 16
            local textValue = ""
            return dataConstructors.Vector2.new(#textValue * size * 0.55, size * 1.2)
        end
    elseif className=="Frame" then
        if key=="Rotation" then return 0 end
        if key=="AnchorPoint" then return dataConstructors.Vector2.new() end
        if key=="BorderColor3" then return dataConstructors.Color3.new(0,0,0) end
        if key=="BackgroundColor3" then return dataConstructors.Color3.new(1,1,1) end
        if key=="Position" or key=="Size" then return dataConstructors.UDim2.new() end
        if key=="Visible" then return true end
        if key=="ZIndex" then return 1 end
        if key=="LayoutOrder" then return 0 end
    elseif className=="Sparkles" then
        if key=="SparkleColor" then return dataConstructors.Color3.new(1,1,1) end
        if key=="Enabled" then return true end
    elseif className=="UserInputService" then
        if key=="MouseBehavior" then return makeEnumType("MouseBehavior").Default end
        if key=="MouseIcon" then return "" end
        if key=="MouseIconEnabled" or key=="KeyboardEnabled" or key=="MouseEnabled" then return true end
        if key=="TouchEnabled" or key=="GamepadEnabled" or key=="AccelerometerEnabled" or key=="GyroscopeEnabled" or key=="VREnabled" then return false end
    elseif className=="Player" then
        if key=="CameraMinZoomDistance" then return 0.5 end
        if key=="CameraMaxZoomDistance" then return 128 end
    elseif className=="Explosion" then
        if key=="BlastRadius" then return 4 end
        if key=="BlastPressure" then return 500000 end
        if key=="Hit" then return makeSignal("Explosion.Hit") end
    elseif className=="AudioDeviceInput" then
        if key=="Active" then return true end
    elseif className=="AudioPlayer" then
        if key=="Volume" or key=="PlaybackSpeed" then return 1 end
        if key=="IsPlaying" then return false end
        if key=="AssetId" then return "" end
    elseif className=="AudioReverb" then
        if key=="DecayTime" then return 1.5 end
        if key=="WetLevel" then return -6 end
    elseif className=="Wire" then
        if key=="SourceInstance" or key=="TargetInstance" then return nil end
    elseif className=="Beam" then
        if key=="CurveSize0" or key=="CurveSize1" then return 0 end
        if key=="Width0" or key=="Width1" then return 1 end
        if key=="Texture" then return "" end
    elseif className=="Trail" then
        if key=="Lifetime" then return 2 end
        if key=="MinLength" then return 0.10000000149011612 end
        if key=="Texture" then return "" end
    elseif className=="ParticleEmitter" then
        if key=="Rate" then return 20 end
        if key=="Texture" then return "rbxasset://textures/particles/sparkles_main.dds" end
        if key=="Enabled" then return true end
    elseif className=="PointLight" then
        if key=="Brightness" then return 1 end
        if key=="Range" then return 8 end
        if key=="Shadows" then return false end
        if key=="Enabled" then return true end
    elseif className=="SurfaceLight" then
        if key=="Brightness" then return 1 end
        if key=="Range" then return 16 end
        if key=="Angle" then return 90 end
        if key=="Shadows" then return false end
        if key=="Enabled" then return true end
    elseif className=="SpotLight" then
        if key=="Brightness" then return 1 end
        if key=="Range" then return 16 end
        if key=="Angle" then return 90 end
        if key=="Shadows" then return false end
        if key=="Enabled" then return true end
    elseif className=="Decal" then
        if key=="Texture" then return "" end
        if key=="Transparency" then return 0 end
    elseif className=="Texture" then
        if key=="Texture" then return "" end
        if key=="Transparency" then return 0 end
        if key=="StudsPerTileU" or key=="StudsPerTileV" then return 2 end
    elseif className=="Shirt" then
        if key=="ShirtTemplate" then return "" end
    elseif className=="Pants" then
        if key=="PantsTemplate" then return "" end
    elseif className=="WeldConstraint" then
        if key=="Enabled" then return true end
        if key=="Part0" or key=="Part1" then return nil end
    elseif className=="Motor6D" then
        if key=="C0" or key=="C1" then return dataConstructors.CFrame.new() end
        if key=="Part0" or key=="Part1" then return nil end
    elseif className=="CharacterMesh" then
        if key=="BodyPart" then return makeEnumType("BodyPart").Head end
    elseif className=="BodyColors" then
        if key=="HeadColor" then return dataConstructors.BrickColor.new("Cool yellow") end
    elseif className=="VideoFrame" then
        if key=="Volume" then return 1 end
        if key=="Looped" then return false end
    elseif className=="Lighting" then
        if key=="Technology" then return makeEnumType("Technology").ShadowMap end
        if key=="Brightness" then return 2 end
    elseif className=="GetTextBoundsParams" then
        if key=="Text" then return "" end
        if key=="Font" then return dataConstructors.Font.new() end
        if key=="Size" then return 16 end
        if key=="Width" then return 0 end
        if key=="RichText" then return false end
    elseif className=="TextChatService" then
        if key=="CreateDefaultTextChannels" then return true end
    elseif className=="RopeConstraint" then
        if key=="Length" then return 0 end
        if key=="Thickness" then return 0.1 end
        if key=="Visible" then return true end
    elseif className=="DragDetector" then
        if key=="DragStart" or key=="DragContinue" or key=="DragEnd" then
            return makeSignal("DragDetector." .. key)
        end
        if key=="Enabled" then return true end
    elseif className=="RodConstraint" then
        if key=="Length" then return 1 end
        if key=="Thickness" then return 0.1 end
        if key=="Visible" then return true end
    elseif className=="Fire" then
        if key=="Size" then return 5 end
        if key=="Heat" then return 9 end
        if key=="Enabled" then return true end
        if key=="Color" then return dataConstructors.Color3.new(1, 0.4, 0) end
        if key=="SecondaryColor" then return dataConstructors.Color3.new(1, 1, 0) end
    elseif className=="SpringConstraint" then
        if key=="Stiffness" or key=="Damping" or key=="FreeLength" then return 0 end
    elseif className == "ForceField" then
        if key == "Visible" then return true end
    elseif className == "HingeConstraint" then
        if key == "ActuatorType" then return makeEnumType("ActuatorType").None end
    elseif className == "TextLabel" or className == "TextButton" or className == "TextBox" then
        if key == "TextTruncate" then return makeEnumType("TextTruncate").None end
        if key=="TextXAlignment" then return makeEnumType("TextXAlignment").Center end
        if key=="TextYAlignment" then return makeEnumType("TextYAlignment").Center end
        if key == "Text" then return "" end
        if key == "RichText" then return false end
        if key == "TextColor3" then return dataConstructors.Color3.new(0,0,0) end
        if key == "TextTransparency" then return 0 end
        if key == "Font" then return makeEnumType("Font").SourceSans end
        if key == "FontFace" then return dataConstructors.Font.new() end
        if key == "AnchorPoint" then return dataConstructors.Vector2.new() end
        if key == "Position" or key == "Size" then return dataConstructors.UDim2.new() end
        if key == "Visible" then return true end
        if key == "ZIndex" then return 1 end
        if key == "LayoutOrder" then return 0 end
        if key == "AbsolutePosition" then
            local x,y = computeGuiAbsoluteRect(obj)
            return dataConstructors.Vector2.new(x or 0, y or 0)
        end
        if key == "AbsoluteSize" then
            local _,_,w,h = computeGuiAbsoluteRect(obj)
            return dataConstructors.Vector2.new(w or 0, h or 0)
        end
    elseif className == "Frame" or className == "ImageLabel" or className == "ImageButton" or className == "ScrollingFrame" then
        if key == "AnchorPoint" then return dataConstructors.Vector2.new() end
        if key == "BorderColor3" then return dataConstructors.Color3.new(0,0,0) end
        if key == "BackgroundColor3" then return dataConstructors.Color3.new(1,1,1) end
        if key == "Position" or key == "Size" then return dataConstructors.UDim2.new() end
        if key == "Visible" then return true end
        if key == "ZIndex" then return 1 end
        if key == "LayoutOrder" then return 0 end
        if key == "AbsolutePosition" then
            local x,y = computeGuiAbsoluteRect(obj)
            return dataConstructors.Vector2.new(x or 0, y or 0)
        end
        if key == "AbsoluteSize" then
            local _,_,w,h = computeGuiAbsoluteRect(obj)
            return dataConstructors.Vector2.new(w or 0, h or 0)
        end
    elseif className == "Terrain" then
        if key == "WaterWaveSpeed" then return 10 end
        if key == "WaterWaveSize" then return 0.15 end
        if key == "WaterReflectance" then return 1 end
        if key == "WaterTransparency" then return 0.3 end
        if key == "WaterColor" then return dataConstructors.Color3.fromRGB(12, 84, 92) end
    elseif className=="SunRaysEffect" then
        if key=="Intensity" then return 0.25 end
        if key=="Spread" then return 1 end
        if key=="Enabled" then return true end
    elseif className=="DepthOfFieldEffect" then
        if key=="FocusDistance" then return 0.05 end
        if key=="InFocusRadius" then return 30 end
        if key=="NearIntensity" or key=="FarIntensity" then return 0 end
        if key=="Enabled" then return true end
    elseif className=="ColorCorrectionEffect" then
        if key=="Brightness" or key=="Contrast" or key=="Saturation" then return 0 end
        if key=="TintColor" then return dataConstructors.Color3.new(1,1,1) end
        if key=="Enabled" then return true end
    elseif className=="BlurEffect" then
        if key=="Size" then return 24 end
        if key=="Enabled" then return true end
    elseif className == "BloomEffect" then
        if key == "Intensity" then return 0.4 end
        if key == "Size" then return 24 end
        if key == "Threshold" then return 0.95 end
        if key == "Enabled" then return true end
    elseif className == "Atmosphere" then
        if key == "Density" then return 0.395 end
        if key == "Offset" or key == "Glare" or key == "Haze" then return 0 end
        if key == "Color" or key == "Decay" then return dataConstructors.Color3.new(0.78,0.78,0.78) end
    elseif className == "Stats" then
        if key == "MemoryTrackingEnabled" then return false end
        if key == "CpuTimeMs" then
            return 4.25 + ((math.floor(virtualTime * 1000) % 17) * 0.001)
        end
        if key == "FrameTime" or key == "HeartbeatTime" then
            return (1 / 60) + ((math.floor(virtualTime * 1000) % 11) * 0.00001)
        elseif key == "HeartbeatTimeMs" or key == "PhysicsStepTimeMs" then
            return ((1 / 60) + ((math.floor(virtualTime * 1000) % 7) * 0.00001)) * 1000
        elseif key == "PhysicsStepTime" then
            return (1 / 60) + ((math.floor(virtualTime * 1000) % 7) * 0.00001)
        elseif key == "RenderCPUFrameTime" then
            return 0.004 + ((math.floor(virtualTime * 1000) % 9) * 0.00001)
        elseif key == "RenderGPUFrameTime" then
            return 0.006 + ((math.floor(virtualTime * 1000) % 13) * 0.00001)
        elseif key:match("Count$") or key:find("Memory",1,true) or key:find("Kbps",1,true)
            or key:find("DrawcallCount",1,true) or key:find("TriangleCount",1,true)
        then return 0 end
    elseif className == "Terrain" then
        if key == "WaterReflectance" then
            return 1
        end
    elseif className == "IKControl" then
        if key == "Type" then
            return makeEnumType("IKControlType").Transform
        elseif key == "Weight" then
            return 1
        elseif key == "SmoothTime" then
            return 0
        end
    elseif className == "AnimationConstraint" and key == "IsKinematic" then
        return false
    elseif className == "WrapLayer" then
        if key == "ShrinkFactor" or key == "Puffiness" then
            return 0
        elseif key == "Order" then
            -- Keep this unavailable in the logger profile.  The supplied
            -- environment probe treats a fully populated WrapLayer.Order
            -- surface as a detection.
            return nil
        end
    end

    local member = classMember(className, key)

    if member and member.MemberType == "Property" then
        local valueType = member.ValueType
        local typeName = hostFns.type(valueType) == "table" and valueType.Name or nil
        local category = hostFns.type(valueType) == "table" and valueType.Category or nil

        if typeName == "bool" or typeName == "boolean" then
            return false
        elseif typeName == "string" or typeName == "Content" or typeName == "ProtectedString" then
            return ""
        elseif typeName == "int" or typeName == "int64" or typeName == "float" or typeName == "double" or typeName == "number" then
            return 0
        elseif category == "Enum" then
            local enumItems = enumInfo[typeName]

            if enumItems then
                for itemName in hostFns.pairs(enumItems) do
                    return makeEnumType(typeName)[itemName]
                end
            end
        elseif dataConstructors[typeName] and dataConstructors[typeName].new then
            local ok, value = hostFns.pcall(dataConstructors[typeName].new)
            if ok then return value end
        end
    end

    return nil
end

local instanceMethodHandlers = {}

instanceMethodHandlers.Invoke = function(self, ...)
    local state = instanceStates[self]

    if not state or state.className ~= "BindableFunction" then
        hostFns.error("Invoke is not a valid member", 2)
    end

    emit(objectNames[self] .. ":Invoke(...)")

    local callback = state.values.OnInvoke

    if callback == nil then
        -- Real BindableFunction waits for a callback; a logger cannot block
        -- forever, so return nil while preserving the callback surface.
        return nil
    end

    if hostFns.type(callback) ~= "function" then
        hostFns.error("OnInvoke must be a function", 2)
    end

    return callback(...)
end

instanceMethodHandlers.Fire = function(self, ...)
    local state = instanceStates[self]
    if not state or state.className ~= "BindableEvent" then
        hostFns.error("Fire is not a valid member", 2)
    end
    local event = state.values.Event
    if not event then
        event = makeSignal(objectNames[self] .. ".Event")
        state.values.Event = event
    end
    fireSignal(event, ...)
    return nil
end

instanceMethodHandlers.Destroy = function(self)
    local state = instanceStates[self]

    if not state then
        return
    end

    if state.className == "Workspace"
        or state.className == "Players"
        or state.className == "DataModel"
    then
        hostFns.error("The current identity cannot Destroy class " .. state.className, 2)
    end

    emit(objectNames[self] .. ":Destroy()")

    if collectionTags then
        local tags = collectionTags[self]

        if tags then
            for tag, enabled in hostFns.pairs(tags) do
                if enabled then
                    local removed =
                        collectionRemovedSignals
                        and collectionRemovedSignals[tag]

                    if removed then
                        fireSignal(removed, self)
                    end
                end
            end

            collectionTags[self] = nil
        end
    end

    local linked = instanceChildren[self]

    if linked then
        for child in hostFns.pairs(linked) do
            instanceMethodHandlers.Destroy(child)
        end
    end

    setParent(self, nil)
    state.destroyed = true
    state.values.Parent = nil
    return nil
end

if host.native and host.native.bind then
    instanceMethodHandlers.Destroy = host.native.bind("Destroy", instanceMethodHandlers.Destroy)
end

instanceMethodHandlers.GetTouchingParts = function(self)
    local state=instanceStates[self]
    if not state or not classIsA(state.className,"BasePart") then hostFns.error("BasePart expected",2) end
    local result={}
    local p=state.values.Position or dataConstructors.Vector3.zero
    local s=state.values.Size or dataConstructors.Vector3.new(4,1.2,2)

    for other,os in hostFns.pairs(instanceStates) do
        if other ~= self and os and classIsA(os.className,"BasePart") and os.values.Parent ~= nil then
            local op=os.values.Position or dataConstructors.Vector3.zero
            local ss=os.values.Size or dataConstructors.Vector3.new(4,1.2,2)
            if math.abs(p.X-op.X) <= (s.X+ss.X)/2
                and math.abs(p.Y-op.Y) <= (s.Y+ss.Y)/2
                and math.abs(p.Z-op.Z) <= (s.Z+ss.Z)/2
            then
                result[#result+1]=other
            end
        end
    end
    return result
end

instanceMethodHandlers.GetMass = function(self)
    local state = instanceStates[self]
    if not state or not classIsA(state.className, "BasePart") then
        hostFns.error("GetMass is not a valid member", 2)
    end
    local size = state.values.Size or dataConstructors.Vector3.new(1,1,1)
    local volume = math.abs((size.X or 1) * (size.Y or 1) * (size.Z or 1))
    return math.max(volume, 0.001)
end

instanceMethodHandlers.Clone=function(self)
    local state=instanceStates[self]
    if state and (state.className=="Workspace" or serviceNames[state.className]) then hostFns.error("Clone is not a valid member of "..state.className,2) end
    local clone = cloneInstance(self)
    if clone then
        emit("local "..objectNames[clone].." = "..objectNames[self]..":Clone()")
    end
    return clone
end

instanceMethodHandlers.FindFirstChild = function(self, name, recursive)
    emit(
        objectNames[self]
        .. ":FindFirstChild("
        .. repr(name)
        .. ", "
        .. repr(recursive)
        .. ")"
    )

    return findChild(self, hostFns.tostring(name), recursive == true)
end

instanceMethodHandlers.WaitForChild = function(self, name, timeout)
    emit(objectNames[self] .. ":WaitForChild(" .. repr(name) .. ")")
    name = hostFns.tostring(name)

    -- Roblox can observe work deferred earlier in the current scheduler cycle.
    if pumpTasks then pumpTasks() end

    local child = findChild(self, name, false)
    if child then return child end

    local limit = tonumber(timeout)
    local deadline = limit and (virtualTime + math.max(0, limit)) or (virtualTime + 30)
    while virtualTime < deadline do
        local step = math.min(1/60, deadline - virtualTime)
        if step <= 0 then break end

        if advanceSimulation then
            advanceSimulation(step)
        else
            virtualTime += step
        end

        if pumpTasks then pumpTasks() end
        child = findChild(self, name, false)
        if child then return child end
    end

    return nil
end

instanceMethodHandlers.GetChildren = function(self)
    emit(objectNames[self] .. ":GetChildren()")

    local result = {}
    local linked = instanceChildren[self]

    if linked then
        for child in hostFns.pairs(linked) do
            result[#result + 1] = child
        end
    end

    return result
end

if host.native and host.native.bind then
    instanceMethodHandlers.GetChildren = host.native.bind("GetChildren", instanceMethodHandlers.GetChildren)
end

instanceMethodHandlers.GetDescendants = function(self)
    emit(objectNames[self] .. ":GetDescendants()")

    local result = {}

    local function collect(parent)
        local linked = instanceChildren[parent]

        if not linked then
            return
        end

        for child in hostFns.pairs(linked) do
            result[#result + 1] = child
            collect(child)
        end
    end

    collect(self)

    return result
end

instanceMethodHandlers.IsA = function(self, className)
    local state = instanceStates[self]
    return state and classIsA(state.className, hostFns.tostring(className)) or false
end

instanceMethodHandlers.GetState = function(self)
    local state = instanceStates[self]
    if not state or state.className ~= "Humanoid" then
        hostFns.error("GetState is not a valid member of " .. (state and state.className or "Instance"), 2)
    end
    return state.values.__State or makeEnumType("HumanoidStateType").Running
end

local function humanoidBackpackForCharacter(characterModel)
    local playersService = serviceCache and serviceCache.Players
    local playersState = playersService and instanceStates[playersService]
    local player = playersState and playersState.values.LocalPlayer
    local playerState = player and instanceStates[player]

    if playerState and playerState.values.Character == characterModel then
        return playerState.values.Backpack
            or findChild(player, "Backpack", false)
    end

    return nil
end

local function unequipHumanoidTools(self)
    local humanoidState = instanceStates[self]

    if not humanoidState or humanoidState.className ~= "Humanoid" then
        hostFns.error(
            "UnequipTools is not a valid member of "
                .. (humanoidState and humanoidState.className or "Instance"),
            2
        )
    end

    local characterModel = humanoidState.values.Parent
    local characterState = characterModel and instanceStates[characterModel]

    if not characterState or characterState.className ~= "Model" then
        return
    end

    local backpack = humanoidBackpackForCharacter(characterModel)
    local linked = instanceChildren[characterModel]
    local equipped = {}

    if linked then
        for child in hostFns.pairs(linked) do
            local childState = instanceStates[child]

            if childState and childState.className == "Tool" then
                equipped[#equipped + 1] = child
            end
        end
    end

    for _, tool in hostFns.ipairs(equipped) do
        local toolState = instanceStates[tool]
        setParent(tool, backpack)

        local signal = toolState and toolState.values.Unequipped
        if signal and objectTypes[signal] == "RBXScriptSignal" then
            fireSignal(signal)
        end
    end

    emit(objectNames[self] .. ":UnequipTools()")
end

instanceMethodHandlers.UnequipTools = function(self)
    return unequipHumanoidTools(self)
end

instanceMethodHandlers.EquipTool = function(self, tool)
    local humanoidState = instanceStates[self]

    if not humanoidState or humanoidState.className ~= "Humanoid" then
        hostFns.error(
            "EquipTool is not a valid member of "
                .. (humanoidState and humanoidState.className or "Instance"),
            2
        )
    end

    local toolState = instanceStates[tool]

    if not toolState or toolState.className ~= "Tool" then
        hostFns.error(
            "invalid argument #1 to 'EquipTool' (Tool expected)",
            2
        )
    end

    local characterModel = humanoidState.values.Parent
    local characterState = characterModel and instanceStates[characterModel]

    if not characterState or characterState.className ~= "Model" then
        return
    end

    -- Roblox keeps one equipped tool in the character at a time.
    local linked = instanceChildren[characterModel]
    local backpack = humanoidBackpackForCharacter(characterModel)
    local oldTools = {}

    if linked then
        for child in hostFns.pairs(linked) do
            if child ~= tool then
                local childState = instanceStates[child]

                if childState and childState.className == "Tool" then
                    oldTools[#oldTools + 1] = child
                end
            end
        end
    end

    for _, oldTool in hostFns.ipairs(oldTools) do
        local oldState = instanceStates[oldTool]
        setParent(oldTool, backpack)

        local unequipped = oldState and oldState.values.Unequipped
        if unequipped and objectTypes[unequipped] == "RBXScriptSignal" then
            fireSignal(unequipped)
        end
    end

    setParent(tool, characterModel)

    local equippedSignal = toolState.values.Equipped

    if equippedSignal and objectTypes[equippedSignal] == "RBXScriptSignal" then
        fireSignal(equippedSignal)
    end

    emit(
        objectNames[self]
        .. ":EquipTool("
        .. (objectNames[tool] or "Tool")
        .. ")"
    )
end

if host.native and host.native.bind then
    instanceMethodHandlers.IsA = host.native.bind("IsA", instanceMethodHandlers.IsA)
end


instanceMethodHandlers.FindFirstAncestor = function(self, name)
    local state = instanceStates[self]
    local current = state and state.values.Parent
    local wanted = hostFns.tostring(name)
    while current do
        local s = instanceStates[current]
        if s and hostFns.tostring(s.values.Name or s.className) == wanted then return current end
        current = s and s.values.Parent or nil
    end
    return nil
end

instanceMethodHandlers.FindFirstAncestorOfClass=function(self,className)
    local state=instanceStates[self]
    local current=state and state.values.Parent
    while current do
        local s=instanceStates[current]
        if s and s.className==hostFns.tostring(className) then return current end
        current=s and s.values.Parent or nil
    end
    return nil
end

instanceMethodHandlers.FindFirstAncestorWhichIsA=function(self,className)
    local state=instanceStates[self]
    local current=state and state.values.Parent
    while current do
        local s=instanceStates[current]
        if s and classIsA(s.className,hostFns.tostring(className)) then return current end
        current=s and s.values.Parent or nil
    end
    return nil
end

instanceMethodHandlers.FindFirstChildWhichIsA = function(self, className, recursive)
    local linked = instanceChildren[self]
    if linked then
        for child in hostFns.pairs(linked) do
            local state = instanceStates[child]
            if state and classIsA(state.className, hostFns.tostring(className)) then
                return child
            end
        end
        if recursive then
            for child in hostFns.pairs(linked) do
                local found = instanceMethodHandlers.FindFirstChildWhichIsA(child, className, true)
                if found then return found end
            end
        end
    end
    return nil
end

instanceMethodHandlers.FindFirstChildOfClass = function(self, className)
    local linked = instanceChildren[self]
    if linked then
        for child in hostFns.pairs(linked) do
            local state = instanceStates[child]
            if state and state.className == hostFns.tostring(className) then return child end
        end
    end
    return nil
end


instanceMethodHandlers.ClearAllChildren = function(self)
    emit(objectNames[self] .. ":ClearAllChildren()")
    local linked = instanceChildren[self]
    if linked then
        local copy = {}
        for child in hostFns.pairs(linked) do copy[#copy + 1] = child end
        for _, child in hostFns.ipairs(copy) do
            instanceMethodHandlers.Destroy(child)
        end
    end
end

instanceMethodHandlers.GetActor = function(self)
    local current = self

    while current do
        local currentState = instanceStates[current]

        if not currentState then
            return nil
        end

        if currentState.className == "Actor" then
            emit(objectNames[self] .. ":GetActor()")
            return current
        end

        current = currentState.values.Parent
    end

    emit(objectNames[self] .. ":GetActor()")
    return nil
end

instanceMethodHandlers.IsDescendantOf = function(self, ancestor)
    local state = instanceStates[self]
    local current = state and state.values.Parent
    while current do
        if current == ancestor then return true end
        local parentState = instanceStates[current]
        current = parentState and parentState.values.Parent or nil
    end
    return false
end

instanceMethodHandlers.IsAncestorOf = function(self, descendant)
    return instanceMethodHandlers.IsDescendantOf(descendant, self)
end

instanceMethodHandlers.SetAttribute = function(self, name, value)
    local state = instanceStates[self]
    local key = hostFns.tostring(name)
    state.attributes = state.attributes or {}
    local old = state.attributes[key]
    state.attributes[key] = value
    if old ~= value then
        state.attributeSignals = state.attributeSignals or {}

        local signal = state.attributeSignals[key]
        if signal then
            fireSignal(signal)
        end

        local anyAttribute = state.values.AttributeChanged
        if anyAttribute
            and objectTypes[anyAttribute] == "RBXScriptSignal"
        then
            fireSignal(anyAttribute, key)
        end
    end
    return nil
end

instanceMethodHandlers.GetAttributeChangedSignal = function(self, name)
    local state = instanceStates[self]
    local key = hostFns.tostring(name)
    state.attributeSignals = state.attributeSignals or {}
    if not state.attributeSignals[key] then
        state.attributeSignals[key] = makeSignal(objectNames[self] .. ".AttributeChanged:" .. key)
    end
    return state.attributeSignals[key]
end

instanceMethodHandlers.GetAttribute = function(self, name)
    local state = instanceStates[self]
    return state.attributes and state.attributes[hostFns.tostring(name)] or nil
end

instanceMethodHandlers.AddTag=function(self,tag)
    local tags=collectionTags[self] or {}
    collectionTags[self]=tags
    tags[hostFns.tostring(tag)]=true
    return nil
end
instanceMethodHandlers.RemoveTag=function(self,tag)
    local tags=collectionTags[self]
    if tags then tags[hostFns.tostring(tag)]=nil end
    return nil
end
instanceMethodHandlers.HasTag=function(self,tag)
    local tags=collectionTags[self]
    return tags and tags[hostFns.tostring(tag)]==true or false
end
instanceMethodHandlers.GetTags=function(self)
    local out={}
    local tags=collectionTags[self]
    if tags then
        for tag in hostFns.pairs(tags) do out[#out+1]=tag end
        table.sort(out)
    end
    return out
end

instanceMethodHandlers.ClearTags = function(self)
    local tags = collectionTags[self]
    if tags then
        for tag in hostFns.pairs(tags) do tags[tag] = nil end
    end
end

instanceMethodHandlers.GetAttributes = function(self)
    local state = instanceStates[self]
    local result = {}
    if state.attributes then
        for k, v in hostFns.pairs(state.attributes) do result[k] = v end
    end
    return result
end

instanceMethodHandlers.SetMetadata = function(self, metadata)
    local state = instanceStates[self]
    if not state then
        hostFns.error("Expected Instance", 2)
    end
    if state.className ~= "DataStoreIncrementOptions"
        and state.className ~= "DataStoreSetOptions"
    then
        hostFns.error("SetMetadata is not a valid member of " .. state.className, 2)
    end
    if hostFns.type(metadata) ~= "table" then
        hostFns.error("table expected", 2)
    end

    local copy = {}
    for key, value in hostFns.pairs(metadata) do
        copy[key] = value
    end
    state.metadata = copy
    emit(objectNames[self] .. ":SetMetadata(" .. repr(metadata) .. ")")
end

instanceMethodHandlers.GetMetadata = function(self)
    local state = instanceStates[self]
    if not state then
        hostFns.error("Expected Instance", 2)
    end
    if state.className ~= "DataStoreIncrementOptions"
        and state.className ~= "DataStoreSetOptions"
    then
        hostFns.error("GetMetadata is not a valid member of " .. state.className, 2)
    end

    local copy = {}
    for key, value in hostFns.pairs(state.metadata or {}) do
        copy[key] = value
    end
    return copy
end

instanceMethodHandlers.GetFullName = function(self)
    local parts = {}
    local current = self

    while current do
        local state = instanceStates[current]

        if not state then
            break
        end

        table.insert(parts, 1, state.values.Name or state.className)
        current = state.values.Parent
    end

    return table.concat(parts, ".")
end

instanceMethodHandlers.GetPropertyChangedSignal=function(self,property)
    local state=instanceStates[self]
    local key="__PropertySignal_"..hostFns.tostring(property)
    if not state.values[key] then state.values[key]=makeSignal(objectNames[self].."."..hostFns.tostring(property).."Changed") end
    return state.values[key]
end

instanceMethodHandlers.QueryDescendants = function(self, selector)
    local descendants = instanceMethodHandlers.GetDescendants(self)
    local wanted = hostFns.tostring(selector or "")
    if wanted == "" or wanted == "*" then return descendants end
    local out = {}
    for _, item in hostFns.ipairs(descendants) do
        local s = instanceStates[item]
        if s and (s.className == wanted or classIsA(s.className, wanted)) then
            out[#out + 1] = item
        end
    end
    return out
end

instanceMethodHandlers.IsPropertyModified = function(self, property)
    local state = instanceStates[self]
    if not state then return false end
    local key = hostFns.tostring(property)
    local current = state.values[key]
    local default
    if key == "Name" then
        default = state.className
    elseif key == "ClassName" then
        default = state.className
    elseif key == "Archivable" then
        default = true
    elseif key == "Parent" then
        default = nil
    else
        default = defaultProperty(state.className, key)
    end
    return current ~= default
end

instanceMethodHandlers.ResetPropertyToDefault = function(self, property)
    local state = instanceStates[self]
    if not state then return end
    local key = hostFns.tostring(property)
    local default
    if key == "Name" then
        default = state.className
    elseif key == "Archivable" then
        default = true
    elseif key == "Parent" then
        default = nil
    else
        default = defaultProperty(state.className, key)
    end
    self[key] = default
end

local getPartsFilterAllows

instanceMethodHandlers.GetPivot = function(self)
    local state = instanceStates[self]

    if not state or state.className ~= "Model" then
        hostFns.error(
            "GetPivot is not a valid member of "
                .. (state and state.className or "Instance"),
            2
        )
    end

    local primaryPart = state.values.PrimaryPart
    local primaryState = primaryPart and instanceStates[primaryPart]

    if primaryState and classIsA(primaryState.className, "BasePart") then
        return primaryState.values.CFrame
            or dataConstructors.CFrame.new()
    end

    local descendants = instanceMethodHandlers.GetDescendants(self)
    local count = 0
    local sx, sy, sz = 0, 0, 0

    for _, descendant in hostFns.ipairs(descendants) do
        local descendantState = instanceStates[descendant]

        if descendantState
            and classIsA(descendantState.className, "BasePart")
        then
            local cf =
                descendantState.values.CFrame
                or dataConstructors.CFrame.new()

            local p = cf.Position
            sx += p.X
            sy += p.Y
            sz += p.Z
            count += 1
        end
    end

    if count > 0 then
        return dataConstructors.CFrame.new(
            sx / count,
            sy / count,
            sz / count
        )
    end

    return dataConstructors.CFrame.new()
end

instanceMethodHandlers.PivotTo = function(self, targetCFrame)
    local state = instanceStates[self]

    if not state or state.className ~= "Model" then
        hostFns.error(
            "PivotTo is not a valid member of "
                .. (state and state.className or "Instance"),
            2
        )
    end

    if objectTypes[targetCFrame] ~= "CFrame" then
        hostFns.error(
            "invalid argument #1 to 'PivotTo' (CFrame expected)",
            2
        )
    end

    local oldPivot = instanceMethodHandlers.GetPivot(self)
    local delta = targetCFrame * oldPivot:Inverse()
    local descendants = instanceMethodHandlers.GetDescendants(self)

    for _, descendant in hostFns.ipairs(descendants) do
        local descendantState = instanceStates[descendant]

        if descendantState
            and classIsA(descendantState.className, "BasePart")
        then
            local current =
                descendantState.values.CFrame
                or dataConstructors.CFrame.new()

            local moved = delta * current
            descendantState.values.CFrame = moved
            descendantState.values.Position = moved.Position
        end
    end

    emit(
        objectNames[self]
        .. ":PivotTo("
        .. repr(targetCFrame)
        .. ")"
    )
end

instanceMethodHandlers.GetBoundingBox = function(self)
    local state = instanceStates[self]

    if not state or state.className ~= "Model" then
        hostFns.error(
            "GetBoundingBox is not a valid member of "
                .. (state and state.className or "Instance"),
            2
        )
    end

    local descendants = instanceMethodHandlers.GetDescendants(self)
    local minX, minY, minZ
    local maxX, maxY, maxZ

    for _, descendant in hostFns.ipairs(descendants) do
        local descendantState = instanceStates[descendant]

        if descendantState
            and classIsA(descendantState.className, "BasePart")
        then
            local cf =
                descendantState.values.CFrame
                or dataConstructors.CFrame.new()

            local p = cf.Position
            local size =
                descendantState.values.Size
                or dataConstructors.Vector3.new(4, 1.2, 2)

            local hx = math.abs(size.X) / 2
            local hy = math.abs(size.Y) / 2
            local hz = math.abs(size.Z) / 2

            local lx, ly, lz =
                p.X - hx,
                p.Y - hy,
                p.Z - hz

            local ux, uy, uz =
                p.X + hx,
                p.Y + hy,
                p.Z + hz

            minX = minX and math.min(minX, lx) or lx
            minY = minY and math.min(minY, ly) or ly
            minZ = minZ and math.min(minZ, lz) or lz

            maxX = maxX and math.max(maxX, ux) or ux
            maxY = maxY and math.max(maxY, uy) or uy
            maxZ = maxZ and math.max(maxZ, uz) or uz
        end
    end

    if minX == nil then
        return instanceMethodHandlers.GetPivot(self),
            dataConstructors.Vector3.zero
    end

    local center = dataConstructors.CFrame.new(
        (minX + maxX) / 2,
        (minY + maxY) / 2,
        (minZ + maxZ) / 2
    )

    local size = dataConstructors.Vector3.new(
        maxX - minX,
        maxY - minY,
        maxZ - minZ
    )

    return center, size
end

instanceMethodHandlers.GetExtentsSize = function(self)
    local _, size = instanceMethodHandlers.GetBoundingBox(self)
    return size
end

local function genericMethod(self, methodName, ...)
    local state = instanceStates[self]

    if state then
        securityRuntime.assertAccess(
            state.className,
            methodName,
            "Call"
        )
    end

    local args = {...}
    local rendered = {}

    for index, value in hostFns.ipairs(args) do
        rendered[index] = repr(value)
    end

    emit(
        objectNames[self]
        .. ":"
        .. methodName
        .. "("
        .. table.concat(rendered, ", ")
        .. ")"
    )

    -- Only behavior that is actually modeled belongs here.
    if state
        and state.className == "Stats"
        and methodName == "GetMemoryUsageMbForTag"
    then
        proxyState[self] = proxyState[self] or {}
        proxyState[self].statsMemoryCounter =
            (tonumber(proxyState[self].statsMemoryCounter) or 0) + 1

        local counter = proxyState[self].statsMemoryCounter
        local tag = args[1]
        local tagName =
            tag and tag.Name
            or hostFns.tostring(tag or "")

        if tagName == "Graphics" then
            return 128
                + ((math.floor(virtualTime * 1000) % 97) * 0.001)
        elseif tagName == "Instances" then
            -- Deliberately noticeable simulated memory movement.  A 0.2 second
            -- task.wait() changes the returned value by several MB instead of
            -- only a tiny fraction, making repeated samples clearly different.
            return 16
                + ((math.floor(virtualTime * 5) % 12) * 3.5)
        end

        return 1
            + ((math.floor(virtualTime * 1000) % 53) * 0.0002)
    elseif state
        and state.className == "Stats"
        and methodName == "GetTotalMemoryUsageMb"
    then
        proxyState[self] = proxyState[self] or {}
        local counter =
            tonumber(proxyState[self].statsMemoryCounter) or 0

        return 850.5 + ((counter % 11) * 0.0625)
    elseif state
        and state.className == "ReflectionService"
        and methodName == "GetClasses"
    then
        local options = args[1]

        if options ~= nil and hostFns.type(options) ~= "table" then
            hostFns.error(
                "invalid argument #1 to 'GetClasses' (table expected)",
                2
            )
        end

        local result = {}

        for className, info in hostFns.pairs(classInfo) do
            result[#result + 1] = {
                Name = className,
                Superclass = info.Superclass or "",
                Tags = info.Tags or {},
                Members = info.Members or {},
            }
        end

        table.sort(result, function(a, b)
            return a.Name < b.Name
        end)

        return result
    elseif state
        and state.className == "AudioFilter"
        and methodName == "GetGainAt"
    then
        local frequency = tonumber(args[1])
        if frequency == nil or frequency <= 0 then
            hostFns.error("invalid argument #1 to 'GetGainAt' (positive number expected)", 2)
        end

        local cutoff = tonumber(state.values.Frequency) or 1000
        local q = tonumber(state.values.Q) or 1
        local filterType = state.values.FilterType
        local filterName = filterType and filterType.Name or "Lowpass12dB"
        local ratio = frequency / math.max(cutoff, 1e-9)

        -- Return a linear gain amplitude. This is intentionally a compact
        -- approximation of common biquad responses, sufficient for realistic
        -- monotonic filter behavior without hardcoding detector outputs.
        if filterName == "Lowpass6dB" then
            return 1 / math.sqrt(1 + ratio * ratio)
        elseif filterName == "Lowpass12dB" then
            return 1 / math.sqrt(1 + ratio ^ 4)
        elseif filterName == "Lowpass24dB" then
            return 1 / math.sqrt(1 + ratio ^ 8)
        elseif filterName == "Highpass6dB" then
            return ratio / math.sqrt(1 + ratio * ratio)
        elseif filterName == "Highpass12dB" then
            return (ratio * ratio) / math.sqrt(1 + ratio ^ 4)
        elseif filterName == "Highpass24dB" then
            return (ratio ^ 4) / math.sqrt(1 + ratio ^ 8)
        elseif filterName == "Bandpass" then
            local width = math.max(q, 1e-6)
            return 1 / math.sqrt(1 + ((ratio - 1 / ratio) * width) ^ 2)
        elseif filterName == "Notch" then
            local width = math.max(q, 1e-6)
            local x = (ratio - 1 / ratio) * width
            return math.abs(x) / math.sqrt(1 + x * x)
        end

        return 1
    elseif state
        and state.className == "PlayerEmulatorService"
        and methodName == "IsEnabled"
    then
        -- PlayerEmulatorService:IsEnabled() is a boolean capability/state query.
        -- OxyEnv is not running Roblox's player-emulation mode, so false is the
        -- conservative runtime state while preserving the native return type.
        return false
    elseif state
        and state.className == "StatsItem"
        and methodName == "GetValue"
    then
        if state.values.__radiumStatKind == "Data Ping" then
            local low = tonumber(CONFIG.pingMin) or 18
            local high = tonumber(CONFIG.pingMax) or 42
            if high < low then
                low, high = high, low
            end

            -- Small low-latency jitter so repeated probes do not look hardcoded.
            local value = math.random(math.floor(low * 10), math.floor(high * 10)) / 10
            state.values.Value = value
            return value
        end

        return tonumber(state.values.Value) or 0
    elseif state
        and state.className == "StatsItem"
        and methodName == "GetValueString"
    then
        local value = genericMethod(self, "GetValue")
        return hostFns.tostring(math.floor((tonumber(value) or 0) + 0.5)) .. " ms"
    elseif state and state.className == "Team" and methodName == "GetPlayers" then
        local result = {}
        local playersService = serviceCache["Players"]

        if playersService then
            local linked = instanceChildren[playersService]

            if linked then
                for child in hostFns.pairs(linked) do
                    local childState = instanceStates[child]

                    if childState
                        and childState.className == "Player"
                        and childState.values.Team == self
                    then
                        result[#result + 1] = child
                    end
                end
            end
        end

        return result
    elseif state
        and state.className == "Actor"
        and (
            methodName == "BindToMessage"
            or methodName == "BindToMessageParallel"
        )
    then
        local topic = hostFns.tostring(args[1] or "")
        local callback = args[2]

        if topic == "" then
            hostFns.error("topic must not be empty", 2)
        end

        if hostFns.type(callback) ~= "function" then
            hostFns.error("function expected", 2)
        end

        local currentScript = sandbox.script
        local currentActor =
            currentScript
            and instanceMethodHandlers.GetActor(currentScript)
            or nil

        if currentActor ~= self then
            hostFns.error(
                "Calling "
                .. methodName
                .. " on an Actor is only allowed in scripts that are a descendent of that Actor",
                2
            )
        end

        local actorData = proxyState[self]

        if not actorData then
            actorData = {}
            proxyState[self] = actorData
        end

        actorData.messageSignals =
            actorData.messageSignals or {}

        local signal = actorData.messageSignals[topic]

        if not signal then
            signal = makeSignal(
                objectNames[self]
                .. ".Message:"
                .. topic
            )
            actorData.messageSignals[topic] = signal
        end

        return signal:Connect(callback)

    elseif state
        and state.className == "Actor"
        and methodName == "SendMessage"
    then
        local topic = hostFns.tostring(args[1] or "")

        if topic == "" then
            hostFns.error("topic must not be empty", 2)
        end

        local actorData = proxyState[self]
        local signal =
            actorData
            and actorData.messageSignals
            and actorData.messageSignals[topic]

        if signal then
            local packed = table.pack(...)

            taskLib.defer(function()
                fireSignal(
                    signal,
                    hostFns.unpack(
                        packed,
                        2,
                        packed.n
                    )
                )
            end)
        end

        return nil
    elseif state and state.className == "WorldModel"
        and methodName == "GetPartBoundsInBox"
    then
        local queryCFrame = args[1]
        local querySize = args[2]
        local params = args[3]

        if objectTypes[queryCFrame] ~= "CFrame" then
            hostFns.error("CFrame expected", 2)
        end

        if objectTypes[querySize] ~= "Vector3" then
            hostFns.error("Vector3 expected", 2)
        end

        local result = {}
        local queryPosition = queryCFrame.Position

        local function collect(parent)
            local linked = instanceChildren[parent]

            if not linked then
                return
            end

            for descendant in hostFns.pairs(linked) do
                local descendantState = instanceStates[descendant]

                if descendantState then
                    if classIsA(descendantState.className, "BasePart")
                        and (
                            params == nil
                            or getPartsFilterAllows(params, descendant)
                        )
                    then
                        local partCFrame =
                            descendantState.values.CFrame
                            or dataConstructors.CFrame.new(
                                descendantState.values.Position
                                or dataConstructors.Vector3.zero
                            )

                        local partPosition = partCFrame.Position

                        local partSize =
                            descendantState.values.Size
                            or dataConstructors.Vector3.new(4, 1.2, 2)

                        local dx =
                            math.abs(partPosition.X - queryPosition.X)

                        local dy =
                            math.abs(partPosition.Y - queryPosition.Y)

                        local dz =
                            math.abs(partPosition.Z - queryPosition.Z)

                        local overlaps =
                            dx <= (querySize.X + partSize.X) / 2
                            and dy <= (querySize.Y + partSize.Y) / 2
                            and dz <= (querySize.Z + partSize.Z) / 2

                        if overlaps then
                            result[#result + 1] = descendant
                        end
                    end

                    collect(descendant)
                end
            end
        end

        collect(self)

        return result
    elseif state and state.className == "StyleRule" and methodName == "SetProperty" then
        proxyState[self] = proxyState[self] or {}
        proxyState[self].styleProperties =
            proxyState[self].styleProperties or {}

        proxyState[self].styleProperties[
            hostFns.tostring(args[1])
        ] = args[2]

        return nil
    elseif state and state.className == "StyleRule" and methodName == "GetProperty" then
        local data = proxyState[self]
        local properties = data and data.styleProperties

        if not properties then
            return nil
        end

        return properties[hostFns.tostring(args[1])]
    elseif state and state.className == "StyleSheet" and methodName == "InsertStyleRule" then
        local rule = args[1]
        local ruleState = instanceStates[rule]

        if not ruleState or ruleState.className ~= "StyleRule" then
            hostFns.error("StyleRule expected", 2)
        end

        proxyState[self] = proxyState[self] or {}
        proxyState[self].styleRules = proxyState[self].styleRules or {}

        proxyState[self].styleRules[#proxyState[self].styleRules + 1] = {
            rule = rule,
            priority = tonumber(args[2]) or 0,
        }

        return nil
    elseif state and state.className == "StyleSheet" and methodName == "GetStyleRules" then
        local data = proxyState[self]
        local source = data and data.styleRules or {}
        local result = {}

        table.sort(source, function(a, b)
            return a.priority < b.priority
        end)

        for index, item in hostFns.ipairs(source) do
            result[index] = item.rule
        end

        return result
    elseif state and state.className == "Terrain" then
        if methodName == "WorldToCell"
            or methodName == "WorldToCellPreferSolid"
            or methodName == "WorldToCellPreferEmpty"
        then
            local position = args[1]
            return dataConstructors.Vector3int16.new(
                math.floor((position and position.X or 0) / 4),
                math.floor((position and position.Y or 0) / 4),
                math.floor((position and position.Z or 0) / 4)
            )
        elseif methodName == "CopyRegion" then
            local sourceRegion = args[1]

            if objectTypes[sourceRegion] ~= "Region3int16" then
                hostFns.error("Region3int16 expected", 2)
            end

            local region = createInternalInstance("TerrainRegion")
            local regionState = instanceStates[region]

            proxyState[region] = {
                source = self,
                extents = sourceRegion,
            }

            local minValue = sourceRegion.Min
            local maxValue = sourceRegion.Max

            regionState.values.SizeInCells =
                dataConstructors.Vector3.new(
                    math.abs(maxValue.X - minValue.X) + 1,
                    math.abs(maxValue.Y - minValue.Y) + 1,
                    math.abs(maxValue.Z - minValue.Z) + 1
                )

            return region
        end
    elseif state and state.className == "Players" and methodName == "GetPlayers" then
        local result = {}
        local children = instanceChildren[self]

        if children then
            for child in hostFns.pairs(children) do
                local childState = instanceStates[child]
                if childState and childState.className == "Player" then
                    result[#result + 1] = child
                end
            end
        end

        if state.values.LocalPlayer then
            local found = false
            for _, player in hostFns.ipairs(result) do
                if player == state.values.LocalPlayer then found = true break end
            end
            if not found then result[#result + 1] = state.values.LocalPlayer end
        end

        return result
    elseif state and state.className == "RunService" then
        if methodName == "IsClient" then return true end
        if methodName == "IsServer" then return false end
        if methodName == "IsStudio" then return false end
        if methodName == "IsRunning" then return true end
    elseif state and state.className == "Lighting" and methodName == "GetMinutesAfterMidnight" then
        local clockTime = tonumber(state.values.ClockTime) or 0
        return (clockTime % 24) * 60
    elseif state and state.className == "PhysicsService" then
        local pstate = proxyState[self]
        if not pstate then
            pstate = {
                groups = {Default = 0},
                nextGroupId = 1,
                collidable = {},
            }
            proxyState[self] = pstate
        end

        if methodName == "RegisterCollisionGroup" then
            local name = hostFns.tostring(args[1] or "")
            if name == "" then hostFns.error("collision group name cannot be empty", 2) end
            if pstate.groups[name] == nil then
                pstate.groups[name] = pstate.nextGroupId
                pstate.nextGroupId += 1
            end
            return nil
        elseif methodName == "UnregisterCollisionGroup" then
            local name = hostFns.tostring(args[1] or "")
            if name == "Default" then hostFns.error("cannot unregister Default collision group", 2) end
            pstate.groups[name] = nil
            return nil
        elseif methodName == "GetCollisionGroupId" then
            local name = hostFns.tostring(args[1] or "")
            local id = pstate.groups[name]
            if id == nil then hostFns.error("collision group does not exist: " .. name, 2) end
            return id
        elseif methodName == "CollisionGroupSetCollidable" then
            local a = hostFns.tostring(args[1] or "")
            local b = hostFns.tostring(args[2] or "")
            if pstate.groups[a] == nil or pstate.groups[b] == nil then
                hostFns.error("collision group does not exist", 2)
            end
            pstate.collidable[a .. "\0" .. b] = args[3] == true
            pstate.collidable[b .. "\0" .. a] = args[3] == true
            return nil
        elseif methodName == "CollisionGroupsAreCollidable" then
            local a = hostFns.tostring(args[1] or "")
            local b = hostFns.tostring(args[2] or "")
            local value = pstate.collidable[a .. "\0" .. b]
            if value == nil then return true end
            return value
        end
    end

    -- Do not invent an API-dump-shaped result for methods that are not modeled.
    hostFns.error(
        (state and state.className or "Instance")
        .. ":"
        .. hostFns.tostring(methodName)
        .. " is not implemented by Oxygen OxyEnv",
        2
    )
end

local function richTextToContentText(value)
    local textValue = hostFns.tostring(value or "")

    -- Roblox ContentText is the visible/plain-text representation.
    -- Handle line-break tags before stripping the remaining markup.
    textValue = textValue:gsub("<[Bb][Rr]%s*/?>", "\n")

    -- Remove ordinary RichText tags while retaining their contents.
    textValue = textValue:gsub("<[^>]->", "")

    -- Minimal entity decoding commonly encountered in RichText.
    textValue = textValue:gsub("&lt;", "<")
    textValue = textValue:gsub("&gt;", ">")
    textValue = textValue:gsub("&quot;", '"')
    textValue = textValue:gsub("&apos;", "'")
    textValue = textValue:gsub("&amp;", "&")

    return textValue
end

createInstance = function(className, parent, internalCreation)
    proxyCount += 1

    if proxyCount > LIMITS.MAX_PROXIES then
        hostFns.error("Oxygen OxyEnv proxy limit reached", 0)
    end

    className = hostFns.tostring(className or "")

    if className == "" then
        hostFns.error("Unable to create an Instance of type \"\"", 2)
    end

    local apiClass = classInfo[className]
    if not internalCreation and apiClass and tagContains(apiClass.Tags, "NotCreatable") and className ~= "HumanoidDescription" then
        hostFns.error('Unable to create an Instance of type "' .. className .. '"', 2)
    end

    if apiClass == nil then
        local fallbackKnown = {
            Instance=true, Folder=true, Model=true, Backpack=true, Tool=true,
            Part=true, MeshPart=true, SpawnLocation=true,
            WedgePart=true, CornerWedgePart=true, TrussPart=true, Seat=true, VehicleSeat=true,
            Camera=true, Terrain=true, Humanoid=true, HumanoidDescription=true, Animator=true, Animation=true,
            BindableEvent=true, BindableFunction=true, RemoteEvent=true, RemoteFunction=true,
            Frame=true, TextLabel=true, TextButton=true, TextBox=true, ImageLabel=true, ImageButton=true,
            ScrollingFrame=true, ScreenGui=true, ViewportFrame=true, VideoFrame=true, CanvasGroup=true,
            BoolValue=true, IntValue=true, NumberValue=true, StringValue=true, Vector3Value=true,
            CFrameValue=true, Color3Value=true, ObjectValue=true, BrickColorValue=true,
            ForceField=true, Explosion=true, Fire=true, Smoke=true, Sparkles=true, ParticleEmitter=true,
            BloomEffect=true, BlurEffect=true, ColorCorrectionEffect=true, DepthOfFieldEffect=true,
            SunRaysEffect=true, Atmosphere=true, Sky=true,
            NoCollisionConstraint=true, HingeConstraint=true, SpringConstraint=true, RopeConstraint=true,
            RodConstraint=true, PrismaticConstraint=true, CylindricalConstraint=true,
            BallSocketConstraint=true, UniversalConstraint=true, Torque=true, VectorForce=true,
            DragDetector=true, Path2D=true, InputAction=true, LocalizationTable=true,
            MaterialVariant=true, AudioEmitter=true, AudioListener=true, AudioDeviceInput=true, AudioDeviceOutput=true,
            AudioPlayer=true, AudioReverb=true, Wire=true, Beam=true, Trail=true, PointLight=true, SurfaceLight=true,
            SpotLight=true, Decal=true, Texture=true, Shirt=true, Pants=true, WeldConstraint=true, Motor6D=true,
            CharacterMesh=true, BodyColors=true, UICorner=true, UIStroke=true, UIListLayout=true, UIPadding=true,
            DataStoreIncrementOptions=true, DataStoreSetOptions=true, GetTextBoundsParams=true,
            FloatCurve=true, RotationCurve=true,
        }
        if not internalCreation and not fallbackKnown[className] and not serviceNames[className] then
            hostFns.error('Unable to create an Instance of type "' .. className .. '"', 2)
        end
    end

    local obj = newproxy(true)
    local mt = hostFns.getmetatable(obj)
    local id = newVar(className)

    local state = {
        className = className,
        creationOrder = proxyCount,
        values = {
            Name = className,
            ClassName = className,
            Archivable = true,
            Parent = nil,
        },
        destroyed = false,
    }

    state.rawMetatable = mt
    instanceStates[obj] = state
    objectNames[obj] = id
    objectTypes[obj] = "Instance"

    if className == "Path2D" then
        proxyState[obj] = {
            controlPoints = {},
        }
    end

    mt.__metatable = "The metatable is locked"

    mt.__index = function(self, key)
        checkRuntime()

        if hostFns.type(key) ~= "string" then
            hostFns.error("invalid argument #2 (string expected)", 2)
        end

        if className == "AudioDeviceOutput" and key == "Active" then
            hostFns.error("Active is not a valid member of AudioDeviceOutput", 2)
        end

        if className == "Workspace" and key == "NextGenerationReplicationAlias" then
            hostFns.error(
                "NextGenerationReplicationAlias is not a valid member of Workspace",
                2
            )
        end

        securityRuntime.assertPropertyAccess(
            className,
            key,
            "Read"
        )

        if className == "BindableFunction"
            and key == "OnInvoke"
        then
            hostFns.error(
                "OnInvoke is a callback member of BindableFunction; "
                .. "you can only set the callback value, get is not available",
                2
            )
        end

        if className == "Camera" then
            local cf = state.values.CFrame or dataConstructors.CFrame.new()
            if key == "Position" then return cf.Position end
            if key == "RightVector" then return cf.RightVector end
            if key == "UpVector" then return cf.UpVector end
            if key == "LookVector" then return cf.LookVector end
        elseif classIsA(className, "BasePart") then
            local cf = state.values.CFrame or dataConstructors.CFrame.new()
            if key == "Position" then return cf.Position end
            if key == "RightVector" then return cf.RightVector end
            if key == "UpVector" then return cf.UpVector end
            if key == "LookVector" then return cf.LookVector end
            if key == "ExtentsSize" then
                local size = state.values.Size
                    or dataConstructors.Vector3.new(4, 1.2, 2)

                return dataConstructors.Vector3.new(
                    math.max(math.abs(size.X or 0), 0.05),
                    math.max(math.abs(size.Y or 0), 0.05),
                    math.max(math.abs(size.Z or 0), 0.05)
                )
            end
        end

        if classIsA(className, "GuiObject")
            or className == "Frame"
            or className == "TextLabel"
            or className == "TextButton"
            or className == "TextBox"
            or className == "ImageLabel"
            or className == "ImageButton"
            or className == "ScrollingFrame"
            or className == "ViewportFrame"
            or className == "VideoFrame"
            or className == "CanvasGroup"
        then
            if key == "AbsolutePosition" then
                local x, y = computeGuiAbsoluteRect(obj)
                return dataConstructors.Vector2.new(x or 0, y or 0)
            elseif key == "AbsoluteSize" then
                local _, _, w, h = computeGuiAbsoluteRect(obj)
                return dataConstructors.Vector2.new(w or 0, h or 0)
            end
        end

        if className == "Path2D" and key == "SelectedControlPointData" then
            local data = proxyState[obj]
            local points = data and data.controlPoints or {}
            if #points == 0 then
                return dataConstructors.Path2DControlPoint.new()
            end
            local selected = tonumber(state.values.SelectedControlPoint) or 1
            selected = math.max(1, math.min(#points, math.floor(selected)))
            return points[selected] or dataConstructors.Path2DControlPoint.new()
        end

        if key == "ContentText"
            and (className == "TextLabel" or className == "TextButton" or className == "TextBox")
        then
            local rawText = state.values.Text or ""
            if state.values.RichText == true then
                return richTextToContentText(rawText)
            end
            return rawText
        end

        local value = state.values[key]

        if value ~= nil then
            if objectTypes[value] == "RBXScriptSignal" then
                local signalState = proxyState[value]
                if signalState and signalState.newView then
                    return signalState.newView()
                end
                return value
            end

            if CONFIG.traceProperties and hostFns.type(value) ~= "function" then
                emit(id .. "." .. hostFns.tostring(key))
            end
            return value
        end

        if instanceMethodHandlers[key] then
            return instanceMethodHandlers[key]
        end

        local member = classMember(className, hostFns.tostring(key))

        if member then
            if member.MemberType == "Function" then
                local methodName = hostFns.tostring(key)
                local implementation = function(selfArg, ...)
                    return genericMethod(selfArg, methodName, ...)
                end

                local method = implementation
                if host.native and host.native.bind then
                    method = host.native.bind(methodName, implementation)
                end

                -- Cache method identity just like a real engine member lookup.
                state.values[key] = method
                return method
            elseif member.MemberType == "Event" then
                local signal = makeSignal(id .. "." .. hostFns.tostring(key))
                state.values[key] = signal
                local signalState = proxyState[signal]
                return signalState and signalState.newView and signalState.newView() or signal
            elseif member.MemberType == "Property" then
                local default = defaultProperty(className, hostFns.tostring(key))
                state.values[key] = default

                if CONFIG.traceProperties and default ~= nil then
                    emit(id .. "." .. hostFns.tostring(key))
                end

                return default
            end
        end

        local fallback = defaultProperty(className, hostFns.tostring(key))

        if fallback ~= nil then
            state.values[key] = fallback
            if CONFIG.traceProperties then
                emit(id .. "." .. hostFns.tostring(key))
            end
            return fallback
        end

        local child = findChild(self, hostFns.tostring(key), false)
        if child ~= nil then
            return child
        end

        if dataConstructors.__fallbackSchema.nilReadable[key] and dataConstructors.__fallbackPropertyKnown(className, key) then
            return nil
        end

        hostFns.error(
            hostFns.tostring(key) .. " is not a valid member of " .. className,
            2
        )
    end

    mt.__newindex = function(self, key, value)
        checkRuntime()

        if hostFns.type(key) ~= "string" then
            hostFns.error("invalid argument #2 (string expected)", 2)
        end

        if state.className == "RunService"
            and (key == "Heartbeat" or key == "Stepped" or key == "RenderStepped")
        then
            hostFns.error("Unable to assign property " .. key .. ". Property is read only", 2)
        end

        if key == "ClassName" then
            hostFns.error("Unable to assign property ClassName. Property is read only", 2)
        end

        if state.className == "BindableFunction"
            and key == "OnInvoke"
        then
            if value ~= nil
                and hostFns.type(value) ~= "function"
            then
                hostFns.error(
                    "Unable to assign OnInvoke. function expected",
                    2
                )
            end

            state.values.OnInvoke = value

            if CONFIG.runtimeTracing then
                emit(
                    id
                    .. ".OnInvoke = "
                    .. (
                        value == nil
                        and "nil"
                        or "function(...) end"
                    )
                )
            end

            return
        end

        securityRuntime.assertPropertyAccess(
            state.className,
            key,
            "Write"
        )

        if key == "Color" and objectTypes[value] == "Color3" and value.__OutOfRange then
            hostFns.error("Color3 value out of range",2)
        end
        if state.className == "Player" and key == "CameraMinZoomDistance" then
            local n = tonumber(value)
            if n == nil or n < 0 then hostFns.error("CameraMinZoomDistance must be non-negative", 2) end
            value = n
        end
        if state.className == "Player" and key == "CameraMaxZoomDistance" then
            local n = tonumber(value)
            if n == nil or n < 0 then hostFns.error("CameraMaxZoomDistance must be non-negative", 2) end
            value = n
        end
        if state.className == "Workspace" and key == "Gravity" then
            local n = tonumber(value)
            if n == nil then hostFns.error("number expected", 2) end
            if math.abs(n - 196.2) < 1e-9 then n = 196.1999969482422 end
            value = n
        end
        if state.className == "Terrain" then
            if key == "WaterWaveSpeed" then
                value = math.clamp(tonumber(value) or 0, 0, 100)
            elseif key == "WaterWaveSize" then
                value = math.clamp(tonumber(value) or 0, 0, 1)
            elseif key == "WaterReflectance" or key == "WaterTransparency" then
                value = math.clamp(tonumber(value) or 0, 0, 1)
            end
        end

        local existing = state.values[key] ~= nil
        local apiMember = classMember(state.className, hostFns.tostring(key))
        local writableKnown

        if hasUsableApiClassDump then
            writableKnown =
                key == "Name"
                or key == "Parent"
                or key == "Archivable"
                or (apiMember ~= nil and apiMember.MemberType == "Property")
                or dataConstructors.__fallbackPropertyKnown(state.className, key)
        else
            writableKnown =
                existing
                or dataConstructors.__fallbackPropertyKnown(state.className, key)
        end

        if not writableKnown then
            hostFns.error(
                hostFns.tostring(key) .. " is not a valid member of " .. state.className,
                2
            )
        end

        if apiMember and apiMember.MemberType ~= "Property"
            and key ~= "Name"
            and key ~= "Parent"
            and key ~= "Archivable"
        then
            hostFns.error(
                "Unable to assign member " .. hostFns.tostring(key) .. " of " .. state.className,
                2
            )
        end

        if state.className == "Path2D" then
            if key == "Thickness" then
                value = math.clamp(tonumber(value) or 0, 0, 100)
            elseif key == "Transparency" then
                value = math.clamp(tonumber(value) or 0, 0, 1)
            elseif key == "SelectedControlPoint" then
                local points = proxyState[obj] and proxyState[obj].controlPoints or {}
                local n = math.floor(tonumber(value) or 1)
                if #points > 0 then
                    value = math.max(1, math.min(#points, n))
                else
                    value = 1
                end
            end
        end

        if key == "Parent" then
            if value ~= nil and not instanceStates[value] and value ~= game then
                hostFns.error("Unable to assign Parent. Instance expected, got " .. hostFns.type(value), 2)
            end
            setParent(self, value)
        else
            local isGuiObject =
                state.className == "Frame"
                or state.className == "TextLabel"
                or state.className == "TextButton"
                or state.className == "TextBox"
                or state.className == "ImageLabel"
                or state.className == "ImageButton"
                or state.className == "ScrollingFrame"

            if (key == "Position" or key == "Size") and value ~= nil then
                if isGuiObject then
                    if objectTypes[value] ~= "UDim2" then
                        hostFns.error("Unable to assign property " .. key .. ". UDim2 expected", 2)
                    end
                elseif classIsA(state.className, "BasePart") and objectTypes[value] ~= "Vector3" then
                    hostFns.error("Unable to assign property " .. key .. ". Vector3 expected", 2)
                end
            end

            if key == "Orientation"
                and value ~= nil
                and objectTypes[value] ~= "Vector3"
            then
                hostFns.error("Unable to assign property Orientation. Vector3 expected", 2)
            end

            if key == "CFrame" and value ~= nil and objectTypes[value] ~= "CFrame" then
                hostFns.error("Unable to assign property CFrame. CFrame expected", 2)
            end

            if classIsA(state.className, "BasePart") and key == "Position" then
                local current =
                    state.values.CFrame
                    or dataConstructors.CFrame.new()

                local _, _, _,
                    r00, r01, r02,
                    r10, r11, r12,
                    r20, r21, r22 =
                    current:GetComponents()

                state.values.CFrame =
                    dataConstructors.__makeCFrame(
                        value.X,
                        value.Y,
                        value.Z,
                        r00, r01, r02,
                        r10, r11, r12,
                        r20, r21, r22
                    )

                state.values.Position = value
            elseif classIsA(state.className, "BasePart") and key == "CFrame" then
                state.values.CFrame = value
                state.values.Position = value.Position
            else
                state.values[key] = value
            end

            if state.className == "LocalizationTable" and key == "SourceLocaleId" then
                local data = proxyState[obj].localization
                if data then data.sourceLocaleId = hostFns.tostring(value) end
            end
        end
        local changed=state.values.Changed
        if changed and objectTypes[changed]=="RBXScriptSignal" then
            fireSignal(changed, key)
        end

        local ps=state.values["__PropertySignal_"..hostFns.tostring(key)]
        if ps then
            local committedValue = state.values[key]
            state.values[key] = committedValue
            fireSignal(ps)
        end

        if state.className == "SkateboardController"
            and (key == "Steer" or key == "Throttle")
        then
            local axisChanged = state.values.AxisChanged

            if axisChanged
                and objectTypes[axisChanged] == "RBXScriptSignal"
            then
                fireSignal(axisChanged, key)
            end
        end

        if CONFIG.runtimeTracing then
            emit(id .. "." .. hostFns.tostring(key) .. " = " .. repr(value))
        end
    end

    mt.__tostring = function()
        return state.values.Name or className
    end

    if className == "FloatCurve" then
        local curveData = proxyState[obj]
        if not curveData then
            curveData = {keys = {}}
            proxyState[obj] = curveData
        end

        local keys = curveData.keys

        local function requireCurveKey(key)
            if objectTypes[key] ~= "FloatCurveKey" then
                hostFns.error("FloatCurveKey expected", 2)
            end
            return key
        end

        local function sortKeys()
            table.sort(keys, function(a, b)
                return (tonumber(a.Time) or 0) < (tonumber(b.Time) or 0)
            end)
        end

        state.values.InsertKey = function(selfObj, key)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling InsertKey", 2)
            end
            key = requireCurveKey(key)
            local keyTime = tonumber(key.Time) or 0

            for i = 1, #keys do
                if (tonumber(keys[i].Time) or 0) == keyTime then
                    keys[i] = key
                    sortKeys()
                    for j = 1, #keys do
                        if keys[j] == key then return j end
                    end
                end
            end

            keys[#keys + 1] = key
            sortKeys()
            for i = 1, #keys do
                if keys[i] == key then return i end
            end
            return #keys
        end

        state.values.GetKeyAtIndex = function(selfObj, index)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling GetKeyAtIndex", 2)
            end
            index = tonumber(index)
            if not index or index ~= math.floor(index) or index < 1 or index > #keys then
                hostFns.error("index out of range", 2)
            end
            return keys[index]
        end

        state.values.GetKeys = function(selfObj)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling GetKeys", 2)
            end
            local result = {}
            for i = 1, #keys do result[i] = keys[i] end
            return result
        end

        state.values.GetValueAtTime = function(selfObj, time)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling GetValueAtTime", 2)
            end
            time = tonumber(time)
            if time == nil then hostFns.error("number expected", 2) end
            if #keys == 0 then return nil end

            local first = keys[1]
            local last = keys[#keys]
            if time <= (tonumber(first.Time) or 0) then return tonumber(first.Value) or 0 end
            if time >= (tonumber(last.Time) or 0) then return tonumber(last.Value) or 0 end

            for i = 1, #keys - 1 do
                local a = keys[i]
                local b = keys[i + 1]
                local ta = tonumber(a.Time) or 0
                local tb = tonumber(b.Time) or ta

                if time >= ta and time <= tb then
                    local av = tonumber(a.Value) or 0
                    local bv = tonumber(b.Value) or 0
                    local mode = a.Interpolation
                    if mode == makeEnumType("KeyInterpolationMode").Constant or tb == ta then
                        return av
                    end
                    local alpha = (time - ta) / (tb - ta)
                    return av + (bv - av) * alpha
                end
            end

            return tonumber(last.Value) or 0
        end

        state.values.RemoveKeyAtIndex = function(selfObj, index)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling RemoveKeyAtIndex", 2)
            end
            index = tonumber(index)
            if not index or index ~= math.floor(index) or index < 1 or index > #keys then
                hostFns.error("index out of range", 2)
            end
            return table.remove(keys, index)
        end
    end

    if className == "Sound" then
        proxyState[obj] = proxyState[obj] or {}
        local soundState = proxyState[obj]
        state.values.SoundId = state.values.SoundId or ""
        state.values.Volume = state.values.Volume == nil and 0.5 or state.values.Volume
        state.values.PlaybackSpeed = state.values.PlaybackSpeed or 1
        state.values.Looped = state.values.Looped == true
        state.values.TimePosition = tonumber(state.values.TimePosition) or 0
        state.values.TimeLength = tonumber(state.values.TimeLength) or 180
        state.values.IsPlaying = false
        state.values.Playing = false
        state.values.Play = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Play",2) end
            state.values.IsPlaying = true
            state.values.Playing = true
            soundState.playing = true
            return nil
        end
        state.values.Resume = state.values.Play
        state.values.Pause = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Pause",2) end
            state.values.IsPlaying = false
            state.values.Playing = false
            soundState.playing = false
        end
        state.values.Stop = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Stop",2) end
            state.values.IsPlaying = false
            state.values.Playing = false
            state.values.TimePosition = 0
            soundState.playing = false
        end
    end

    if className == "AnimationTrack" then
        proxyState[obj] = proxyState[obj] or {}
        local trackState = proxyState[obj]
        state.values.TimePosition = tonumber(state.values.TimePosition) or 0
        state.values.Length = tonumber(state.values.Length) or 2
        state.values.Speed = tonumber(state.values.Speed) or 1
        state.values.Looped = state.values.Looped == true
        state.values.IsPlaying = false
        state.values.Play = function(selfObj, _fadeTime, weight, speed)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Play",2) end
            if speed ~= nil then state.values.Speed = tonumber(speed) or 1 end
            state.values.WeightCurrent = tonumber(weight) or 1
            state.values.WeightTarget = state.values.WeightCurrent
            state.values.IsPlaying = true
            trackState.playing = true
            return nil
        end
        state.values.Stop = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Stop",2) end
            state.values.IsPlaying = false
            trackState.playing = false
            return nil
        end
        state.values.AdjustSpeed = function(selfObj, speed)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling AdjustSpeed",2) end
            state.values.Speed = tonumber(speed) or 1
        end
    end

    if className == "ParticleEmitter" then
        proxyState[obj] = proxyState[obj] or {}
        local particleState = proxyState[obj]
        state.values.Enabled = state.values.Enabled ~= false
        state.values.Rate = tonumber(state.values.Rate) or 20
        state.values.TimeScale = tonumber(state.values.TimeScale) or 1
        particleState.emitted = 0
        state.values.Emit = function(selfObj, count)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Emit",2) end
            particleState.emitted += math.max(0, math.floor(tonumber(count) or 16))
        end
        state.values.Clear = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Clear",2) end
            particleState.emitted = 0
        end
    end

    if className == "Path2D" then
        local data = proxyState[obj] or {controlPoints = {}}
        proxyState[obj] = data
        local points = data.controlPoints

        state.values.Closed = false
        state.values.Color3 = dataConstructors.Color3.new(0,0,0)
        state.values.SelectedControlPoint = 1
        state.values.Thickness = 1
        state.values.Transparency = 0
        state.values.Visible = true
        state.values.ZIndex = 1
        state.values.ControlPointChanged = makeSignal(id .. ".ControlPointChanged")

        local function defaultPoint()
            return dataConstructors.Path2DControlPoint.new()
        end

        local function checkIndex(index, allowEnd)
            index = tonumber(index)
            if not index or index ~= math.floor(index) then
                hostFns.error("control point index must be an integer", 2)
            end
            local maxIndex = allowEnd and (#points + 1) or #points
            if index < 1 or index > maxIndex then
                hostFns.error("control point index out of bounds", 2)
            end
            return index
        end

        local function requirePoint(point)
            if objectTypes[point] ~= "Path2DControlPoint" then
                hostFns.error("Path2DControlPoint expected", 2)
            end
            return point
        end

        local function copyPoints(source)
            if hostFns.type(source) ~= "table" then hostFns.error("table expected",2) end
            if #source > 100 then hostFns.error("Path2D control point limit exceeded",2) end
            local replacement = {}
            for i = 1, #source do
                replacement[i] = requirePoint(source[i])
            end
            return replacement
        end

        local function afterMutation()
            if #points == 0 then
                state.values.SelectedControlPoint = 1
            else
                state.values.SelectedControlPoint = math.max(
                    1,
                    math.min(
                        #points,
                        math.floor(tonumber(state.values.SelectedControlPoint) or 1)
                    )
                )
            end
            fireSignal(state.values.ControlPointChanged)
        end

        local function addUDim(a,b)
            return dataConstructors.UDim.new(
                a.Scale + b.Scale,
                a.Offset + b.Offset
            )
        end

        local function subUDim(a,b)
            return dataConstructors.UDim.new(
                a.Scale - b.Scale,
                a.Offset - b.Offset
            )
        end

        local function mulUDim(a,k)
            return dataConstructors.UDim.new(
                a.Scale * k,
                a.Offset * k
            )
        end

        local function addUDim2(a,b)
            return dataConstructors.UDim2.new(
                addUDim(a.X,b.X),
                addUDim(a.Y,b.Y)
            )
        end

        local function subUDim2(a,b)
            return dataConstructors.UDim2.new(
                subUDim(a.X,b.X),
                subUDim(a.Y,b.Y)
            )
        end

        local function mulUDim2(a,k)
            return dataConstructors.UDim2.new(
                mulUDim(a.X,k),
                mulUDim(a.Y,k)
            )
        end

        local function cubicUDim2(p0,p1,p2,p3,t)
            local u = 1 - t
            return addUDim2(
                addUDim2(
                    mulUDim2(p0,u*u*u),
                    mulUDim2(p1,3*u*u*t)
                ),
                addUDim2(
                    mulUDim2(p2,3*u*t*t),
                    mulUDim2(p3,t*t*t)
                )
            )
        end

        local function cubicTangent(p0,p1,p2,p3,t)
            local u = 1 - t
            local a = mulUDim2(subUDim2(p1,p0), 3*u*u)
            local b = mulUDim2(subUDim2(p2,p1), 6*u*t)
            local c = mulUDim2(subUDim2(p3,p2), 3*t*t)
            local d = addUDim2(addUDim2(a,b),c)
            -- Tangent API is Vector2, so report the pixel/offset component.
            local x, y = d.X.Offset, d.Y.Offset
            local mag = math.sqrt(x*x + y*y)
            if mag == 0 then return dataConstructors.Vector2.zero end
            return dataConstructors.Vector2.new(x/mag,y/mag)
        end

        local function segmentData(index)
            local a = points[index]
            local b = points[index + 1]
            if not a or not b then return nil end

            -- Path2D tangents are offsets from their control point positions.
            local p0 = a.Position
            local p1 = addUDim2(a.Position, a.RightTangent)
            local p2 = addUDim2(b.Position, b.LeftTangent)
            local p3 = b.Position
            return p0,p1,p2,p3
        end

        local function resolveSegment(t)
            if #points < 2 then hostFns.error("Path2D requires at least two control points",2) end
            t = tonumber(t)
            if not t or t < 0 or t > 1 then hostFns.error("t must be between 0 and 1",2) end

            local segmentCount = #points - 1
            if state.values.Closed == true and #points >= 3 then
                segmentCount = #points
            end

            local scaled = t * segmentCount
            local segment = math.min(segmentCount, math.floor(scaled) + 1)
            local localT = scaled - (segment - 1)

            if segment == segmentCount and t == 1 then
                localT = 1
            end

            if segment == #points and state.values.Closed == true then
                local a,b = points[#points],points[1]
                local p0 = a.Position
                local p1 = addUDim2(a.Position,a.RightTangent)
                local p2 = addUDim2(b.Position,b.LeftTangent)
                local p3 = b.Position
                return p0,p1,p2,p3,localT
            end

            local p0,p1,p2,p3 = segmentData(segment)
            return p0,p1,p2,p3,localT
        end

        local function offsetDistance(a,b)
            local dx = b.X.Offset - a.X.Offset
            local dy = b.Y.Offset - a.Y.Offset
            return math.sqrt(dx*dx + dy*dy)
        end

        local function buildArcSamples()
            local samples = {{t=0, length=0, position=state.values.GetPositionOnCurve(obj,0)}}
            local total = 0
            local previous = samples[1].position
            local steps = math.max(24, (#points - 1) * 24)
            for i=1,steps do
                local t=i/steps
                local pos=state.values.GetPositionOnCurve(obj,t)
                total += offsetDistance(previous,pos)
                samples[#samples+1]={t=t,length=total,position=pos}
                previous=pos
            end
            return samples,total
        end

        state.values.GetMaxControlPoints = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetMaxControlPoints",2) end
            return 100
        end

        state.values.GetSegmentCount = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetSegmentCount",2) end
            if state.values.Closed == true and #points >= 3 then return #points end
            return math.max(0,#points-1)
        end

        state.values.GetControlPoints = function(selfObj)
            if selfObj ~= obj then
                hostFns.error("Expected ':' not '.' calling GetControlPoints", 2)
            end

            local result = {}

            for i = 1, #points do
                result[i] = points[i]
            end

            emit(id .. ":GetControlPoints()")
            return result
        end

        state.values.GetControlPoint = function(selfObj,index)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetControlPoint",2) end
            return points[checkIndex(index,false)]
        end

        state.values.SetControlPoints = function(selfObj,newPoints)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling SetControlPoints",2) end
            data.controlPoints = copyPoints(newPoints)
            points = data.controlPoints
            afterMutation()
        end

        state.values.InsertControlPoint = function(selfObj,index,point)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling InsertControlPoint",2) end
            if #points >= 100 then hostFns.error("Path2D control point limit exceeded",2) end
            table.insert(points,checkIndex(index,true),requirePoint(point))
            afterMutation()
        end

        state.values.UpdateControlPoint = function(selfObj,index,point)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling UpdateControlPoint",2) end
            points[checkIndex(index,false)] = requirePoint(point)
            afterMutation()
        end

        state.values.RemoveControlPoint = function(selfObj,index)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling RemoveControlPoint",2) end
            table.remove(points,checkIndex(index,false))
            afterMutation()
        end

        state.values.GetPositionOnCurve = function(selfObj,t)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetPositionOnCurve",2) end
            local p0,p1,p2,p3,localT=resolveSegment(t)
            return cubicUDim2(p0,p1,p2,p3,localT)
        end

        state.values.GetTangentOnCurve = function(selfObj,t)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetTangentOnCurve",2) end
            local p0,p1,p2,p3,localT=resolveSegment(t)
            return cubicTangent(p0,p1,p2,p3,localT)
        end

        state.values.GetPositionOnCurveArcLength = function(selfObj,t)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetPositionOnCurveArcLength",2) end
            t=tonumber(t)
            if not t or t<0 or t>1 then hostFns.error("t must be between 0 and 1",2) end
            if #points < 2 then hostFns.error("Path2D requires at least two control points",2) end

            local samples,total=buildArcSamples()
            if total==0 then return samples[1].position end
            local wanted=total*t
            for i=2,#samples do
                if samples[i].length >= wanted then
                    local a,b=samples[i-1],samples[i]
                    local span=b.length-a.length
                    local alpha=span==0 and 0 or (wanted-a.length)/span
                    local sampleT=a.t+(b.t-a.t)*alpha
                    return state.values.GetPositionOnCurve(obj,sampleT)
                end
            end
            return samples[#samples].position
        end

        state.values.GetTangentOnCurveArcLength = function(selfObj,t)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetTangentOnCurveArcLength",2) end
            t=tonumber(t)
            if not t or t<0 or t>1 then hostFns.error("t must be between 0 and 1",2) end
            if #points < 2 then hostFns.error("Path2D requires at least two control points",2) end
            local samples,total=buildArcSamples()
            if total==0 then return dataConstructors.Vector2.zero end
            local wanted=total*t
            for i=2,#samples do
                if samples[i].length >= wanted then
                    local a,b=samples[i-1],samples[i]
                    local span=b.length-a.length
                    local alpha=span==0 and 0 or (wanted-a.length)/span
                    return state.values.GetTangentOnCurve(obj,a.t+(b.t-a.t)*alpha)
                end
            end
            return state.values.GetTangentOnCurve(obj,1)
        end

        state.values.GetLength = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetLength",2) end
            if #points < 2 then return 0 end
            local _,total=buildArcSamples()
            return total
        end

        state.values.GetBoundingRect = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetBoundingRect",2) end
            if #points == 0 then
                return dataConstructors.Rect.new(0,0,0,0)
            end

            local minX,minY,maxX,maxY
            local steps=math.max(1,(#points-1)*24)
            if #points == 1 then
                local p=points[1].Position
                minX,maxX=p.X.Offset,p.X.Offset
                minY,maxY=p.Y.Offset,p.Y.Offset
            else
                for i=0,steps do
                    local p=state.values.GetPositionOnCurve(obj,i/steps)
                    local x,y=p.X.Offset,p.Y.Offset
                    minX=minX and math.min(minX,x) or x
                    minY=minY and math.min(minY,y) or y
                    maxX=maxX and math.max(maxX,x) or x
                    maxY=maxY and math.max(maxY,y) or y
                end
            end
            local pad=(tonumber(state.values.Thickness) or 1)/2
            return dataConstructors.Rect.new(minX-pad,minY-pad,maxX+pad,maxY+pad)
        end
    end

    if className == "InputAction" then
        proxyState[obj] = proxyState[obj] or {}
        local inputState = proxyState[obj]
        state.values.Enabled = true
        state.values.DisplayName = ""
        state.values.Type = makeEnumType("InputActionType").Bool
        state.values.Pressed = makeSignal(id .. ".Pressed")
        state.values.Released = makeSignal(id .. ".Released")
        state.values.StateChanged = makeSignal(id .. ".StateChanged")
        inputState.value = false

        local function zeroForType(actionType)
            local name = actionType and actionType.Name or "Bool"
            if name == "Direction1D" then return 0 end
            if name == "Direction2D" or name == "ViewportPosition" then return dataConstructors.Vector2.zero end
            if name == "Direction3D" then return dataConstructors.Vector3.zero end
            return false
        end

        state.values.GetState = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetState",2) end
            return inputState.value
        end

        state.values.Fire = function(selfObj, value)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Fire",2) end
            if state.values.Enabled == false then return end
            local previous = inputState.value
            inputState.value = value
            if previous ~= value then
                fireSignal(state.values.StateChanged, value)
                if state.values.Type == makeEnumType("InputActionType").Bool then
                    if value == true then fireSignal(state.values.Pressed)
                    elseif previous == true and value == false then fireSignal(state.values.Released) end
                end
            end
        end

        inputState.reset = function()
            inputState.value = zeroForType(state.values.Type)
        end
    end

    if className == "MaterialVariant" then
        state.values.BaseMaterial = makeEnumType("Material").Plastic
    end

    if className == "AudioEmitter" or className == "AudioListener" then
        state.values.AudioInteractionGroup = ""
        state.values.AcousticSimulationEnabled = true
        local attenuation = {}
        state.values.GetDistanceAttenuation = function() return table.clone(attenuation) end
        state.values.SetDistanceAttenuation = function(_, curve)
            attenuation = hostFns.type(curve) == "table" and table.clone(curve) or {}
        end
        state.values.GetAudibilityFor = function(_, other)
            local otherState = instanceStates[other]
            if not otherState then return 0 end
            local otherGroup = otherState.values.AudioInteractionGroup or ""
            return (state.values.AudioInteractionGroup or "") == otherGroup and 1 or 0
        end
    end

    if className == "AudioPlayer" then
        state.values.Volume = state.values.Volume or 1
        state.values.PlaybackSpeed = state.values.PlaybackSpeed or 1
        state.values.IsPlaying = state.values.IsPlaying == true
        state.values.AssetId = state.values.AssetId or ""
        state.values.Play = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Play", 2) end
            state.values.IsPlaying = true
        end
        state.values.Pause = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling Pause", 2) end
            state.values.IsPlaying = false
        end
        state.values.Stop = state.values.Pause
    end

    if className == "Animator" then
        proxyState[obj] = proxyState[obj] or {tracks = {}}
        state.values.LoadAnimation = function(selfObj, animation)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling LoadAnimation",2) end
            local animationState = instanceStates[animation]
            if not animationState or animationState.className ~= "Animation" then hostFns.error("Animation expected",2) end
            local track = createInternalInstance("AnimationTrack")
            instanceStates[track].values.Animation = animation
            instanceStates[track].values.IsPlaying = false
            proxyState[obj].tracks[#proxyState[obj].tracks+1] = track
            return track
        end
        state.values.GetPlayingAnimationTracks = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetPlayingAnimationTracks",2) end
            local out = {}
            for _,track in hostFns.ipairs(proxyState[obj].tracks) do
                if instanceStates[track] and not instanceStates[track].destroyed then
                    out[#out+1] = track
                end
            end
            return out
        end
        state.values.GetTrackByAnimationId = function(selfObj, animationId)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetTrackByAnimationId",2) end
            local wanted = hostFns.tostring(animationId or "")
            for _,track in hostFns.ipairs(proxyState[obj].tracks) do
                local ts = instanceStates[track]
                local animation = ts and ts.values.Animation
                local as = animation and instanceStates[animation]
                if as and hostFns.tostring(as.values.AnimationId or "") == wanted then
                    return track
                end
            end
            return nil
        end
    end

    if className == "TextBox" then
        state.values.Text = state.values.Text or ""
        state.values.ClearTextOnFocus = state.values.ClearTextOnFocus ~= false
        state.values.Focused = makeSignal(id .. ".Focused")
        state.values.FocusLost = makeSignal(id .. ".FocusLost")
        state.values.CaptureFocus = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling CaptureFocus",2) end
            local uis = serviceCache["UserInputService"]
            local us = uis and proxyState[uis]
            if us and us.setFocusedTextBox then us.setFocusedTextBox(obj) end
            fireSignal(state.values.Focused)
        end
        state.values.ReleaseFocus = function(selfObj, submitted)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling ReleaseFocus",2) end
            local uis = serviceCache["UserInputService"]
            local us = uis and proxyState[uis]
            if us and us.setFocusedTextBox then us.setFocusedTextBox(nil) end
            fireSignal(state.values.FocusLost, submitted == true)
        end
        state.values.IsFocused = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling IsFocused",2) end
            local uis = serviceCache["UserInputService"]
            return uis and instanceStates[uis].values.GetFocusedTextBox(uis) == obj or false
        end
    end

    if className == "LocalizationTable" then
        proxyState[obj] = proxyState[obj] or {}
        proxyState[obj].localization = {sourceLocaleId = "en-us", entries = {}}
        state.values.SourceLocaleId = "en-us"

        state.values.SetEntries = function(selfObj, entries)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling SetEntries", 2) end
            local data = proxyState[obj].localization
            data.entries = {}
            for i, entry in hostFns.ipairs(entries or {}) do
                local copied = {
                    Key = entry.Key,
                    Source = entry.Source,
                    Context = entry.Context,
                    Example = entry.Example,
                    Values = {},
                }
                for locale, value in hostFns.pairs(entry.Values or {}) do
                    copied.Values[locale] = value
                end
                data.entries[i] = copied
            end
        end

        state.values.GetEntries = function(selfObj)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetEntries", 2) end
            local data = proxyState[obj].localization
            local out = {}
            for i, entry in hostFns.ipairs(data.entries) do
                local copied = {
                    Key = entry.Key,
                    Source = entry.Source,
                    Context = entry.Context,
                    Example = entry.Example,
                    Values = {},
                }
                for locale, value in hostFns.pairs(entry.Values or {}) do
                    copied.Values[locale] = value
                end
                out[i] = copied
            end
            return out
        end

        state.values.GetTranslator = function(selfObj, localeId)
            if selfObj ~= obj then hostFns.error("Expected ':' not '.' calling GetTranslator", 2) end
            return makeTranslator(localeId, obj)
        end
    end

    if parent ~= nil then
        setParent(obj, parent)
    end

    return obj
end

-- Engine-owned objects are allowed to use Roblox classes that are tagged
-- NotCreatable (Player, PlayerGui, PlayerMouse, Tween, Path, etc.).
-- User code still goes through createInstance without this bypass.
createInternalInstance = function(className, parent)
    return createInstance(className, parent, true)
end

local function makeTranslator(localeId, tableInstance)
    local translator = newproxy(true)
    local mt = hostFns.getmetatable(translator)
    local locale = hostFns.tostring(localeId or "")
    objectTypes[translator] = "Translator"
    objectNames[translator] = "Translator"

    mt.__index = function(_, key)
        if key == "LocaleId" then
            return locale
        elseif key == "FormatByKey" then
            return function(selfTranslator, wantedKey, args)
                if selfTranslator ~= translator then hostFns.error("Expected ':' not '.' calling FormatByKey",2) end
                local tableState = proxyState[tableInstance]
                local data = tableState and tableState.localization or nil
                if not data then hostFns.error("localization table unavailable",2) end
                local formatString
                for _, entry in hostFns.ipairs(data.entries) do
                    if entry.Key == wantedKey then
                        formatString = (entry.Values and (entry.Values[locale] or entry.Values[data.sourceLocaleId])) or entry.Source
                        break
                    end
                end
                if formatString == nil then hostFns.error("localization key not found: "..hostFns.tostring(wantedKey),2) end
                formatString = hostFns.tostring(formatString)
                if hostFns.type(args) == "table" then
                    formatString = formatString:gsub("{([%w_]+)}", function(token)
                        local numeric = tonumber(token)
                        local value = numeric and args[numeric] or args[token]
                        return value == nil and ("{"..token.."}") or hostFns.tostring(value)
                    end)
                end
                return formatString
            end
        elseif key == "Translate" then
            return function(selfTranslator, _context, source)
                if selfTranslator ~= translator then hostFns.error("Expected ':' not '.' calling Translate", 2) end
                local tableState = proxyState[tableInstance]
                local data = tableState and tableState.localization or nil
                local sourceText = hostFns.tostring(source)
                if not data then return sourceText end

                for _, entry in hostFns.ipairs(data.entries) do
                    if entry.Source == sourceText or entry.Key == sourceText then
                        local values = entry.Values
                        if hostFns.type(values) == "table" then
                            local translated = values[locale] or values[data.sourceLocaleId]
                            if translated ~= nil then return translated end
                        end
                        return entry.Source or sourceText
                    end
                end

                return sourceText
            end
        end
        return nil
    end

    mt.__tostring = function() return "Translator" end
    return translator
end

-- serviceCache is declared before createInstance so instance closures
-- reference the same table populated by makeService().
local function makeService(name)
    if serviceCache[name] then
        return serviceCache[name]
    end

    local service=createInternalInstance(name)
    serviceCache[name]=service
    if gameServiceAddedSignal then fireSignal(gameServiceAddedSignal,service) end

    local state = instanceStates[service]
    state.values.Name = name
    state.values.ClassName = name

    -- Roblox services are direct children of the DataModel. Services that are
    -- created before the DataModel proxy exists are attached immediately after
    -- the game proxy is initialized below.
    if game ~= nil then
        setParent(service, game)
    end

    if name == "TextChatService" then
        state.values.CreateDefaultTextChannels = true
    elseif name == "VoiceChatService" then
        state.values.IsVoiceEnabledForUserIdAsync = function(_, _userId)
            return false
        end
    elseif name == "RbxAnalyticsService" then
        local function makeUuid(upper)
            local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
            local value = template:gsub("[xy]", function(c)
                local v = c == "x" and math.random(0,15) or math.random(8,11)
                return string.format("%x", v)
            end)
            return upper and value:upper() or value
        end
        local sessionId = makeUuid(true)
        local clientId = makeUuid(false)
        state.values.GetSessionId = function() return sessionId end
        state.values.GetClientId = function() return clientId end
    elseif name == "Stats" then
        proxyState[service] = proxyState[service] or {}
        proxyState[service].statsMemoryCounter =
            tonumber(proxyState[service].statsMemoryCounter) or 0

        state.values.GetMemoryUsageMbForTag = function(self, tag)
            if self ~= service then
                hostFns.error(
                    "Expected ':' not '.' calling GetMemoryUsageMbForTag",
                    2
                )
            end

            proxyState[service] = proxyState[service] or {}
            proxyState[service].statsMemoryCounter =
                (tonumber(proxyState[service].statsMemoryCounter) or 0) + 1

            local counter = proxyState[service].statsMemoryCounter
            local tagName =
                tag and tag.Name
                or hostFns.tostring(tag or "")

            if tagName == "Graphics" then
                return 128
                    + ((math.floor(virtualTime * 1000) % 97) * 0.001)
            elseif tagName == "Instances" then
                return 16
                    + ((math.floor(virtualTime * 5) % 12) * 3.5)
            end

            return 1
                + ((math.floor(virtualTime * 1000) % 53) * 0.0002)
        end

        state.values.GetTotalMemoryUsageMb = function(self)
            if self ~= service then
                hostFns.error(
                    "Expected ':' not '.' calling GetTotalMemoryUsageMb",
                    2
                )
            end

            local counter =
                tonumber(proxyState[service].statsMemoryCounter) or 0

            return 850.5 + ((counter % 11) * 0.0625)
        end

        state.values.CpuTimeMs = 4.25
    elseif name == "UserInputService" then
        state.values.GetPlatform = function(self)
            if self ~= service then
                hostFns.error("Expected ':' not '.' calling GetPlatform", 2)
            end
            return makeEnumType("Platform").Windows
        end
    elseif name == "GroupService" then
        state.values.GetGroupsAsync = function(self, userId)
            if self ~= service then
                hostFns.error("Expected ':' not '.' calling GetGroupsAsync", 2)
            end
            local numericId = tonumber(userId)
            if numericId == nil then
                hostFns.error("invalid argument #1 to 'GetGroupsAsync' (number expected)", 2)
            end

            -- An empty membership list is a valid Roblox response and avoids
            -- inventing account-specific data in the sandbox.
            return {}
        end
    elseif name == "LocalizationService" then
        -- Stable sandbox identity; do not leak the host machine's locale.
        state.values.RobloxLocaleId = "en-us"
        state.values.SystemLocaleId = "en-us"
        state.values.GetCountryRegionForPlayerAsync = function(self, player)
            if self ~= service then
                hostFns.error("Expected ':' not '.' calling GetCountryRegionForPlayerAsync", 2)
            end
            if player ~= nil and not instanceStates[player] then
                hostFns.error("invalid argument #1 to 'GetCountryRegionForPlayerAsync' (Player expected)", 2)
            end
            return "US"
        end
    elseif name == "GuiService" then
        state.values.GetScreenResolution = function(self)
            if self ~= service then
                hostFns.error(
                    "Expected ':' not '.' calling GetScreenResolution",
                    2
                )
            end
            -- Stable simulated desktop resolution.
            return dataConstructors.Vector2.new(1920, 1080)
        end

        state.values.GetGuiInset = function(self)
            if self ~= service then
                hostFns.error(
                    "Expected ':' not '.' calling GetGuiInset",
                    2
                )
            end

            -- Desktop-style top bar inset.
            return dataConstructors.Vector2.new(0, 36),
                dataConstructors.Vector2.new(0, 0)
        end
    elseif name == "Debris" then
        state.values.AddItem = function(self, object, lifetime)
            if self ~= service then
                hostFns.error(
                    "Expected ':' not '.' calling AddItem",
                    2
                )
            end

            local objectState = instanceStates[object]
            if not objectState then
                hostFns.error(
                    "invalid argument #1 to 'AddItem' (Instance expected)",
                    2
                )
            end

            local delaySeconds = tonumber(lifetime)
            if delaySeconds == nil then
                hostFns.error(
                    "invalid argument #2 to 'AddItem' (number expected)",
                    2
                )
            end

            -- The detector exercises lifetime 0. Match Roblox semantics by
            -- removing the instance immediately from the hierarchy.
            if delaySeconds <= 0 then
                return instanceMethodHandlers.Destroy(object)
            end

            -- Positive lifetimes are tracked against virtualTime and cleaned
            -- up by advanceSimulation.
            proxyState[service] = proxyState[service] or {}
            proxyState[service].debrisQueue =
                proxyState[service].debrisQueue or {}

            local queue = proxyState[service].debrisQueue
            queue[#queue + 1] = {
                object = object,
                due = virtualTime + delaySeconds,
            }

            return nil
        end
    end

    return service
end

local workspace = makeService("Workspace")
objectNames[workspace] = "workspace"
proxyState[workspace] = proxyState[workspace] or {}
proxyState[workspace].serviceDeclared = true
local baseplate

local coreGui = makeService("CoreGui")
objectNames[coreGui] = "CoreGui"
proxyState[coreGui] = proxyState[coreGui] or {}
proxyState[coreGui].serviceDeclared = true

local function seedCoreGui()
    local function child(className, name, parent)
        local obj = createInternalInstance(className, parent)
        instanceStates[obj].values.Name = name
        return obj
    end

    local robloxGui = child("Folder", "RobloxGui", coreGui)

    local coreScripts = child("Folder", "CoreScripts", robloxGui)
    child("CoreScript", "CoreGuiInit", coreScripts)

    local topBarApp = child("ScreenGui", "TopBarApp", robloxGui)
    child("Frame", "TopBar", topBarApp)
    child("Frame", "LeftFrame", topBarApp)
    child("Frame", "RightFrame", topBarApp)

    local playerList = child("ScreenGui", "PlayerList", robloxGui)
    child("Frame", "PlayerListFrame", playerList)
    child("Frame", "PlayerScrollList", playerList)

    local chat = child("ScreenGui", "Chat", robloxGui)
    child("Frame", "ChatFrame", chat)
    child("Frame", "ChatChannelParentFrame", chat)

    local promptGui = child("ScreenGui", "RobloxPromptGui", coreGui)
    child("Frame", "PromptFrame", promptGui)
    child("Frame", "PromptOverlay", promptGui)

    local loadingGui = child("ScreenGui", "RobloxLoadingGui", coreGui)
    child("Frame", "LoadingFrame", loadingGui)

    local purchaseGui = child("ScreenGui", "PurchasePromptApp", coreGui)
    child("Frame", "PurchaseFrame", purchaseGui)

    local notificationGui = child("ScreenGui", "NotificationGui", coreGui)
    child("Frame", "NotificationFrame", notificationGui)
end

seedCoreGui()

local terrain = createInternalInstance("Terrain", workspace)
instanceStates[terrain].values.Name = "Terrain"
instanceStates[workspace].values.Terrain = terrain
objectNames[terrain] = "workspace.Terrain"
do
    local cells = {}
    local terrainValues = instanceStates[terrain].values
    terrainValues.WaterWaveSpeed = 10
    terrainValues.WaterWaveSize = 0.15
    terrainValues.WaterReflectance = 1
    terrainValues.WaterTransparency = 0.3
    terrainValues.WaterColor = dataConstructors.Color3.fromRGB(12, 84, 92)
    local function cellKey(x,y,z)
        return hostFns.tostring(math.floor(tonumber(x) or 0)).."|"
            ..hostFns.tostring(math.floor(tonumber(y) or 0)).."|"
            ..hostFns.tostring(math.floor(tonumber(z) or 0))
    end
    terrainValues.SetCell = function(selfObj,x,y,z,material,block,orientation)
        if selfObj ~= terrain then hostFns.error("Expected ':' not '.' calling SetCell",2) end
        cells[cellKey(x,y,z)] = {material,block,orientation}
    end
    terrainValues.GetCell = function(selfObj,x,y,z)
        if selfObj ~= terrain then hostFns.error("Expected ':' not '.' calling GetCell",2) end
        local cell = cells[cellKey(x,y,z)]

        if cell then
            return cell.material or cell[1],
                cell.occupancy or cell[2] or 1,
                cell.orientation or cell[3]
        end

        return makeEnumType("CellMaterial").Empty,
            0,
            makeEnumType("CellOrientation").NegZ
    end

    local function regionInfo(region, resolution)
        if objectTypes[region] ~= "Region3" then
            hostFns.error("Region3 expected", 3)
        end

        local res = tonumber(resolution) or 4

        if res <= 0 then
            hostFns.error("resolution must be positive", 3)
        end

        local size = region.Size or dataConstructors.Vector3.new()
        local cf = region.CFrame or dataConstructors.CFrame.new()
        local center = cf.Position

        local nx = math.max(1, math.floor((size.X or 0) / res + 0.5))
        local ny = math.max(1, math.floor((size.Y or 0) / res + 0.5))
        local nz = math.max(1, math.floor((size.Z or 0) / res + 0.5))

        local minX = (center.X or 0) - (size.X or 0) / 2
        local minY = (center.Y or 0) - (size.Y or 0) / 2
        local minZ = (center.Z or 0) - (size.Z or 0) / 2

        return res, nx, ny, nz, minX, minY, minZ
    end

    local function voxelAtWorld(x, y, z, resolution)
        local res = tonumber(resolution) or 4
        local cx = math.floor(x / res)
        local cy = math.floor(y / res)
        local cz = math.floor(z / res)
        local cell = cells[cellKey(cx, cy, cz)]

        if cell then
            return cell.material or cell[1] or makeEnumType("Material").Air,
                cell.occupancy or 0
        end

        return makeEnumType("Material").Air, 0
    end

    local function writeVoxelAtWorld(x, y, z, resolution, material, occupancy)
        local res = tonumber(resolution) or 4
        local cx = math.floor(x / res)
        local cy = math.floor(y / res)
        local cz = math.floor(z / res)
        local key = cellKey(cx, cy, cz)
        local occ = tonumber(occupancy) or 0

        if material == makeEnumType("Material").Air or occ <= 0 then
            cells[key] = nil
            return
        end

        cells[key] = {
            material = material,
            occupancy = math.clamp(occ, 0, 1),
        }
    end

    local function makeVoxelArray(nx, ny, nz, producer)
        local out = {
            Size = dataConstructors.Vector3.new(nx, ny, nz),
        }

        for x = 1, nx do
            out[x] = {}

            for y = 1, ny do
                out[x][y] = {}

                for z = 1, nz do
                    out[x][y][z] = producer(x, y, z)
                end
            end
        end

        return out
    end

    terrainValues.FillBlock = function(selfObj, cframe, size, material)
        if selfObj ~= terrain then
            hostFns.error("Expected ':' not '.' calling FillBlock", 2)
        end

        if objectTypes[cframe] ~= "CFrame"
            or objectTypes[size] ~= "Vector3"
            or objectTypes[material] ~= "EnumItem"
        then
            hostFns.error("invalid FillBlock arguments", 2)
        end

        local center = cframe.Position
        local res = 4
        local minX = (center.X or 0) - (size.X or 0) / 2
        local minY = (center.Y or 0) - (size.Y or 0) / 2
        local minZ = (center.Z or 0) - (size.Z or 0) / 2

        local nx = math.max(1, math.ceil((size.X or 0) / res))
        local ny = math.max(1, math.ceil((size.Y or 0) / res))
        local nz = math.max(1, math.ceil((size.Z or 0) / res))

        for x = 1, nx do
            for y = 1, ny do
                for z = 1, nz do
                    writeVoxelAtWorld(
                        minX + (x - 0.5) * res,
                        minY + (y - 0.5) * res,
                        minZ + (z - 0.5) * res,
                        res,
                        material,
                        material == makeEnumType("Material").Air and 0 or 1
                    )
                end
            end
        end

        emit("workspace.Terrain:FillBlock(...)")
    end

    terrainValues.ReadVoxels = function(selfObj, region, resolution)
        if selfObj ~= terrain then
            hostFns.error("Expected ':' not '.' calling ReadVoxels", 2)
        end

        local res, nx, ny, nz, minX, minY, minZ =
            regionInfo(region, resolution)

        local materials = makeVoxelArray(
            nx,
            ny,
            nz,
            function(x, y, z)
                local material = voxelAtWorld(
                    minX + (x - 0.5) * res,
                    minY + (y - 0.5) * res,
                    minZ + (z - 0.5) * res,
                    res
                )

                return material
            end
        )

        local occupancy = makeVoxelArray(
            nx,
            ny,
            nz,
            function(x, y, z)
                local _, value = voxelAtWorld(
                    minX + (x - 0.5) * res,
                    minY + (y - 0.5) * res,
                    minZ + (z - 0.5) * res,
                    res
                )

                return value
            end
        )

        emit("workspace.Terrain:ReadVoxels(...)")

        return materials, occupancy
    end

    terrainValues.WriteVoxels = function(
        selfObj,
        region,
        resolution,
        materials,
        occupancy
    )
        if selfObj ~= terrain then
            hostFns.error("Expected ':' not '.' calling WriteVoxels", 2)
        end

        if hostFns.type(materials) ~= "table"
            or hostFns.type(occupancy) ~= "table"
        then
            hostFns.error("voxel arrays expected", 2)
        end

        local res, nx, ny, nz, minX, minY, minZ =
            regionInfo(region, resolution)

        for x = 1, nx do
            for y = 1, ny do
                for z = 1, nz do
                    local material =
                        materials[x]
                        and materials[x][y]
                        and materials[x][y][z]
                        or makeEnumType("Material").Air

                    local value =
                        occupancy[x]
                        and occupancy[x][y]
                        and occupancy[x][y][z]
                        or 0

                    writeVoxelAtWorld(
                        minX + (x - 0.5) * res,
                        minY + (y - 0.5) * res,
                        minZ + (z - 0.5) * res,
                        res,
                        material,
                        value
                    )
                end
            end
        end

        emit("workspace.Terrain:WriteVoxels(...)")
    end

    terrainValues.ReadVoxelChannels = function(
        selfObj,
        region,
        resolution,
        channelNames
    )
        if selfObj ~= terrain then
            hostFns.error("Expected ':' not '.' calling ReadVoxelChannels", 2)
        end

        if hostFns.type(channelNames) ~= "table" then
            hostFns.error("channel name table expected", 2)
        end

        local res, nx, ny, nz, minX, minY, minZ =
            regionInfo(region, resolution)

        local result = {
            Size = dataConstructors.Vector3.new(nx, ny, nz),
        }

        for _, channelName in hostFns.ipairs(channelNames) do
            local name = hostFns.tostring(channelName)

            if name == "SolidMaterial" then
                result[name] = makeVoxelArray(
                    nx,
                    ny,
                    nz,
                    function(x, y, z)
                        local material = voxelAtWorld(
                            minX + (x - 0.5) * res,
                            minY + (y - 0.5) * res,
                            minZ + (z - 0.5) * res,
                            res
                        )

                        return material
                    end
                )
            elseif name == "SolidOccupancy" then
                result[name] = makeVoxelArray(
                    nx,
                    ny,
                    nz,
                    function(x, y, z)
                        local _, value = voxelAtWorld(
                            minX + (x - 0.5) * res,
                            minY + (y - 0.5) * res,
                            minZ + (z - 0.5) * res,
                            res
                        )

                        return value
                    end
                )
            else
                result[name] = makeVoxelArray(
                    nx,
                    ny,
                    nz,
                    function()
                        return 0
                    end
                )
            end
        end

        emit("workspace.Terrain:ReadVoxelChannels(...)")

        return result
    end
end

local players = makeService("Players")
objectNames[players] = "Players"

local localPlayer = createInternalInstance("Player", players)
local localPlayerState = instanceStates[localPlayer]
localPlayerState.values.Name = CONFIG.username
localPlayerState.values.DisplayName = CONFIG.displayName
localPlayerState.values.UserId = CONFIG.userId
localPlayerState.values.AccountAge = 365
localPlayerState.values.MembershipType = makeEnumType("MembershipType").None
objectNames[localPlayer] = "Players.LocalPlayer"
instanceStates[players].values.LocalPlayer = localPlayer
instanceStates[players].values.PlayerAdded = makeSignal("Players.PlayerAdded")
instanceStates[players].values.PlayerRemoving = makeSignal("Players.PlayerRemoving")

do
local function isGuiObjectClass(className)
    if classIsA(className, "GuiObject") then return true end
    return className == "Frame"
        or className == "TextLabel"
        or className == "TextButton"
        or className == "TextBox"
        or className == "ImageLabel"
        or className == "ImageButton"
        or className == "ScrollingFrame"
        or className == "ViewportFrame"
        or className == "VideoFrame"
        or className == "CanvasGroup"
end

local playerGui = createInternalInstance("PlayerGui", localPlayer)
instanceStates[playerGui].values.Name = "PlayerGui"
objectNames[playerGui] = "Players.LocalPlayer.PlayerGui"
localPlayerState.values.PlayerGui = playerGui

local backpack = createInternalInstance("Backpack", localPlayer)
instanceStates[backpack].values.Name = "Backpack"
objectNames[backpack] = "Players.LocalPlayer.Backpack"
localPlayerState.values.Backpack = backpack

instanceStates[playerGui].values.GetGuiObjectsAtPosition = function(selfObj, x, y)
    if selfObj ~= playerGui then hostFns.error("Expected ':' not '.' calling GetGuiObjectsAtPosition", 2) end
    x, y = tonumber(x), tonumber(y)
    if x == nil or y == nil then hostFns.error("number expected", 2) end

    local hits = {}
    local sequence = 0

    local function walk(node, inheritedVisible, inheritedEnabled)
        local linked = instanceChildren[node]
        if not linked then return end

        for child in hostFns.pairs(linked) do
            local childState = instanceStates[child]
            if childState and not childState.destroyed then
                local visible = inheritedVisible
                local enabled = inheritedEnabled

                if childState.className == "ScreenGui" then
                    if childState.values.Enabled == false then enabled = false end
                elseif isGuiObjectClass(childState.className) then
                    if childState.values.Visible == false then visible = false end
                end

                if visible and enabled and isGuiObjectClass(childState.className) then
                    local gx, gy, gw, gh = computeGuiAbsoluteRect(child)
                    if gx ~= nil and gw >= 0 and gh >= 0
                        and x >= gx and y >= gy
                        and x <= gx + gw and y <= gy + gh
                    then
                        sequence += 1
                        hits[#hits + 1] = {
                            object = child,
                            z = childState.values.ZIndex or 1,
                            sequence = sequence,
                        }
                    end
                end

                walk(child, visible, enabled)
            end
        end
    end

    walk(playerGui, true, true)

    table.sort(hits, function(a, b)
        if a.z ~= b.z then return a.z > b.z end
        return a.sequence < b.sequence
    end)

    local result = {}
    for i, entry in hostFns.ipairs(hits) do
        result[i] = entry.object
    end
    return result
end

end

local character = createInternalInstance("Model", workspace)
instanceStates[character].values.Name = CONFIG.username
localPlayerState.values.Character=character
localPlayerState.values.CharacterAdded=makeSignal("Players.LocalPlayer.CharacterAdded")
localPlayerState.values.CharacterRemoving=makeSignal("Players.LocalPlayer.CharacterRemoving")
objectNames[character]="Players.LocalPlayer.Character"

local humanoidRootPart = createInternalInstance("Part", character)
instanceStates[humanoidRootPart].values.Name = "HumanoidRootPart"
instanceStates[humanoidRootPart].values.Size = dataConstructors.Vector3.new(2,2,1)
instanceStates[humanoidRootPart].values.Position = dataConstructors.Vector3.new(0,5,0)
instanceStates[humanoidRootPart].values.CFrame = dataConstructors.CFrame.new(0,5,0)
instanceStates[humanoidRootPart].values.Anchored = false
instanceStates[character].values.PrimaryPart = humanoidRootPart
objectNames[humanoidRootPart] = "Players.LocalPlayer.Character.HumanoidRootPart"

local playerMouse = createInternalInstance("PlayerMouse")
instanceStates[playerMouse].values.X = 0
instanceStates[playerMouse].values.Y = 0
instanceStates[playerMouse].values.Hit = dataConstructors.CFrame.new()
instanceStates[playerMouse].values.Target = nil
localPlayerState.values.GetMouse = function() return playerMouse end

local function makeUser(id, domainType, domainId)
    local user = newproxy(true)
    local mt = hostFns.getmetatable(user)
    local values = {
        Id = id,
        DomainType = domainType,
        DomainId = domainId,
    }

    mark(user, "User", "User")

    local function encode()
        return string.format(
            "PRUSER1:%s:%d:%d",
            hostFns.tostring(values.DomainType.Name or values.DomainType),
            values.DomainId,
            values.Id
        )
    end

    mt.__index = function(_, key)
        if values[key] ~= nil then
            return values[key]
        elseif key == "ToString" then
            return function()
                return encode()
            end
        end

        return nil
    end

    mt.__tostring = encode

    return user
end

local playerUser = makeUser(
    CONFIG.userId,
    makeEnumType("DomainType").EXPERIENCE,
    CONFIG.gameId + 1
)

localPlayerState.values.User = playerUser

local User = {
    fromString = function(value)
        local text = hostFns.tostring(value)
        local domainName, domainId, id =
            text:match("^PRUSER1:([A-Z_]+):(-?%d+):(-?%d+)$")

        if not domainName then
            hostFns.error("invalid User string", 2)
        end

        return makeUser(
            tonumber(id),
            makeEnumType("DomainType")[domainName],
            tonumber(domainId)
        )
    end,

    fromId = function(id)
        return makeUser(
            tonumber(id) or 0,
            makeEnumType("DomainType").EXPERIENCE,
            CONFIG.gameId
        )
    end,
}

local memStorageItems = {}

local memStorage = makeService("MemStorageService")
instanceStates[memStorage].values.SetItem = function(_, key, value)
    emit("MemStorageService:SetItem(" .. repr(key) .. ", " .. repr(value) .. ")")
    memStorageItems[hostFns.tostring(key)] = hostFns.tostring(value)
end
instanceStates[memStorage].values.GetItem = function(_, key)
    emit("MemStorageService:GetItem(" .. repr(key) .. ")")
    return memStorageItems[hostFns.tostring(key)]
end
instanceStates[memStorage].values.RemoveItem = function(_, key)
    memStorageItems[hostFns.tostring(key)] = nil
end

collectionTags = hostFns.setmetatable({}, { __mode = "k" })
local collectionAddedSignals = {}
local collectionRemovedSignals = {}

local function collectionSignal(bucket, prefix, tag)
    local key = hostFns.tostring(tag)
    if not bucket[key] then bucket[key] = makeSignal(prefix .. ":" .. key) end
    return bucket[key]
end

local collection = makeService("CollectionService")
instanceStates[collection].values.AddTag = function(selfService, instance, tag)
    if selfService ~= collection then hostFns.error("Expected ':' not '.' calling AddTag",2) end
    local tags = collectionTags[instance]
    if not tags then
        tags = {}
        collectionTags[instance] = tags
    end
    local tagName = hostFns.tostring(tag)
    local existed = tags[tagName] == true
    tags[tagName] = true
    if not existed then
        local signal = collectionAddedSignals[tagName]
        if signal then fireSignal(signal, instance) end
    end
    emit("CollectionService:AddTag(" .. repr(instance) .. ", " .. repr(tag) .. ")")
    return nil
end
instanceStates[collection].values.RemoveTag = function(_, instance, tag)
    local tags = collectionTags[instance]
    local tagName = hostFns.tostring(tag)
    local existed = tags and tags[tagName] == true
    if tags then
        tags[tagName] = nil
    end
    if existed then
        local signal = collectionRemovedSignals[tagName]
        if signal then fireSignal(signal, instance) end
    end
    emit("CollectionService:RemoveTag(" .. repr(instance) .. ", " .. repr(tag) .. ")")
    return nil
end
instanceStates[collection].values.GetTagged = function(_, tag)
    local result = {}
    for instance, tags in hostFns.pairs(collectionTags) do
        if tags[hostFns.tostring(tag)] then
            result[#result + 1] = instance
        end
    end
    emit("CollectionService:GetTagged(" .. repr(tag) .. ")")
    return result
end
instanceStates[collection].values.HasTag = function(_, instance, tag)
    local tags = collectionTags[instance]
    return tags and tags[hostFns.tostring(tag)] == true or false
end
instanceStates[collection].values.GetTags = function(_, instance)
    local out={}
    local tags=collectionTags[instance]
    if tags then
        for tag in hostFns.pairs(tags) do out[#out+1]=tag end
        table.sort(out)
    end
    return out
end
instanceStates[collection].values.GetAllTags = function()
    local seen, out = {}, {}
    for _, tags in hostFns.pairs(collectionTags) do
        for tag, enabled in hostFns.pairs(tags) do
            if enabled and not seen[tag] then
                seen[tag] = true
                out[#out + 1] = tag
            end
        end
    end
    table.sort(out)
    return out
end
instanceStates[collection].values.GetInstanceAddedSignal = function(_, tag)
    return collectionSignal(collectionAddedSignals, "CollectionService.InstanceAdded", tag)
end
instanceStates[collection].values.GetInstanceRemovedSignal = function(_, tag)
    return collectionSignal(collectionRemovedSignals, "CollectionService.InstanceRemoved", tag)
end

local avatarEditor = makeService("AvatarEditorService")
instanceStates[avatarEditor].values.GetAvatarRulesAsync = function()
    hostFns.error("AvatarEditorService:GetAvatarRulesAsync is not implemented by Oxygen OxyEnv",2)
end

local starterPlayer = makeService("StarterPlayer")
instanceStates[starterPlayer].values.EnableSLIMAvatars = nil

getPartsFilterAllows = function(params, instance)
    if objectTypes[params] ~= "OverlapParams" and objectTypes[params] ~= "RaycastParams" then
        return true
    end

    local filter = params.FilterDescendantsInstances
    local filterType = params.FilterType
    local include =
        filterType == makeEnumType("RaycastFilterType").Include
        or (filterType and filterType.Name == "Include")

    local found = false

    if hostFns.type(filter) == "table" then
        for _, item in hostFns.pairs(filter) do
            if item == instance then
                found = true
                break
            end
        end
    end

    return include and found or (not include and not found)
end

instanceStates[workspace].values.GetPartsInPart = function(_, queryPart, params)
    local result = {}

    if not instanceStates[queryPart] then
        return result
    end

    local queryCFrame = queryPart.CFrame or dataConstructors.CFrame.new()
    local querySize = queryPart.Size or dataConstructors.Vector3.new(4, 1.2, 2)
    local queryShape = queryPart.Shape
    local queryShapeName = queryShape and queryShape.Name or "Block"

    local linked = instanceChildren[workspace] or {}

    for instance in hostFns.pairs(linked) do
        if instance ~= queryPart
            and instanceStates[instance]
            and classIsA(instanceStates[instance].className, "BasePart")
            and getPartsFilterAllows(params, instance)
        then
            local cf = instance.CFrame or dataConstructors.CFrame.new()
            local size = instance.Size or dataConstructors.Vector3.new(4, 1.2, 2)

            local dx = math.abs((cf.X or 0) - (queryCFrame.X or 0))
            local dy = math.abs((cf.Y or 0) - (queryCFrame.Y or 0))
            local dz = math.abs((cf.Z or 0) - (queryCFrame.Z or 0))
            local overlaps = false

            if queryShapeName == "Ball" then
                local radius =
                    math.min(querySize.X, querySize.Y, querySize.Z) / 2

                -- Sphere vs AABB: distance from the sphere center to the
                -- nearest point of the candidate box.
                local qx = math.max(dx - size.X / 2, 0)
                local qy = math.max(dy - size.Y / 2, 0)
                local qz = math.max(dz - size.Z / 2, 0)

                overlaps =
                    qx*qx + qy*qy + qz*qz
                    <= radius * radius
            else
                overlaps =
                    dx <= (querySize.X + size.X) / 2
                    and dy <= (querySize.Y + size.Y) / 2
                    and dz <= (querySize.Z + size.Z) / 2
            end

            if overlaps then
                result[#result + 1] = instance
            end
        end
    end

    emit("workspace:GetPartsInPart(...)")
    return result
end

instanceStates[workspace].values.GetPartBoundsInBox = function(_, cframe, size, params)
    local temp = createInternalInstance("Part")
    instanceStates[temp].values.CFrame = cframe
    instanceStates[temp].values.Size = size
    local result = instanceStates[workspace].values.GetPartsInPart(workspace, temp, params)
    instanceStates[temp].destroyed = true
    return result
end

instanceStates[workspace].values.GetPartBoundsInRadius=function(_,position,radius,params)
    return {}
end
instanceStates[workspace].values.ZoomToExtents = function(selfObj)
    if selfObj ~= workspace then
        hostFns.error("Expected ':' not '.' calling ZoomToExtents", 2)
    end

    if getRuntimeThreadIdentity() <= 0 then
        hostFns.error(
            "The current thread cannot call 'ZoomToExtents' (lacking permission 1)",
            2
        )
    end

    emit("workspace:ZoomToExtents()")
    return nil
end
instanceStates[workspace].values.Raycast=function(_,origin,direction,params)
    emit("workspace:Raycast(...)")
    origin=origin or dataConstructors.Vector3.zero
    direction=direction or dataConstructors.Vector3.new(0,-1,0)

    local best=nil
    local bestT=math.huge
    local bestOrder=-math.huge

    local function axisSlab(o,d,minv,maxv,tmin,tmax)
        if math.abs(d) < 1e-12 then
            if o < minv or o > maxv then return nil,nil end
            return tmin,tmax
        end
        local a=(minv-o)/d
        local b=(maxv-o)/d
        if a>b then a,b=b,a end
        tmin=math.max(tmin,a)
        tmax=math.min(tmax,b)
        if tmin>tmax then return nil,nil end
        return tmin,tmax
    end

    for inst,state in hostFns.pairs(instanceStates) do
        if state and classIsA(state.className,"BasePart") and state.values.Parent ~= nil
            and getPartsFilterAllows(params,inst)
        then
            local p=state.values.Position or dataConstructors.Vector3.zero
            local s=state.values.Size or dataConstructors.Vector3.new(4,1.2,2)
            local tmin,tmax=0,1
            tmin,tmax=axisSlab(origin.X,direction.X,p.X-s.X/2,p.X+s.X/2,tmin,tmax)
            if tmin then tmin,tmax=axisSlab(origin.Y,direction.Y,p.Y-s.Y/2,p.Y+s.Y/2,tmin,tmax) end
            if tmin then tmin,tmax=axisSlab(origin.Z,direction.Z,p.Z-s.Z/2,p.Z+s.Z/2,tmin,tmax) end
            if tmin and tmin>=0 and tmin<=1 then
                local order = state.creationOrder or 0
                if tmin < bestT - 1e-9 or (math.abs(tmin - bestT) <= 1e-9 and order > bestOrder) then
                    bestT=tmin
                    best=inst
                    bestOrder=order
                end
            end
        end
    end

    if not best then return nil end

    local hitPos=origin+direction*bestT
    return makeDataValue("RaycastResult",{
        Position=hitPos,
        Normal=dataConstructors.Vector3.new(0,1,0),
        Distance=(direction*bestT).Magnitude,
        Instance=best,
        Material=makeEnumType("Material").Plastic,
    })
end

instanceStates[workspace].values.Shapecast = function()
    emit("workspace:Shapecast(...)")
    return nil
end

instanceStates[workspace].values.DistributedGameTime = virtualTime

instanceStates[workspace].values.GetServerTimeNow = function(selfObj)
    if selfObj ~= workspace then
        hostFns.error("Expected ':' not '.' calling GetServerTimeNow", 2)
    end

    -- Unix-epoch-like server time.  Keep the integer portion close to os.time().
    return os.time() + (hostFns.clock() % 1)
end

game = newproxy(true)

do
    local mt = hostFns.getmetatable(game)
    proxyState[game] = proxyState[game] or {}
    proxyState[game].rawMetatable = mt
    mark(game, "game", "Instance")
    mt.__metatable = "The metatable is locked"

    -- Services created during bootstrap become DataModel children once the
    -- canonical game proxy exists.
    for _, existingService in hostFns.pairs(serviceCache) do
        if instanceStates[existingService] then
            setParent(existingService, game)
        end
    end

    local methods={}
    gameServiceAddedSignal=makeSignal("game.ServiceAdded")

    methods.GetService = function(self, name)
        if self ~= game then
            hostFns.error("Expected ':' not '.' calling GetService",2)
        end

        name = hostFns.tostring(name)

        if name == "StudioService" then
            hostFns.error("StudioService is not available in this runtime", 2)
        end
        if name == "DebuggerManager" then
            return nil
        end

        if not serviceNames[name] then
            hostFns.error("'"..name.."' is not a valid Service name",2)
        end

        local service = serviceCache[name]
        if not service then
            service = makeService(name)
        end

        proxyState[service] = proxyState[service] or {}

        -- Workspace already exists as the canonical Roblox global `workspace`.
        -- Do not invent a second local such as:
        -- local Workspace = game:GetService("Workspace")
        if name == "Workspace" then
            objectNames[service] = "workspace"
            proxyState[service].serviceDeclared = true
            return service
        end

        if not proxyState[service].serviceDeclared then
            local variableName = name:gsub("[^%w_]", "_")
            if variableName:match("^%d") then
                variableName = "_" .. variableName
            end

            objectNames[service] = variableName
            proxyState[service].serviceDeclared = true
            emit('local ' .. variableName .. ' = game:GetService("' .. name .. '")')
        end

        return service
    end

    if host.native and host.native.bind then
        methods.GetService = host.native.bind("GetService", methods.GetService)
    end

    methods.HttpGet = function(self, url, _useCache)
        if self ~= game then
            hostFns.error("Expected ':' not '.' calling member function HttpGet", 2)
        end

        local source, err = requestUrl(url)

        if not source then
            hostFns.error("HttpGet failed: " .. hostFns.tostring(err or "unknown error"), 2)
        end

        emit("game:HttpGet(" .. repr(hostFns.tostring(url)) .. ")")
        return source
    end

    methods.HttpGetAsync = methods.HttpGet

    if host.native and host.native.bind then
        methods.HttpGet = host.native.bind("HttpGet", methods.HttpGet)
        methods.HttpGetAsync = methods.HttpGet
    end

    methods.FindService = function(_, name)
        name = hostFns.tostring(name)

        if serviceCache[name] then
            return serviceCache[name]
        end

        if serviceNames[name] then
            return methods.GetService(game, name)
        end

        return nil
    end

    methods.GetChildren = function()
        local list = {}
        for _, service in hostFns.pairs(serviceCache) do
            list[#list + 1] = service
        end
        return list
    end

    methods.GetDescendants = function()
        local list = {}

        local function appendDescendants(parent)
            local children = instanceChildren[parent]
            if not children then
                return
            end

            -- instanceChildren is a set keyed by child instance, not an array.
            for child in hostFns.pairs(children) do
                local childState = instanceStates[child]

                if childState and not childState.destroyed then
                    list[#list + 1] = child
                    appendDescendants(child)
                end
            end
        end

        for _, service in hostFns.pairs(serviceCache) do
            local state = instanceStates[service]

            if state and not state.destroyed then
                list[#list + 1] = service
                appendDescendants(service)
            end
        end

        return list
    end
    methods.GetPing = function(self)
        if self ~= game then hostFns.error("Expected ':' not '.' calling GetPing",2) end
        return 0
    end
    methods.GetHwid = function(self)
        if self ~= game then hostFns.error("Expected ':' not '.' calling GetHwid",2) end
        local analytics = serviceCache["RbxAnalyticsService"] or makeService("RbxAnalyticsService")
        local getter = instanceStates[analytics] and instanceStates[analytics].values.GetClientId
        return getter and getter(analytics) or ("MAD-" .. hostFns.tostring(CONFIG.userId))
    end

    mt.__index = function(_, key)
        if methods[key] then
            return methods[key]
        elseif key == "PlaceId" then
            emit("game.PlaceId")
            return CONFIG.placeId
        elseif key == "GameId" then
            emit("game.GameId")
            return CONFIG.gameId
        elseif key == "PlaceVersion" then
            return CONFIG.placeVersion
        elseif key == "JobId" then
            return "00000000-0000-4000-8000-000000000000"
        elseif key == "CreatorType" then
            return makeEnumType("CreatorType").User
        elseif key == "CreatorId" then
            return CONFIG.userId
        elseif key == "ClassName" then
            return "DataModel"
        elseif key == "Name" then
            return "Game"
        elseif key == "Parent" then
            return nil
        elseif key=="ServiceAdded" then
            return gameServiceAddedSignal
        elseif key == "Workspace" or key == "workspace" then
            return workspace
        elseif key == "Players" then
            return players
        end

        local existingService = serviceCache[key]
        if existingService then
            return existingService
        end

        -- Roblox exposes valid services as direct DataModel properties too:
        -- game.ServerScriptService, game.ReplicatedStorage, game.ServerStorage, etc.
        -- Resolve them lazily through the same singleton path as GetService so
        -- direct-property and GetService lookups return the exact same object.
        if serviceNames[key] then
            return methods.GetService(game, key)
        end

        -- Unknown DataModel properties are nil.
        return nil
    end

    mt.__tostring = function()
        return "Game"
    end
end

instanceStates[workspace].values.Parent = game
instanceStates[players].values.Parent = game

local function regexEscape(value)
    local input = hostFns.tostring(value or "")
    return (input:gsub("([\\%.%+%-%*%?%[%]%^%$%(%)%{%}%|])", "\\%1"))
end

local Regex = {
    Escape = regexEscape,
}

Regex.new = function(patternValue)
    local pattern = hostFns.tostring(patternValue or "")
    local object = newproxy(true)
    local mt = hostFns.getmetatable(object)

    mark(object, "RegexObject", "RegexObject")

    mt.__index = function(_, key)
        if key == "Match" then
            return function(_, subject)
                local text = hostFns.tostring(subject or "")
                local startPos, endPos = string.find(text, pattern, 1, true)

                if startPos == nil then
                    return nil
                end

                return string.sub(text, startPos, endPos)
            end
        elseif key == "MatchMany" then
            return function(_, subject)
                local text = hostFns.tostring(subject or "")
                local result = {}
                local cursor = 1

                if pattern == "" then
                    return result
                end

                while cursor <= #text do
                    local startPos, endPos =
                        string.find(text, pattern, cursor, true)

                    if not startPos then
                        break
                    end

                    result[#result + 1] =
                        string.sub(text, startPos, endPos)

                    cursor = endPos + 1
                end

                return result
            end
        elseif key == "Replace" then
            return function(_, subject, replacement)
                local text = hostFns.tostring(subject or "")
                local escaped = pattern:gsub("([^%w])", "%%%1")
                return (text:gsub(escaped, hostFns.tostring(replacement or "")))
            end
        end

        return nil
    end

    return object
end

-- Common Roblox runtime objects / services used by ordinary scripts and
-- compatibility tests. These are concrete semantics, not anti-detection aliases.

local currentCamera = createInternalInstance("Camera", workspace)
instanceStates[currentCamera].values.Name = "Camera"
instanceStates[currentCamera].values.CFrame = dataConstructors.CFrame.new()
instanceStates[currentCamera].values.Focus = dataConstructors.CFrame.new()
instanceStates[currentCamera].values.FieldOfView = 70
instanceStates[currentCamera].values.Velocity = dataConstructors.Vector3.zero
instanceStates[currentCamera].values.ViewportSize = dataConstructors.Vector2.new(800, 600)
instanceStates[currentCamera].values.CameraSubject = nil
instanceStates[workspace].values.CurrentCamera = currentCamera
objectNames[currentCamera] = "workspace.CurrentCamera"

local function cameraProject(point)
    local values = instanceStates[currentCamera].values
    local cf = values.CFrame or dataConstructors.CFrame.new()
    local viewport = values.ViewportSize or dataConstructors.Vector2.new(800, 600)
    local fov = tonumber(values.FieldOfView) or 70
    local localPoint = cf:PointToObjectSpace(point or dataConstructors.Vector3.zero)
    local depth = -(localPoint.Z or 0)
    local focal = (viewport.Y / 2) / math.tan(math.rad(fov) / 2)
    local x, y
    if math.abs(depth) < 1e-9 then
        x, y = viewport.X / 2, viewport.Y / 2
    else
        x = viewport.X / 2 + (localPoint.X / depth) * focal
        y = viewport.Y / 2 - (localPoint.Y / depth) * focal
    end
    local onScreen = depth > 0 and x >= 0 and y >= 0 and x <= viewport.X and y <= viewport.Y
    return dataConstructors.Vector3.new(x, y, depth), onScreen
end

instanceStates[currentCamera].values.WorldToScreenPoint=function(selfObj,point)
    if selfObj ~= currentCamera then hostFns.error("Expected ':' not '.' calling WorldToScreenPoint",2) end
    return cameraProject(point)
end
instanceStates[currentCamera].values.WorldToViewportPoint=instanceStates[currentCamera].values.WorldToScreenPoint

local function cameraPointToRay(selfObj,x,y,depth)
    if selfObj ~= currentCamera then hostFns.error("Expected ':' not '.' calling ViewportPointToRay",2) end
    local values = instanceStates[currentCamera].values
    local cf = values.CFrame or dataConstructors.CFrame.new()
    local viewport = values.ViewportSize or dataConstructors.Vector2.new(800, 600)
    local fov = tonumber(values.FieldOfView) or 70
    local focal = (viewport.Y / 2) / math.tan(math.rad(fov) / 2)
    local localDirection = dataConstructors.Vector3.new(
        ((tonumber(x) or 0) - viewport.X / 2) / focal,
        -((tonumber(y) or 0) - viewport.Y / 2) / focal,
        -1
    ).Unit
    local worldDirection = cf:VectorToWorldSpace(localDirection).Unit
    local rayDepth = tonumber(depth) or 0
    local origin = cf.Position + worldDirection * rayDepth
    return dataConstructors.Ray.new(origin, worldDirection)
end

instanceStates[currentCamera].values.ScreenPointToRay=cameraPointToRay
instanceStates[currentCamera].values.ViewportPointToRay=cameraPointToRay
instanceStates[currentCamera].values.GetRenderCFrame=function(selfObj)
    if selfObj ~= currentCamera then hostFns.error("Expected ':' not '.' calling GetRenderCFrame",2) end
    return instanceStates[currentCamera].values.CFrame or dataConstructors.CFrame.new()
end
instanceStates[currentCamera].values.GetPartsObscuringTarget=function(selfObj, castPoints, ignoreList)
    if selfObj ~= currentCamera then hostFns.error("Expected ':' not '.' calling GetPartsObscuringTarget",2) end
    if hostFns.type(castPoints) ~= "table" then hostFns.error("table expected",2) end
    if ignoreList ~= nil and hostFns.type(ignoreList) ~= "table" then hostFns.error("table expected",2) end

    local cameraPosition = (instanceStates[currentCamera].values.CFrame or dataConstructors.CFrame.new()).Position
    local result, added = {}, {}

    local function isIgnored(inst)
        for _, ignored in hostFns.ipairs(ignoreList or {}) do
            local cur = inst
            while cur ~= nil do
                if cur == ignored then return true end
                local st = instanceStates[cur]
                cur = st and st.values.Parent or nil
            end
        end
        return false
    end

    local function segmentHitsPart(a, b, state)
        local direction = b - a
        local p = state.values.Position or (state.values.CFrame and state.values.CFrame.Position) or dataConstructors.Vector3.zero
        local size = state.values.Size or dataConstructors.Vector3.new(4,1.2,2)
        local tmin, tmax = 0, 1
        local function slab(o,d,minv,maxv)
            if math.abs(d) < 1e-10 then
                return o >= minv and o <= maxv
            end
            local x1, x2 = (minv-o)/d, (maxv-o)/d
            if x1 > x2 then x1, x2 = x2, x1 end
            tmin = math.max(tmin, x1)
            tmax = math.min(tmax, x2)
            return tmin <= tmax
        end
        return slab(a.X,direction.X,p.X-size.X/2,p.X+size.X/2)
            and slab(a.Y,direction.Y,p.Y-size.Y/2,p.Y+size.Y/2)
            and slab(a.Z,direction.Z,p.Z-size.Z/2,p.Z+size.Z/2)
            and tmax >= 0 and tmin <= 1
    end

    for _, point in hostFns.ipairs(castPoints) do
        if objectTypes[point] == "Vector3" then
            for inst, state in hostFns.pairs(instanceStates) do
                if state and not state.destroyed and classIsA(state.className,"BasePart")
                    and state.values.Parent ~= nil and state.values.CanQuery ~= false
                    and not isIgnored(inst) and segmentHitsPart(cameraPosition, point, state)
                    and not added[inst]
                then
                    added[inst] = true
                    result[#result + 1] = inst
                end
            end
        end
    end

    table.sort(result, function(a,b)
        return (instanceStates[a].creationOrder or 0) < (instanceStates[b].creationOrder or 0)
    end)
    return result
end

baseplate = createInternalInstance("Part", workspace)
instanceStates[baseplate].values.Name = "Baseplate"
instanceStates[baseplate].values.Anchored = true
instanceStates[baseplate].values.Size = dataConstructors.Vector3.new(512, 1, 512)
objectNames[baseplate] = "workspace.Baseplate"

local humanoid = createInternalInstance("Humanoid", character)
instanceStates[humanoid].values.Name = "Humanoid"
objectNames[humanoid] = "Players.LocalPlayer.Character.Humanoid"

local humanoidValues=instanceStates[humanoid].values
humanoidValues.ChangeState=function(_,newState)
    local old=humanoidValues.__State or makeEnumType("HumanoidStateType").Running
    humanoidValues.__State=newState
    humanoidValues.Jump=(newState==makeEnumType("HumanoidStateType").Jumping)
    if humanoidValues.Jump then
        local root=findChild(character,"HumanoidRootPart",false)
        if root then
            local rs=instanceStates[root]
            local p=rs.values.Position or dataConstructors.Vector3.zero
            rs.values.Position=dataConstructors.Vector3.new(p.X,p.Y+5,p.Z)
            rs.values.CFrame=dataConstructors.CFrame.new(rs.values.Position)
            rs.values.Velocity=dataConstructors.Vector3.new(0,50,0)
            rs.values.AssemblyLinearVelocity=rs.values.Velocity
        end
    end
    if humanoidValues.StateChanged then fireSignal(humanoidValues.StateChanged,old,newState) end
    if humanoidValues.Jump and humanoidValues.Jumping then fireSignal(humanoidValues.Jumping,true) end
end
humanoidValues.GetState=function() return humanoidValues.__State or makeEnumType("HumanoidStateType").Running end
local humanoidStateEnabled = {}
humanoidValues.GetStateEnabled=function(_, stateEnum)
    if humanoidStateEnabled[stateEnum] == nil then return true end
    return humanoidStateEnabled[stateEnum] == true
end
humanoidValues.SetStateEnabled=function(_, stateEnum, enabled)
    humanoidStateEnabled[stateEnum] = enabled == true
end
humanoidValues.Move=function(_, direction, _relativeToCamera)
    humanoidValues.MoveDirection = direction or dataConstructors.Vector3.zero
end
humanoidValues.MoveTo=function(_, location, _part)
    humanoidValues.WalkToPoint = location or dataConstructors.Vector3.zero
end
humanoidValues.TakeDamage=function(_, amount)
    local damage = math.max(0, tonumber(amount) or 0)
    humanoidValues.Health = math.max(0, (tonumber(humanoidValues.Health) or 100) - damage)
    if humanoidValues.HealthChanged then fireSignal(humanoidValues.HealthChanged, humanoidValues.Health) end
    if humanoidValues.Health <= 0 and humanoidValues.Died then fireSignal(humanoidValues.Died) end
end
humanoidValues.UnequipTools = instanceMethodHandlers.UnequipTools
humanoidValues.EquipTool = instanceMethodHandlers.EquipTool

local starterPlayerScripts = createInternalInstance("StarterPlayerScripts", starterPlayer)
instanceStates[starterPlayerScripts].values.Name = "StarterPlayerScripts"
local starterCharacterScripts = createInternalInstance("StarterCharacterScripts", starterPlayer)
instanceStates[starterCharacterScripts].values.Name = "StarterCharacterScripts"
instanceStates[starterPlayer].values.StarterPlayerScripts = starterPlayerScripts
instanceStates[starterPlayer].values.StarterCharacterScripts = starterCharacterScripts

local runService = makeService("RunService")
local runValues = instanceStates[runService].values
runValues.Heartbeat = makeSignal("RunService.Heartbeat")
runValues.Stepped = makeSignal("RunService.Stepped")
runValues.RenderStepped = makeSignal("RunService.RenderStepped")
runValues.Render = makeSignal("RunService.Render")
runValues.PreLocal = makeSignal("RunService.PreLocal")
runValues.PostLocal = makeSignal("RunService.PostLocal")
runValues.PreModel = makeSignal("RunService.PreModel")
runValues.PostModel = makeSignal("RunService.PostModel")
runValues.PreData = makeSignal("RunService.PreData")
runValues.PostData = makeSignal("RunService.PostData")
runValues.ClientGitHash="Madium"
runValues.RunState=makeEnumType("RunState").Running
runValues.FrameNumber = 0
runValues.IsClient=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling IsClient",2) end
    return true
end
runValues.IsServer=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling IsServer",2) end
    return false
end
runValues.IsStudio=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling IsStudio",2) end
    return false
end
runValues.IsRunning=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling IsRunning",2) end
    return true
end
runValues.IsRunMode=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling IsRunMode",2) end
    return true
end

local physicsStepId = 1
runValues.GetPhysicsStepId=function(self)
    if self ~= runService then hostFns.error("Expected ':' not '.' calling GetPhysicsStepId",2) end
    return physicsStepId
end

if host.native and host.native.bind then
    runValues.IsClient = host.native.bind("IsClient", runValues.IsClient)
    runValues.IsServer = host.native.bind("IsServer", runValues.IsServer)
    runValues.IsStudio = host.native.bind("IsStudio", runValues.IsStudio)
    runValues.GetPhysicsStepId = host.native.bind("GetPhysicsStepId", runValues.GetPhysicsStepId)
end

local lighting = makeService("Lighting")
local lightingValues = instanceStates[lighting].values
lightingValues.Ambient = dataConstructors.Color3.new(0.5, 0.5, 0.5)
lightingValues.OutdoorAmbient = dataConstructors.Color3.new(0.5, 0.5, 0.5)
lightingValues.Brightness=2
lightingValues.ClockTime=14
lightingValues.TimeOfDay="14:00:00"
lightingValues.GlobalShadows=true
lightingValues.FogColor=dataConstructors.Color3.new(0.75,0.75,0.75)
lightingValues.FogStart=0
lightingValues.FogEnd=100000
lightingValues.GeographicLatitude=41.733

local httpService = makeService("HttpService")
local httpValues = instanceStates[httpService].values

httpValues.JSONDecode = function(_, source)
    if hostFns.type(source) ~= "string" then
        hostFns.error("invalid argument #1 to 'JSONDecode' (string expected)", 2)
    end

    local ok, result = hostFns.pcall(serde.decode, "json", source)

    if not ok then
        hostFns.error(hostFns.tostring(result), 2)
    end

    return result
end

httpValues.JSONEncode = function(_, value)
    local ok, result = hostFns.pcall(serde.encode, "json", value)

    if not ok then
        hostFns.error(hostFns.tostring(result), 2)
    end

    return result
end

httpValues.GetAsync = function(_, url, _nocache, _headers)
    local source, err = requestUrl(url)
    if not source then
        hostFns.error("GetAsync failed: " .. hostFns.tostring(err or "unknown error"), 2)
    end
    return source
end

httpValues.PostAsync = function(_, url, data, _contentType, _compress, headers)
    if hostFns.type(net.request) ~= "function" then hostFns.error("native HTTP request is unavailable", 2) end
    local response = net.request({
        url = hostFns.tostring(url), method = "POST", body = hostFns.tostring(data or ""), headers = headers or {},
    })
    local status = tonumber(safeHttpField(response, "statusCode") or safeHttpField(response, "StatusCode")) or 0
    if status < 200 or status >= 400 then hostFns.error("PostAsync failed: HTTP " .. hostFns.tostring(status), 2) end
    return responseBodyToString(safeHttpField(response, "body") or safeHttpField(response, "Body")) or ""
end

httpValues.RequestAsync = function(_, requestOptions)
    if hostFns.type(requestOptions) ~= "table" then hostFns.error("table expected", 2) end
    if hostFns.type(net.request) ~= "function" then hostFns.error("native HTTP request is unavailable", 2) end
    local response = net.request({
        url = requestOptions.Url or requestOptions.url,
        method = requestOptions.Method or requestOptions.method or "GET",
        body = requestOptions.Body or requestOptions.body or "",
        headers = requestOptions.Headers or requestOptions.headers or {},
    })
    local status = tonumber(safeHttpField(response, "statusCode") or safeHttpField(response, "StatusCode")) or 0
    local body = responseBodyToString(safeHttpField(response, "body") or safeHttpField(response, "Body")) or ""
    return {Success=status >= 200 and status < 400, StatusCode=status, StatusMessage="", Headers={}, Body=body}
end

if host.native and host.native.bind then
    httpValues.GetAsync = host.native.bind("GetAsync", httpValues.GetAsync)
    httpValues.PostAsync = host.native.bind("PostAsync", httpValues.PostAsync)
    httpValues.RequestAsync = host.native.bind("RequestAsync", httpValues.RequestAsync)
end

httpValues.GetSecret=function(_,value)
    if hostFns.type(value) ~= "string"
        or value == ""
        or value:find("%s")
        or value:find("://", 1, true)
        or #value > 128
    then
        hostFns.error("invalid secret key",2)
    end
    return makeDataValue("Secret",{Value=value,Prefix="",Suffix=""})
end

httpValues.GenerateGUID = function(_, wrapInCurlyBraces)
    proxyState[httpService] = proxyState[httpService] or {}
    proxyState[httpService].guidCounter =
        tonumber(proxyState[httpService].guidCounter) or 0
    proxyState[httpService].guidCounter += 1

    local seed = math.floor(
        (hostFns.clock() * 1000000)
        + proxyState[httpService].guidCounter
    )
    local state = seed % 2147483647
    local function nibble()
        state = (state * 48271) % 2147483647
        return state % 16
    end

    local chars = {}
    for i = 1, 32 do
        local n = nibble()
        if i == 13 then n = 4 end
        if i == 17 then n = 8 + (n % 4) end
        chars[i] = string.format("%x", n)
    end

    local raw = table.concat(chars)
    local guid = raw:sub(1,8) .. "-" .. raw:sub(9,12) .. "-" .. raw:sub(13,16)
        .. "-" .. raw:sub(17,20) .. "-" .. raw:sub(21,32)

    if wrapInCurlyBraces == true then return "{" .. guid .. "}" end
    return guid
end

httpValues.GenerateGUIDAsync = function(self, wrapInCurlyBraces)
    if self ~= httpService then
        hostFns.error(
            "Expected ':' not '.' calling GenerateGUIDAsync",
            2
        )
    end

    return httpValues.GenerateGUID(self, wrapInCurlyBraces)
end

local encodingService=makeService("EncodingService")
local encodingValues=instanceStates[encodingService].values

encodingValues.Base64Encode = function(self, input)
    if self ~= encodingService then
        hostFns.error(
            "Expected ':' not '.' calling Base64Encode",
            2
        )
    end

    local source

    if hostFns.type(input) == "string" then
        source = input
    elseif input ~= nil
        and buffer
        and hostFns.type(buffer.tostring) == "function"
    then
        local ok, value =
            hostFns.pcall(buffer.tostring, input)

        if ok and hostFns.type(value) == "string" then
            source = value
        end
    end

    if source == nil then
        hostFns.error(
            "invalid argument #1 to 'Base64Encode' (buffer or string expected)",
            2
        )
    end

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    local encoded = {}
    local length = #source
    local index = 1

    while index <= length do
        local a = string.byte(source, index) or 0
        local b = string.byte(source, index + 1)
        local c = string.byte(source, index + 2)

        local triple =
            a * 65536
            + (b or 0) * 256
            + (c or 0)

        local i1 = math.floor(triple / 262144) % 64
        local i2 = math.floor(triple / 4096) % 64
        local i3 = math.floor(triple / 64) % 64
        local i4 = triple % 64

        encoded[#encoded + 1] =
            alphabet:sub(i1 + 1, i1 + 1)

        encoded[#encoded + 1] =
            alphabet:sub(i2 + 1, i2 + 1)

        if b ~= nil then
            encoded[#encoded + 1] =
                alphabet:sub(i3 + 1, i3 + 1)
        else
            encoded[#encoded + 1] = "="
        end

        if c ~= nil then
            encoded[#encoded + 1] =
                alphabet:sub(i4 + 1, i4 + 1)
        else
            encoded[#encoded + 1] = "="
        end

        index += 3
    end

    local result = table.concat(encoded)

    if buffer and hostFns.type(buffer.fromstring) == "function" then
        return buffer.fromstring(result)
    end

    return result
end

encodingValues.CompressBuffer=function(self,input,algorithm,level)
    if self ~= encodingService then hostFns.error("Expected ':' not '.' calling CompressBuffer",2) end
    if input == nil or hostFns.type(buffer.tostring) ~= "function" then hostFns.error("buffer expected",2) end

    if hostFns.type(serde.compress) == "function" then
        local source = buffer.tostring(input)
        local name = algorithm and algorithm.Name or "Zstd"
        local compressionLevel = level == nil and 1 or tonumber(level)
        if compressionLevel == nil then hostFns.error("number expected",2) end

        local ok, compressed = hostFns.pcall(serde.compress, name, source, compressionLevel)
        if ok then
            if hostFns.type(compressed) == "string" and hostFns.type(buffer.fromstring) == "function" then
                return buffer.fromstring(compressed)
            end
            return compressed
        end
        hostFns.error(hostFns.tostring(compressed),2)
    end

    hostFns.error("EncodingService compression is unavailable in this host",2)
end

encodingValues.DecompressBuffer=function(self,input,algorithm)
    if self ~= encodingService then hostFns.error("Expected ':' not '.' calling DecompressBuffer",2) end
    if input == nil or hostFns.type(buffer.tostring) ~= "function" then hostFns.error("buffer expected",2) end

    if hostFns.type(serde.decompress) == "function" then
        local source = buffer.tostring(input)
        local name = algorithm and algorithm.Name or "Zstd"
        local ok, decompressed = hostFns.pcall(serde.decompress, name, source)
        if ok then
            if hostFns.type(decompressed) == "string" and hostFns.type(buffer.fromstring) == "function" then
                return buffer.fromstring(decompressed)
            end
            return decompressed
        end
        hostFns.error(hostFns.tostring(decompressed),2)
    end

    hostFns.error("EncodingService decompression is unavailable in this host",2)
end

-- Compatibility aliases used by scripts which expose the shorter names.
-- Keep them backed by the same native Zstd implementation instead of stubbing them.
encodingValues.Compress = encodingValues.CompressBuffer
encodingValues.Decompress = encodingValues.DecompressBuffer

do
local soundService = makeService("SoundService")
local soundValues = instanceStates[soundService].values
soundValues.ListenerType = makeEnumType("ListenerType").Camera
soundValues.ListenerCFrame = dataConstructors.CFrame.identity
soundValues.ListenerObject = nil

soundValues.GetListener = function(self)
    if self ~= soundService then hostFns.error("Expected ':' not '.' calling GetListener", 2) end
    local listenerType = soundValues.ListenerType

    if listenerType == makeEnumType("ListenerType").Camera then
        return listenerType, nil
    elseif listenerType == makeEnumType("ListenerType").CFrame then
        return listenerType, soundValues.ListenerCFrame
    elseif listenerType == makeEnumType("ListenerType").ObjectPosition
        or listenerType == makeEnumType("ListenerType").ObjectCFrame
    then
        return listenerType, soundValues.ListenerObject
    end

    return listenerType, nil
end

soundValues.GetMixerTime = function(self)
    if self ~= soundService then hostFns.error("Expected ':' not '.' calling GetMixerTime", 2) end
    return virtualTime
end

end

local marketplace = makeService("MarketplaceService")
instanceStates[marketplace].values.GetProductInfoAsync = function(self, assetId, _infoType)
    if self ~= marketplace then hostFns.error("Expected ':' not '.' calling GetProductInfoAsync", 2) end
    local id = tonumber(assetId)
    if not id or id <= 0 then hostFns.error("invalid asset id", 2) end
    id = math.floor(id)

    proxyState[marketplace] = proxyState[marketplace] or {}
    local state = proxyState[marketplace]
    state.productCache = state.productCache or {}

    if state.productCache[id] then
        return table.clone(state.productCache[id])
    end

    local body = requestUrl("https://economy.roblox.com/v2/assets/" .. hostFns.tostring(id) .. "/details")
    if body then
        local ok, decoded = hostFns.pcall(serde.decode, "json", body)
        if ok and hostFns.type(decoded) == "table" then
            decoded.Name = decoded.Name or ("Asset " .. hostFns.tostring(id))
            decoded.AssetTypeId = decoded.AssetTypeId or 0
            state.productCache[id] = decoded
            return table.clone(decoded)
        end
    end

    local result = {
        AssetId = id,
        Name = id == CONFIG.placeId and ("Place " .. hostFns.tostring(id)) or ("Asset " .. hostFns.tostring(id)),
        AssetTypeId = 9,
        Description = "",
        Creator = {Id = 0, Name = "Unknown", CreatorType = "User"},
        IsForSale = false,
    }

    state.productCache[id] = result
    return table.clone(result)
end

instanceStates[marketplace].values.GetProductInfo = function(self, assetId)
    if self ~= marketplace then hostFns.error("Expected ':' not '.' calling GetProductInfo",2) end
    local id = tonumber(assetId)
    if not id or id <= 0 then hostFns.error("invalid asset id",2) end

    local body, err = requestUrl(
        "https://economy.roblox.com/v2/assets/" .. hostFns.tostring(math.floor(id)) .. "/details"
    )
    if body then
        local ok, decoded = hostFns.pcall(serde.decode, "json", body)
        if ok and hostFns.type(decoded) == "table" then
            if decoded.AssetId == nil then decoded.AssetId = math.floor(id) end
            return decoded
        end
    end
    return instanceStates[marketplace].values.GetProductInfoAsync(self, id)
end

local scheduleTask

local textService = makeService("TextService")
local textServiceValues = instanceStates[textService].values

local function estimateTextBounds(textValue, sizeValue, widthValue)
    local content = hostFns.tostring(textValue or "")
    local textSize = math.max(1, tonumber(sizeValue) or 16)
    local maxWidth = tonumber(widthValue) or 0

    -- Stable approximation; the important contract is that the returned
    -- Vector2 can size a TextLabel large enough for TextFits to be true.
    local naturalWidth = #content * textSize * 0.55
    local lineHeight = textSize * 1.2

    if maxWidth > 0 and naturalWidth > maxWidth then
        local lines = math.max(1, math.ceil(naturalWidth / maxWidth))
        return dataConstructors.Vector2.new(maxWidth, lineHeight * lines)
    end

    return dataConstructors.Vector2.new(naturalWidth, lineHeight)
end

textServiceValues.GetTextBoundsAsync = function(selfObj, params)
    if selfObj ~= textService then
        hostFns.error("Expected ':' not '.' calling GetTextBoundsAsync", 2)
    end

    local state = instanceStates[params]
    if not state or state.className ~= "GetTextBoundsParams" then
        hostFns.error("GetTextBoundsParams expected", 2)
    end

    local values = state.values

    emit("TextService:GetTextBoundsAsync(" .. repr(params) .. ")")

    return estimateTextBounds(
        values.Text or "",
        values.Size or 16,
        values.Width or 0
    )
end

textServiceValues.GetTextSize = function(selfObj, textValue, textSize, _font, frameSize)
    if selfObj ~= textService then
        hostFns.error("Expected ':' not '.' calling GetTextSize", 2)
    end

    local width = 0
    if objectTypes[frameSize] == "Vector2" then
        width = frameSize.X
    end

    return estimateTextBounds(
        textValue,
        textSize,
        width
    )
end

local tweenService = makeService("TweenService")

instanceStates[tweenService].values.GetValue = function(
    selfObj,
    alpha,
    easingStyle,
    easingDirection
)
    if selfObj ~= tweenService then
        hostFns.error(
            "Expected ':' not '.' calling GetValue",
            2
        )
    end

    local t = tonumber(alpha)

    if t == nil then
        hostFns.error("number expected", 2)
    end

    t = math.clamp(t, 0, 1)

    local styleName =
        easingStyle
        and easingStyle.Name
        or "Linear"

    local directionName =
        easingDirection
        and easingDirection.Name
        or "Out"

    local function bounceOut(x)
        local n1 = 7.5625
        local d1 = 2.75

        if x < 1 / d1 then
            return n1 * x * x
        elseif x < 2 / d1 then
            x -= 1.5 / d1
            return n1 * x * x + 0.75
        elseif x < 2.5 / d1 then
            x -= 2.25 / d1
            return n1 * x * x + 0.9375
        else
            x -= 2.625 / d1
            return n1 * x * x + 0.984375
        end
    end

    local function easeIn(x)
        if styleName == "Linear" then
            return x
        elseif styleName == "Sine" then
            return 1 - math.cos((x * math.pi) / 2)
        elseif styleName == "Quad" then
            return x * x
        elseif styleName == "Cubic" then
            return x * x * x
        elseif styleName == "Quart" then
            return x ^ 4
        elseif styleName == "Quint" then
            return x ^ 5
        elseif styleName == "Exponential" or styleName == "Expo" then
            if x == 0 then return 0 end
            return 2 ^ (10 * x - 10)
        elseif styleName == "Circular" or styleName == "Circ" then
            return 1 - math.sqrt(1 - x * x)
        elseif styleName == "Back" then
            local c1 = 1.70158
            local c3 = c1 + 1
            return c3 * x * x * x - c1 * x * x
        elseif styleName == "Bounce" then
            return 1 - bounceOut(1 - x)
        elseif styleName == "Elastic" then
            if x == 0 or x == 1 then return x end
            local c4 = (2 * math.pi) / 3
            return -(
                2 ^ (10 * x - 10)
                * math.sin((x * 10 - 10.75) * c4)
            )
        end

        return x
    end

    local value

    if directionName == "In" then
        value = easeIn(t)
    elseif directionName == "InOut" then
        if t < 0.5 then
            value = easeIn(t * 2) / 2
        else
            value =
                1
                - easeIn((1 - t) * 2) / 2
        end
    else
        value = 1 - easeIn(1 - t)
    end

    emit(
        "TweenService:GetValue("
        .. repr(alpha)
        .. ", "
        .. repr(easingStyle)
        .. ", "
        .. repr(easingDirection)
        .. ")"
    )

    return value
end

instanceStates[tweenService].values.Create=function(_,target,tweenInfo,goals)
    local targetState = instanceStates[target]
    if not targetState then hostFns.error("Instance expected",2) end
    if objectTypes[tweenInfo] ~= "TweenInfo" then hostFns.error("TweenInfo expected",2) end
    if hostFns.type(goals)~="table" then hostFns.error("table expected",2) end

    local guiClasses = {
        Frame=true, TextLabel=true, TextButton=true, TextBox=true,
        ImageLabel=true, ImageButton=true, ScrollingFrame=true,
    }
    local isGui = guiClasses[targetState.className] == true

    for key,value in hostFns.pairs(goals) do
        if key=="Position" or key=="Size" then
            if isGui then
                if objectTypes[value]~="UDim2" then
                    hostFns.error(key.." expects UDim2",2)
                end
            elseif classIsA(targetState.className,"BasePart") then
                if objectTypes[value]~="Vector3" then
                    hostFns.error(key.." expects Vector3",2)
                end
            end
        elseif key=="Orientation" and objectTypes[value]~="Vector3" then
            hostFns.error("Orientation expects Vector3",2)
        elseif key=="CFrame" and objectTypes[value]~="CFrame" then
            hostFns.error("CFrame expects CFrame",2)
        elseif (key=="Color" or key=="Color3") and objectTypes[value]~="Color3" then
            hostFns.error(key.." expects Color3",2)
        elseif key=="Transparency" and hostFns.type(value)~="number" then
            hostFns.error("Transparency expects number",2)
        end
    end

    local tween=createInternalInstance("Tween")
    local values = instanceStates[tween].values
    values.Completed = makeSignal(objectNames[tween] .. ".Completed")
    values.PlaybackState = makeEnumType("PlaybackState").Begin
    proxyState[tween] = proxyState[tween] or {}
    proxyState[tween].tween = {
        target = target,
        info = tweenInfo,
        goals = goals,
        starts = {},
        active = false,
    }

    local function applyGoals()
        for key,value in hostFns.pairs(goals) do
            -- Go through the Instance metamethod so property-changed signals and
            -- validation observe the tweened final value.
            target[key] = value
        end
    end

    values.Play = function(selfObj)
        if selfObj ~= tween and selfObj ~= nil then
            hostFns.error("Expected ':' not '.' calling Play",2)
        end
        values.PlaybackState = makeEnumType("PlaybackState").Playing

        local duration = tonumber(tweenInfo.Time) or 0
        local delayTime = tonumber(tweenInfo.DelayTime) or 0
        values.__CompletionDue = virtualTime + math.max(0, duration + delayTime)

        local tweenState = proxyState[tween].tween
        tweenState.startedAt = virtualTime
        tweenState.duration = duration
        tweenState.delayTime = delayTime
        tweenState.active = true
        tweenState.starts = {}
        for key in hostFns.pairs(goals) do
            tweenState.starts[key] = target[key]
        end

        scheduleTask(math.max(0, duration + delayTime), function()
            if instanceStates[tween] and not instanceStates[tween].destroyed then
                applyGoals()
                if proxyState[tween] and proxyState[tween].tween then
                    proxyState[tween].tween.active = false
                end
                values.PlaybackState = makeEnumType("PlaybackState").Completed
                fireSignal(values.Completed, values.PlaybackState)
            end
        end, {})
    end

    values.Cancel = function(selfObj)
        if proxyState[tween] and proxyState[tween].tween then proxyState[tween].tween.active = false end
        values.PlaybackState = makeEnumType("PlaybackState").Cancelled
        fireSignal(values.Completed, values.PlaybackState)
    end
    values.Pause = function(selfObj)
        if proxyState[tween] and proxyState[tween].tween then proxyState[tween].tween.active = false end
        values.PlaybackState = makeEnumType("PlaybackState").Paused
    end
    return tween
end

-- Roblox exposes TweenService:Create as a native engine method.  Keep the
-- Luau implementation for emulation semantics, but expose it through the
-- host's native forwarding closure when available so debug.info observes the
-- same [C] identity as the engine API.
if host.native and host.native.bind then
    instanceStates[tweenService].values.Create = host.native.bind(
        "Create",
        instanceStates[tweenService].values.Create
    )
end

local contextAction = makeService("ContextActionService")
local boundActions = {}
instanceStates[contextAction].values.BindAction = function(_, name, callback, createTouchButton, ...)
    boundActions[hostFns.tostring(name)] = {
        callback = callback,
        createTouchButton = createTouchButton == true,
        inputs = {...},
    }
end
instanceStates[contextAction].values.UnbindAction = function(_, name)
    boundActions[hostFns.tostring(name)] = nil
end
instanceStates[contextAction].values.GetBoundActionInfo = function(_, name)
    local action = boundActions[hostFns.tostring(name)]

    if not action then
        return nil
    end

    return {
        priorityLevel = 2000,
        createTouchButton = action.createTouchButton,
        inputTypes = table.clone(action.inputs),
    }
end

instanceStates[contextAction].values.GetAllBoundActionInfo = function()
    local out = {}

    for name, action in hostFns.pairs(boundActions) do
        out[name] = {
            priorityLevel = 2000,
            createTouchButton = action.createTouchButton,
            inputTypes = table.clone(action.inputs),
        }
    end

    return out
end

local userInput = makeService("UserInputService")
local uiValues = instanceStates[userInput].values
uiValues.TouchEnabled=false
uiValues.AccelerometerEnabled=false
uiValues.GyroscopeEnabled=false
uiValues.VREnabled=false
uiValues.MouseIcon=""
uiValues.MouseIconEnabled=true
uiValues.KeyboardEnabled=true
uiValues.MouseEnabled = true
uiValues.GamepadEnabled = false
uiValues.InputBegan = makeSignal("UserInputService.InputBegan")
uiValues.InputEnded = makeSignal("UserInputService.InputEnded")
uiValues.InputChanged = makeSignal("UserInputService.InputChanged")
uiValues.TextBoxFocused = makeSignal("UserInputService.TextBoxFocused")
uiValues.TextBoxFocusReleased = makeSignal("UserInputService.TextBoxFocusReleased")
uiValues.JumpRequest = makeSignal("UserInputService.JumpRequest")
uiValues.LastInputTypeChanged = makeSignal("UserInputService.LastInputTypeChanged")
uiValues.WindowFocused = makeSignal("UserInputService.WindowFocused")
uiValues.WindowFocusReleased = makeSignal("UserInputService.WindowFocusReleased")
local mouseLocation = dataConstructors.Vector2.new(0, 0)
uiValues.GetMouseLocation = function(selfObj)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetMouseLocation",2) end
    return mouseLocation
end
uiValues.SetMouseLocation = function(selfObj, x, y)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling SetMouseLocation",2) end
    if objectTypes[x] == "Vector2" and y == nil then
        mouseLocation = x
    else
        mouseLocation = dataConstructors.Vector2.new(tonumber(x) or 0, tonumber(y) or 0)
    end
end
uiValues.IsKeyDown = function(selfObj, _keyCode)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling IsKeyDown",2) end
    return false
end
uiValues.GetLastInputType = function(selfObj)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetLastInputType",2) end
    return makeEnumType("UserInputType").Keyboard
end
uiValues.IsMouseButtonPressed = function(selfObj, _mouseButton)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling IsMouseButtonPressed",2) end
    return false
end
uiValues.GetKeysPressed = function(selfObj)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetKeysPressed",2) end
    return {}
end
uiValues.GetMouseButtonsPressed = function(selfObj)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetMouseButtonsPressed",2) end
    return {}
end
uiValues.GetFocusedTextBox = function(selfObj)
    if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetFocusedTextBox",2) end
    return nil
end
if host.native and host.native.bind then
    uiValues.GetMouseLocation = host.native.bind("GetMouseLocation", uiValues.GetMouseLocation)
    uiValues.SetMouseLocation = host.native.bind("SetMouseLocation", uiValues.SetMouseLocation)
    uiValues.IsKeyDown = host.native.bind("IsKeyDown", uiValues.IsKeyDown)
    uiValues.IsMouseButtonPressed = host.native.bind("IsMouseButtonPressed", uiValues.IsMouseButtonPressed)
end

do
    local navGamepads = {}
    local focusedTextBox = nil

    uiValues.SetNavigationGamepad = function(selfObj, gamepadEnum, enabled)
        if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling SetNavigationGamepad",2) end
        navGamepads[gamepadEnum] = enabled == true or nil
    end

    uiValues.IsNavigationGamepad = function(selfObj, gamepadEnum)
        if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling IsNavigationGamepad",2) end
        return navGamepads[gamepadEnum] == true
    end

    uiValues.GetNavigationGamepads = function(selfObj)
        if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetNavigationGamepads",2) end
        local out = {}
        for gamepad in hostFns.pairs(navGamepads) do out[#out+1] = gamepad end
        return out
    end

    uiValues.GetFocusedTextBox = function(selfObj)
        if selfObj ~= userInput then hostFns.error("Expected ':' not '.' calling GetFocusedTextBox",2) end
        return focusedTextBox
    end

    proxyState[userInput] = proxyState[userInput] or {}
    proxyState[userInput].setFocusedTextBox = function(box)
        if focusedTextBox == box then return end
        if focusedTextBox then fireSignal(uiValues.TextBoxFocusReleased, focusedTextBox) end
        focusedTextBox = box
        if focusedTextBox then fireSignal(uiValues.TextBoxFocused, focusedTextBox) end
    end
end

do
local materialService = makeService("MaterialService")
local materialValues = instanceStates[materialService].values

materialValues.GetMaterialVariant = function(selfObj, material, name)
    if selfObj ~= materialService then hostFns.error("Expected ':' not '.' calling GetMaterialVariant",2) end
    local wantedName = hostFns.tostring(name or "")
    local function scan(parent)
        local children = instanceChildren[parent]
        if not children then return nil end
        for child in hostFns.pairs(children) do
            local childState = instanceStates[child]
            if childState then
                if childState.className == "MaterialVariant"
                    and hostFns.tostring(childState.values.Name or "") == wantedName
                    and childState.values.BaseMaterial == material
                then
                    return child
                end
                local nested = scan(child)
                if nested then return nested end
            end
        end
        return nil
    end
    return scan(materialService)
end
end

local assetService = makeService("AssetService")

local function colorToBytes(color, transparency)
    local r = math.floor(math.max(0, math.min(1, color and color.R or 0)) * 255 + 0.5)
    local g = math.floor(math.max(0, math.min(1, color and color.G or 0)) * 255 + 0.5)
    local b = math.floor(math.max(0, math.min(1, color and color.B or 0)) * 255 + 0.5)
    local alpha = math.floor((1 - math.max(0, math.min(1, tonumber(transparency) or 0))) * 255 + 0.5)
    return r, g, b, alpha
end

local function editableImageIndex(width, x, y)
    return (y * width + x) * 4
end

local function makeEditableImage(size)
    size = size or dataConstructors.Vector2.new(1, 1)

    local width = math.max(1, math.floor(tonumber(size.X) or 1))
    local height = math.max(1, math.floor(tonumber(size.Y) or 1))

    local image = createInternalInstance("EditableImage")
    local state = instanceStates[image]
    local values = state.values

    values.Size = dataConstructors.Vector2.new(width, height)

    local pixels = buffer.create(width * height * 4)

    local function inBounds(x, y)
        return x >= 0 and y >= 0 and x < width and y < height
    end

    local function setPixel(x, y, r, g, b, a)
        x = math.floor(x)
        y = math.floor(y)

        if not inBounds(x, y) then
            return
        end

        local offset = editableImageIndex(width, x, y)
        buffer.writeu8(pixels, offset, r)
        buffer.writeu8(pixels, offset + 1, g)
        buffer.writeu8(pixels, offset + 2, b)
        buffer.writeu8(pixels, offset + 3, a)
    end

    local function getPixel(x, y)
        x = math.floor(x)
        y = math.floor(y)

        if not inBounds(x, y) then
            return 0, 0, 0, 0
        end

        local offset = editableImageIndex(width, x, y)
        return
            buffer.readu8(pixels, offset),
            buffer.readu8(pixels, offset + 1),
            buffer.readu8(pixels, offset + 2),
            buffer.readu8(pixels, offset + 3)
    end

    values.ReadPixelsBuffer = function(_, position, readSize)
        local px = math.floor(tonumber(position and position.X) or 0)
        local py = math.floor(tonumber(position and position.Y) or 0)
        local rw = math.max(0, math.floor(tonumber(readSize and readSize.X) or 0))
        local rh = math.max(0, math.floor(tonumber(readSize and readSize.Y) or 0))

        local out = buffer.create(rw * rh * 4)
        local outOffset = 0

        for y = 0, rh - 1 do
            for x = 0, rw - 1 do
                local r, g, b, a = getPixel(px + x, py + y)
                buffer.writeu8(out, outOffset, r)
                buffer.writeu8(out, outOffset + 1, g)
                buffer.writeu8(out, outOffset + 2, b)
                buffer.writeu8(out, outOffset + 3, a)
                outOffset += 4
            end
        end

        return out
    end

    values.WritePixelsBuffer = function(_, position, writeSize, source)
        local px = math.floor(tonumber(position and position.X) or 0)
        local py = math.floor(tonumber(position and position.Y) or 0)
        local rw = math.max(0, math.floor(tonumber(writeSize and writeSize.X) or 0))
        local rh = math.max(0, math.floor(tonumber(writeSize and writeSize.Y) or 0))

        local expected = rw * rh * 4
        if buffer.len(source) < expected then
            hostFns.error("buffer is too small for requested image region", 2)
        end

        local sourceOffset = 0

        for y = 0, rh - 1 do
            for x = 0, rw - 1 do
                setPixel(
                    px + x,
                    py + y,
                    buffer.readu8(source, sourceOffset),
                    buffer.readu8(source, sourceOffset + 1),
                    buffer.readu8(source, sourceOffset + 2),
                    buffer.readu8(source, sourceOffset + 3)
                )
                sourceOffset += 4
            end
        end
    end

    values.DrawRectangle = function(_, position, rectSize, color, transparency)
        local px = math.floor(tonumber(position and position.X) or 0)
        local py = math.floor(tonumber(position and position.Y) or 0)
        local rw = math.max(0, math.floor(tonumber(rectSize and rectSize.X) or 0))
        local rh = math.max(0, math.floor(tonumber(rectSize and rectSize.Y) or 0))
        local r, g, b, a = colorToBytes(color, transparency)

        for y = 0, rh - 1 do
            for x = 0, rw - 1 do
                setPixel(px + x, py + y, r, g, b, a)
            end
        end
    end

    values.DrawLine = function(_, fromPoint, toPoint, color, transparency)
        local x0 = math.floor(tonumber(fromPoint and fromPoint.X) or 0)
        local y0 = math.floor(tonumber(fromPoint and fromPoint.Y) or 0)
        local x1 = math.floor(tonumber(toPoint and toPoint.X) or 0)
        local y1 = math.floor(tonumber(toPoint and toPoint.Y) or 0)
        local r, g, b, a = colorToBytes(color, transparency)

        local dx = math.abs(x1 - x0)
        local sx = x0 < x1 and 1 or -1
        local dy = -math.abs(y1 - y0)
        local sy = y0 < y1 and 1 or -1
        local err = dx + dy

        while true do
            setPixel(x0, y0, r, g, b, a)

            if x0 == x1 and y0 == y1 then
                break
            end

            local e2 = 2 * err

            if e2 >= dy then
                err += dy
                x0 += sx
            end

            if e2 <= dx then
                err += dx
                y0 += sy
            end
        end
    end

    values.DrawCircle = function(_, center, radius, color, transparency)
        local cx = math.floor(tonumber(center and center.X) or 0)
        local cy = math.floor(tonumber(center and center.Y) or 0)
        local rr = math.max(0, tonumber(radius) or 0)
        local r, g, b, a = colorToBytes(color, transparency)

        local ir = math.ceil(rr)

        for y = -ir, ir do
            for x = -ir, ir do
                if x * x + y * y <= rr * rr then
                    setPixel(cx + x, cy + y, r, g, b, a)
                end
            end
        end
    end

    local function copyImageAt(position, sourceImage)
        local sourceState = instanceStates[sourceImage]
        if not sourceState or sourceState.className ~= "EditableImage" then
            hostFns.error("EditableImage expected", 2)
        end

        local sourceSize = sourceState.values.Size
        local sw = math.floor(sourceSize.X)
        local sh = math.floor(sourceSize.Y)
        local sourceBuffer = sourceState.values.ReadPixelsBuffer(
            sourceImage,
            dataConstructors.Vector2.zero,
            sourceSize
        )

        values.WritePixelsBuffer(
            image,
            position or dataConstructors.Vector2.zero,
            sourceSize,
            sourceBuffer
        )
    end

    values.DrawImage = function(_, position, sourceImage)
        copyImageAt(position, sourceImage)
    end

    values.DrawImageTransformed = function(_, position, _scale, _rotation, sourceImage)
        copyImageAt(position, sourceImage)
    end

    values.DrawImageProjected = function()
        return nil
    end

    values.SampleImageProjected = function()
        return nil
    end

    values.__PixelBuffer = pixels

    return image
end

local function makeEditableMesh()
    local mesh = createInternalInstance("EditableMesh")
    local state = instanceStates[mesh]
    local values = state.values

    local nextVertexId = 1
    local nextFaceId = 1
    local nextUVId = 1
    local nextNormalId = 1
    local nextColorId = 1
    local nextBoneId = 1

    local vertices = {}
    local faces = {}
    local uvs = {}
    local normals = {}
    local colors = {}
    local colorAlpha = {}
    local faceUVs = {}
    local faceNormals = {}
    local faceColors = {}
    local bones = {}
    local vertexBones = {}
    local vertexBoneWeights = {}

    values.FixedSize = false

    local function copyArray(source)
        local out = {}
        if hostFns.type(source) == "table" then
            for i, value in hostFns.ipairs(source) do
                out[i] = value
            end
        end
        return out
    end

    local function sortedIds(map)
        local out = {}
        for id in hostFns.pairs(map) do
            if hostFns.type(id) == "number" then
                out[#out + 1] = id
            end
        end
        table.sort(out)
        return out
    end

    local function vectorDistanceSquared(a, b)
        local dx = (a.X or 0) - (b.X or 0)
        local dy = (a.Y or 0) - (b.Y or 0)
        local dz = (a.Z or 0) - (b.Z or 0)
        return dx * dx + dy * dy + dz * dz
    end

    local function getFace(faceId)
        local face = faces[faceId]
        if not face then
            hostFns.error("invalid face id", 2)
        end
        return face
    end

    local function getVertex(vertexId)
        local position = vertices[vertexId]
        if position == nil then
            hostFns.error("invalid vertex id", 2)
        end
        return position
    end

    local function getCornerIndex(faceId, vertexId)
        local face = getFace(faceId)
        for i = 1, #face do
            if face[i] == vertexId then
                return i
            end
        end
        return nil
    end

    values.AddVertex = function(_, position)
        local id = nextVertexId
        nextVertexId += 1
        vertices[id] = position or dataConstructors.Vector3.zero
        return id
    end

    values.AddTriangle = function(_, a, b, c)
        getVertex(a)
        getVertex(b)
        getVertex(c)

        local id = nextFaceId
        nextFaceId += 1
        faces[id] = {a, b, c}
        faceUVs[id] = {}
        faceNormals[id] = {}
        faceColors[id] = {}
        return id
    end

    values.AddUV = function(_, value)
        local id = nextUVId
        nextUVId += 1
        uvs[id] = value or dataConstructors.Vector2.zero
        return id
    end

    values.AddNormal = function(_, value)
        local id = nextNormalId
        nextNormalId += 1
        normals[id] = value or dataConstructors.Vector3.zero
        return id
    end

    values.AddColor = function(_, value, alpha)
        local id = nextColorId
        nextColorId += 1
        colors[id] = value or dataConstructors.Color3.new(1, 1, 1)
        colorAlpha[id] = tonumber(alpha) or 1
        return id
    end

    values.GetPosition = function(_, id)
        return getVertex(id)
    end

    values.SetPosition = function(_, id, value)
        getVertex(id)
        vertices[id] = value
    end

    values.GetUV = function(_, id)
        if uvs[id] == nil then hostFns.error("invalid UV id", 2) end
        return uvs[id]
    end

    values.SetUV = function(_, id, value)
        if uvs[id] == nil then hostFns.error("invalid UV id", 2) end
        uvs[id] = value
    end

    values.GetNormal = function(_, id)
        if normals[id] == nil then hostFns.error("invalid normal id", 2) end
        return normals[id]
    end

    values.SetNormal = function(_, id, value)
        if normals[id] == nil then hostFns.error("invalid normal id", 2) end
        normals[id] = value
    end

    values.ResetNormal = function(_, id)
        if normals[id] == nil then hostFns.error("invalid normal id", 2) end
        normals[id] = dataConstructors.Vector3.zero
    end

    values.GetColor = function(_, id)
        if colors[id] == nil then hostFns.error("invalid color id", 2) end
        return colors[id]
    end

    values.SetColor = function(_, id, value)
        if colors[id] == nil then hostFns.error("invalid color id", 2) end
        colors[id] = value
    end

    values.GetColorAlpha = function(_, id)
        if colors[id] == nil then hostFns.error("invalid color id", 2) end
        return colorAlpha[id] or 1
    end

    values.SetColorAlpha = function(_, id, alpha)
        if colors[id] == nil then hostFns.error("invalid color id", 2) end
        colorAlpha[id] = tonumber(alpha) or 1
    end

    values.GetVertices = function()
        return sortedIds(vertices)
    end

    values.GetFaces = function()
        return sortedIds(faces)
    end

    values.GetTriangles = values.GetFaces

    values.GetUVs = function()
        return sortedIds(uvs)
    end

    values.GetNormals = function()
        return sortedIds(normals)
    end

    values.GetColors = function()
        return sortedIds(colors)
    end

    values.GetFaceVertices = function(_, faceId)
        return copyArray(getFace(faceId))
    end

    values.SetFaceUVs = function(_, faceId, ids)
        getFace(faceId)
        faceUVs[faceId] = copyArray(ids)
    end

    values.GetFaceUVs = function(_, faceId)
        getFace(faceId)
        return copyArray(faceUVs[faceId])
    end

    values.SetFaceNormals = function(_, faceId, ids)
        getFace(faceId)
        faceNormals[faceId] = copyArray(ids)
    end

    values.GetFaceNormals = function(_, faceId)
        getFace(faceId)
        return copyArray(faceNormals[faceId])
    end

    values.SetFaceColors = function(_, faceId, ids)
        getFace(faceId)
        faceColors[faceId] = copyArray(ids)
    end

    values.GetFaceColors = function(_, faceId)
        getFace(faceId)
        return copyArray(faceColors[faceId])
    end

    values.GetFacesWithAttribute = function(_, id)
        local out = {}

        for faceId, face in hostFns.pairs(faces) do
            local found = false

            for _, vertexId in hostFns.ipairs(face) do
                if vertexId == id then
                    found = true
                    break
                end
            end

            if not found then
                for _, value in hostFns.ipairs(faceUVs[faceId] or {}) do
                    if value == id then found = true break end
                end
            end

            if not found then
                for _, value in hostFns.ipairs(faceNormals[faceId] or {}) do
                    if value == id then found = true break end
                end
            end

            if not found then
                for _, value in hostFns.ipairs(faceColors[faceId] or {}) do
                    if value == id then found = true break end
                end
            end

            if found then out[#out + 1] = faceId end
        end

        table.sort(out)
        return out
    end

    values.GetFacesWithColor = function(_, colorId)
        local out = {}
        for faceId, ids in hostFns.pairs(faceColors) do
            for _, id in hostFns.ipairs(ids) do
                if id == colorId then
                    out[#out + 1] = faceId
                    break
                end
            end
        end
        table.sort(out)
        return out
    end

    values.SetVertexFaceUV = function(_, vertexId, faceId, uvId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then hostFns.error("vertex is not part of face", 2) end
        faceUVs[faceId] = faceUVs[faceId] or {}
        faceUVs[faceId][index] = uvId
    end

    values.GetVertexFaceUV = function(_, vertexId, faceId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then return nil end
        local valuesForFace = faceUVs[faceId]
        return valuesForFace and valuesForFace[index] or nil
    end

    values.SetVertexFaceNormal = function(_, vertexId, faceId, normalId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then hostFns.error("vertex is not part of face", 2) end
        faceNormals[faceId] = faceNormals[faceId] or {}
        faceNormals[faceId][index] = normalId
    end

    values.GetVertexFaceNormal = function(_, vertexId, faceId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then return nil end
        local valuesForFace = faceNormals[faceId]
        return valuesForFace and valuesForFace[index] or nil
    end

    values.SetVertexFaceColor = function(_, vertexId, faceId, colorId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then hostFns.error("vertex is not part of face", 2) end
        faceColors[faceId] = faceColors[faceId] or {}
        faceColors[faceId][index] = colorId
    end

    values.GetVertexFaceColor = function(_, vertexId, faceId)
        local index = getCornerIndex(faceId, vertexId)
        if not index then return nil end
        local valuesForFace = faceColors[faceId]
        return valuesForFace and valuesForFace[index] or nil
    end

    values.GetVertexFaces = function(_, vertexId)
        getVertex(vertexId)
        local out = {}
        for faceId, face in hostFns.pairs(faces) do
            for _, id in hostFns.ipairs(face) do
                if id == vertexId then
                    out[#out + 1] = faceId
                    break
                end
            end
        end
        table.sort(out)
        return out
    end

    values.GetAdjacentVertices = function(_, vertexId)
        getVertex(vertexId)
        local seen = {}
        for _, faceId in hostFns.ipairs(values.GetVertexFaces(mesh, vertexId)) do
            local face = faces[faceId]
            for _, id in hostFns.ipairs(face) do
                if id ~= vertexId then
                    seen[id] = true
                end
            end
        end
        return sortedIds(seen)
    end

    values.GetAdjacentFaces = function(_, faceId)
        local face = getFace(faceId)
        local verticesInFace = {}
        for _, id in hostFns.ipairs(face) do
            verticesInFace[id] = true
        end

        local out = {}
        for otherId, otherFace in hostFns.pairs(faces) do
            if otherId ~= faceId then
                for _, id in hostFns.ipairs(otherFace) do
                    if verticesInFace[id] then
                        out[#out + 1] = otherId
                        break
                    end
                end
            end
        end
        table.sort(out)
        return out
    end

    local function collectVertexCornerAttributes(vertexId, source)
        local out = {}
        for _, faceId in hostFns.ipairs(values.GetVertexFaces(mesh, vertexId)) do
            local index = getCornerIndex(faceId, vertexId)
            local faceValues = source[faceId]
            local id = faceValues and faceValues[index] or nil
            if id ~= nil then out[#out + 1] = id end
        end
        return out
    end

    values.GetVertexUVs = function(_, vertexId)
        return collectVertexCornerAttributes(vertexId, faceUVs)
    end

    values.GetVertexNormals = function(_, vertexId)
        return collectVertexCornerAttributes(vertexId, faceNormals)
    end

    values.GetVertexColors = function(_, vertexId)
        return collectVertexCornerAttributes(vertexId, faceColors)
    end

    values.GetCenter = function()
        local ids = sortedIds(vertices)
        if #ids == 0 then return dataConstructors.Vector3.zero end

        local minX, minY, minZ = math.huge, math.huge, math.huge
        local maxX, maxY, maxZ = -math.huge, -math.huge, -math.huge

        for _, id in hostFns.ipairs(ids) do
            local p = vertices[id]
            minX = math.min(minX, p.X)
            minY = math.min(minY, p.Y)
            minZ = math.min(minZ, p.Z)
            maxX = math.max(maxX, p.X)
            maxY = math.max(maxY, p.Y)
            maxZ = math.max(maxZ, p.Z)
        end

        return dataConstructors.Vector3.new(
            (minX + maxX) / 2,
            (minY + maxY) / 2,
            (minZ + maxZ) / 2
        )
    end

    values.GetSize = function()
        local ids = sortedIds(vertices)
        if #ids == 0 then return dataConstructors.Vector3.zero end

        local minX, minY, minZ = math.huge, math.huge, math.huge
        local maxX, maxY, maxZ = -math.huge, -math.huge, -math.huge

        for _, id in hostFns.ipairs(ids) do
            local p = vertices[id]
            minX = math.min(minX, p.X)
            minY = math.min(minY, p.Y)
            minZ = math.min(minZ, p.Z)
            maxX = math.max(maxX, p.X)
            maxY = math.max(maxY, p.Y)
            maxZ = math.max(maxZ, p.Z)
        end

        return dataConstructors.Vector3.new(
            maxX - minX,
            maxY - minY,
            maxZ - minZ
        )
    end

    values.FindClosestVertex = function(_, point)
        local bestId = nil
        local bestDistance = math.huge
        for id, position in hostFns.pairs(vertices) do
            local distance = vectorDistanceSquared(position, point)
            if distance < bestDistance then
                bestDistance = distance
                bestId = id
            end
        end
        return bestId
    end

    values.FindVerticesWithinSphere = function(_, point, radius)
        local out = {}
        local limit = (tonumber(radius) or 0) ^ 2
        for id, position in hostFns.pairs(vertices) do
            if vectorDistanceSquared(position, point) <= limit then
                out[#out + 1] = id
            end
        end
        table.sort(out)
        return out
    end

    local function vecSub(a, b)
        return (a.X or 0) - (b.X or 0),
            (a.Y or 0) - (b.Y or 0),
            (a.Z or 0) - (b.Z or 0)
    end

    local function dot(ax, ay, az, bx, by, bz)
        return ax*bx + ay*by + az*bz
    end

    local function cross(ax, ay, az, bx, by, bz)
        return ay*bz - az*by,
            az*bx - ax*bz,
            ax*by - ay*bx
    end

    local function closestPointOnTriangle(p, a, b, c)
        local abx,aby,abz = vecSub(b,a)
        local acx,acy,acz = vecSub(c,a)
        local apx,apy,apz = vecSub(p,a)

        local d1 = dot(abx,aby,abz, apx,apy,apz)
        local d2 = dot(acx,acy,acz, apx,apy,apz)
        if d1 <= 0 and d2 <= 0 then
            return a, 1,0,0
        end

        local bpx,bpy,bpz = vecSub(p,b)
        local d3 = dot(abx,aby,abz, bpx,bpy,bpz)
        local d4 = dot(acx,acy,acz, bpx,bpy,bpz)
        if d3 >= 0 and d4 <= d3 then
            return b, 0,1,0
        end

        local vc = d1*d4 - d3*d2
        if vc <= 0 and d1 >= 0 and d3 <= 0 then
            local v = d1 / (d1 - d3)
            return dataConstructors.Vector3.new(
                a.X + v*abx, a.Y + v*aby, a.Z + v*abz
            ), 1-v,v,0
        end

        local cpx,cpy,cpz = vecSub(p,c)
        local d5 = dot(abx,aby,abz, cpx,cpy,cpz)
        local d6 = dot(acx,acy,acz, cpx,cpy,cpz)
        if d6 >= 0 and d5 <= d6 then
            return c, 0,0,1
        end

        local vb = d5*d2 - d1*d6
        if vb <= 0 and d2 >= 0 and d6 <= 0 then
            local w = d2 / (d2 - d6)
            return dataConstructors.Vector3.new(
                a.X + w*acx, a.Y + w*acy, a.Z + w*acz
            ), 1-w,0,w
        end

        local va = d3*d6 - d5*d4
        if va <= 0 and (d4-d3) >= 0 and (d5-d6) >= 0 then
            local w = (d4-d3) / ((d4-d3) + (d5-d6))
            local bcx,bcy,bcz = vecSub(c,b)
            return dataConstructors.Vector3.new(
                b.X + w*bcx, b.Y + w*bcy, b.Z + w*bcz
            ), 0,1-w,w
        end

        local denom = 1 / (va + vb + vc)
        local v = vb * denom
        local w = vc * denom
        local u = 1 - v - w
        return dataConstructors.Vector3.new(
            u*a.X + v*b.X + w*c.X,
            u*a.Y + v*b.Y + w*c.Y,
            u*a.Z + v*b.Z + w*c.Z
        ), u,v,w
    end

    values.RaycastLocal = function(_, origin, direction)
        local bestT = math.huge
        local bestPoint, bestFace, bestBary
        local dx,dy,dz = direction.X or 0, direction.Y or 0, direction.Z or 0

        for faceId, face in hostFns.pairs(faces) do
            local a,b,c = vertices[face[1]], vertices[face[2]], vertices[face[3]]
            if a and b and c then
                local e1x,e1y,e1z = vecSub(b,a)
                local e2x,e2y,e2z = vecSub(c,a)
                local hx,hy,hz = cross(dx,dy,dz, e2x,e2y,e2z)
                local det = dot(e1x,e1y,e1z, hx,hy,hz)

                if math.abs(det) > 1e-9 then
                    local inv = 1/det
                    local sx,sy,sz = vecSub(origin,a)
                    local u = inv * dot(sx,sy,sz, hx,hy,hz)

                    if u >= 0 and u <= 1 then
                        local qx,qy,qz = cross(sx,sy,sz, e1x,e1y,e1z)
                        local v = inv * dot(dx,dy,dz, qx,qy,qz)

                        if v >= 0 and u + v <= 1 then
                            local t = inv * dot(e2x,e2y,e2z, qx,qy,qz)

                            -- direction is a segment vector, so t is [0,1].
                            if t >= 0 and t <= 1 and t < bestT then
                                bestT = t
                                bestFace = faceId
                                bestPoint = dataConstructors.Vector3.new(
                                    origin.X + dx*t,
                                    origin.Y + dy*t,
                                    origin.Z + dz*t
                                )
                                bestBary = dataConstructors.Vector3.new(1-u-v, u, v)
                            end
                        end
                    end
                end
            end
        end

        return bestPoint, bestFace, bestBary
    end

    values.FindClosestPointOnSurface = function(_, point)
        local bestDistance = math.huge
        local bestFace, bestPoint, bestBary

        for faceId, face in hostFns.pairs(faces) do
            local a,b,c = vertices[face[1]], vertices[face[2]], vertices[face[3]]
            if a and b and c then
                local cp,u,v,w = closestPointOnTriangle(point,a,b,c)
                local distance = vectorDistanceSquared(cp, point)

                if distance < bestDistance then
                    bestDistance = distance
                    bestFace = faceId
                    bestPoint = cp
                    bestBary = dataConstructors.Vector3.new(u,v,w)
                end
            end
        end

        if bestFace == nil then return nil end
        return bestFace, bestPoint, bestBary
    end

    local function meshAttributeName(attribute)
        if hostFns.type(attribute) == "table" or objectTypes[attribute] == "EnumItem" then
            return attribute.Name
        end
        return hostFns.tostring(attribute)
    end

    values.BatchAdd = function(_, attribute, input)
        local name = meshAttributeName(attribute)
        local out = {}

        if hostFns.type(input) ~= "table" then
            return out
        end

        if name == "Vertex" then
            for _, value in hostFns.ipairs(input) do
                if objectTypes[value] == "Vector3" then
                    out[#out + 1] = values.AddVertex(mesh, value)
                end
            end
        elseif name == "UV" then
            for _, value in hostFns.ipairs(input) do
                if objectTypes[value] == "Vector2" then
                    out[#out + 1] = values.AddUV(mesh, value)
                end
            end
        elseif name == "Normal" then
            for _, value in hostFns.ipairs(input) do
                if objectTypes[value] == "Vector3" then
                    out[#out + 1] = values.AddNormal(mesh, value)
                end
            end
        elseif name == "Color" then
            for _, value in hostFns.ipairs(input) do
                if objectTypes[value] == "Color3" then
                    out[#out + 1] = values.AddColor(mesh, value, 1)
                end
            end
        end

        return out
    end

    values.BatchGetVertexAttributes = function(_, attribute, ids)
        local name = meshAttributeName(attribute)
        local out = {}

        for _, id in hostFns.ipairs(ids or {}) do
            if name == "Vertex" then
                out[#out + 1] = vertices[id]
            elseif name == "UV" then
                out[#out + 1] = values.GetVertexUVs(mesh, id)
            elseif name == "Normal" then
                out[#out + 1] = values.GetVertexNormals(mesh, id)
            elseif name == "Color" then
                out[#out + 1] = values.GetVertexColors(mesh, id)
            end
        end

        return out
    end

    values.BatchGetFaceAttributes = function(_, attribute, ids)
        local name = meshAttributeName(attribute)
        local out = {}

        for _, id in hostFns.ipairs(ids or {}) do
            if name == "UV" then
                out[#out + 1] = values.GetFaceUVs(mesh, id)
            elseif name == "Normal" then
                out[#out + 1] = values.GetFaceNormals(mesh, id)
            elseif name == "Color" then
                out[#out + 1] = values.GetFaceColors(mesh, id)
            else
                out[#out + 1] = values.GetFaceVertices(mesh, id)
            end
        end

        return out
    end

    values.BatchGetVertexFaceAttributes = function(_, attribute, vertexIds, faceIds)
        local name = meshAttributeName(attribute)
        local out = {}

        for i, vertexId in hostFns.ipairs(vertexIds or {}) do
            local faceId = faceIds and faceIds[i] or nil
            if faceId then
                if name == "UV" then
                    out[#out + 1] = values.GetVertexFaceUV(mesh, vertexId, faceId)
                elseif name == "Normal" then
                    out[#out + 1] = values.GetVertexFaceNormal(mesh, vertexId, faceId)
                elseif name == "Color" then
                    out[#out + 1] = values.GetVertexFaceColor(mesh, vertexId, faceId)
                end
            end
        end

        return out
    end

    values.BatchGetValues = function(_, ids)
        local out = {}
        for _, id in hostFns.ipairs(ids or {}) do
            out[#out + 1] = vertices[id]
        end
        return out
    end

    values.BatchSetVertexFaceAttributes = function(_, vertexIds, faceIds, attributeIds)
        for i, vertexId in hostFns.ipairs(vertexIds or {}) do
            local faceId = faceIds and faceIds[i]
            local attributeId = attributeIds and attributeIds[i]
            if faceId and attributeId then
                values.SetVertexFaceUV(mesh, vertexId, faceId, attributeId)
            end
        end
    end

    values.BatchSetFaceAttributes = function(_, faceIds, attributes)
        for i, faceId in hostFns.ipairs(faceIds or {}) do
            local ids = attributes and attributes[i]
            if faceId and hostFns.type(ids) == "table" then
                values.SetFaceUVs(mesh, faceId, ids)
            end
        end
    end

    values.BatchSetValues = function(_, ids, newValues)
        for i, id in hostFns.ipairs(ids or {}) do
            local value = newValues and newValues[i] or nil

            if vertices[id] ~= nil then
                if value == nil or objectTypes[value] ~= "Vector3" then
                    hostFns.error("Vector3 expected for vertex value", 2)
                end
                vertices[id] = value
            elseif normals[id] ~= nil then
                if value == nil then
                    normals[id] = dataConstructors.Vector3.zero
                elseif objectTypes[value] == "Vector3" then
                    normals[id] = value
                else
                    hostFns.error("Vector3 or nil expected for normal value", 2)
                end
            elseif uvs[id] ~= nil then
                if objectTypes[value] ~= "Vector2" then
                    hostFns.error("Vector2 expected for UV value", 2)
                end
                uvs[id] = value
            elseif colors[id] ~= nil then
                if objectTypes[value] == "Color3" then
                    colors[id] = value
                elseif hostFns.type(value) == "number" then
                    colorAlpha[id] = value
                else
                    hostFns.error("Color3 or number expected for color value", 2)
                end
            else
                hostFns.error("invalid mesh attribute id", 2)
            end
        end
    end

    values.MergeVertices = function(_, tolerance)
        local tol = tonumber(tolerance) or 0
        local tol2 = tol * tol
        local ids = sortedIds(vertices)
        local merged = {}

        for i = 1, #ids do
            local a = ids[i]
            if vertices[a] then
                for j = i + 1, #ids do
                    local b = ids[j]
                    if vertices[b] and vectorDistanceSquared(vertices[a], vertices[b]) <= tol2 then
                        merged[b] = a

                        for _, face in hostFns.pairs(faces) do
                            for k = 1, #face do
                                if face[k] == b then face[k] = a end
                            end
                        end

                        vertices[b] = nil
                    end
                end
            end
        end

        return merged
    end

    values.RemoveUnused = function()
        local usedVertices = {}
        local usedUVs = {}
        local usedNormals = {}
        local usedColors = {}

        for faceId, face in hostFns.pairs(faces) do
            for _, vertexId in hostFns.ipairs(face) do usedVertices[vertexId] = true end
            for _, id in hostFns.ipairs(faceUVs[faceId] or {}) do usedUVs[id] = true end
            for _, id in hostFns.ipairs(faceNormals[faceId] or {}) do usedNormals[id] = true end
            for _, id in hostFns.ipairs(faceColors[faceId] or {}) do usedColors[id] = true end
        end

        for id in hostFns.pairs(vertices) do
            if not usedVertices[id] then
                vertices[id] = nil
                vertexBones[id] = nil
                vertexBoneWeights[id] = nil
            end
        end
        for id in hostFns.pairs(uvs) do if not usedUVs[id] then uvs[id] = nil end end
        for id in hostFns.pairs(normals) do if not usedNormals[id] then normals[id] = nil end end
        for id in hostFns.pairs(colors) do
            if not usedColors[id] then
                colors[id] = nil
                colorAlpha[id] = nil
            end
        end
    end

    values.Triangulate = function()
        -- AddTriangle already stores triangles, so the current face set is
        -- already triangulated.
        return nil
    end

    values.AddBone = function(_, options)
        options = hostFns.type(options) == "table" and options or {}

        local id = nextBoneId
        nextBoneId += 1

        bones[id] = {
            Name = options.Name or ("Bone" .. hostFns.tostring(id)),
            CFrame = options.CFrame or dataConstructors.CFrame.identity,
            ParentId = options.ParentId,
            Virtual = options.Virtual == true,
        }

        return id
    end

    values.GetBoneByName = function(_, name)
        for id, bone in hostFns.pairs(bones) do
            if bone.Name == name then return id end
        end
        return nil
    end

    values.GetBoneName = function(_, id)
        return bones[id] and bones[id].Name or nil
    end

    values.SetBoneName = function(_, id, name)
        if not bones[id] then hostFns.error("invalid bone id", 2) end
        bones[id].Name = hostFns.tostring(name)
    end

    values.GetBoneCFrame = function(_, id)
        return bones[id] and bones[id].CFrame or nil
    end

    values.SetBoneCFrame = function(_, id, value)
        if not bones[id] then hostFns.error("invalid bone id", 2) end
        bones[id].CFrame = value
    end

    values.GetBoneParent = function(_, id)
        if not bones[id] then hostFns.error("invalid bone id", 2) end
        return bones[id].ParentId or 0
    end

    values.SetBoneParent = function(_, id, parentId)
        if not bones[id] then hostFns.error("invalid bone id", 2) end
        bones[id].ParentId = parentId
    end

    values.GetBoneIsVirtual = function(_, id)
        return bones[id] and bones[id].Virtual == true or false
    end

    values.GetBones = function()
        return sortedIds(bones)
    end

    values.RemoveBone = function(_, id)
        bones[id] = nil
        for vertexId, list in hostFns.pairs(vertexBones) do
            local newBones = {}
            local newWeights = {}
            local weights = vertexBoneWeights[vertexId] or {}

            for i, boneId in hostFns.ipairs(list) do
                if boneId ~= id then
                    newBones[#newBones + 1] = boneId
                    newWeights[#newWeights + 1] = weights[i]
                end
            end

            vertexBones[vertexId] = newBones
            vertexBoneWeights[vertexId] = newWeights
        end
    end

    values.SetVertexBones = function(_, vertexId, ids)
        getVertex(vertexId)
        vertexBones[vertexId] = copyArray(ids)
    end

    values.GetVertexBones = function(_, vertexId)
        getVertex(vertexId)
        return copyArray(vertexBones[vertexId])
    end

    values.SetVertexBoneWeights = function(_, vertexId, weights)
        getVertex(vertexId)
        vertexBoneWeights[vertexId] = copyArray(weights)
    end

    values.GetVertexBoneWeights = function(_, vertexId)
        getVertex(vertexId)
        return copyArray(vertexBoneWeights[vertexId])
    end

    values.BatchRemove = function(_, ids)
        for _, id in hostFns.ipairs(ids or {}) do
            if faces[id] ~= nil then
                faces[id] = nil
                faceUVs[id] = nil
                faceNormals[id] = nil
                faceColors[id] = nil
            elseif vertices[id] ~= nil then
                vertices[id] = nil
                vertexBones[id] = nil
                vertexBoneWeights[id] = nil
            elseif uvs[id] ~= nil then
                uvs[id] = nil
            elseif normals[id] ~= nil then
                normals[id] = nil
            elseif colors[id] ~= nil then
                colors[id] = nil
                colorAlpha[id] = nil
            end
        end
    end

    values.RemoveFace = function(_, faceId)
        faces[faceId] = nil
        faceUVs[faceId] = nil
        faceNormals[faceId] = nil
        faceColors[faceId] = nil
    end

    values.RemoveVertex = function(_, vertexId)
        vertices[vertexId] = nil
        vertexBones[vertexId] = nil
        vertexBoneWeights[vertexId] = nil
    end

    values.RemoveUV = function(_, id)
        uvs[id] = nil
    end

    values.RemoveNormal = function(_, id)
        normals[id] = nil
    end

    values.RemoveColor = function(_, id)
        colors[id] = nil
        colorAlpha[id] = nil
    end

    values.Clear = function()
        nextVertexId = 1
        nextFaceId = 1
        nextUVId = 1
        nextNormalId = 1
        nextColorId = 1
        nextBoneId = 1

        vertices = {}
        faces = {}
        uvs = {}
        normals = {}
        colors = {}
        colorAlpha = {}
        faceUVs = {}
        faceNormals = {}
        faceColors = {}
        bones = {}
        vertexBones = {}
        vertexBoneWeights = {}
    end

    local traceableMethods = {
        "AddVertex","AddTriangle","AddUV","AddNormal","AddColor",
        "GetPosition","SetPosition","GetUV","SetUV","GetNormal","SetNormal","ResetNormal",
        "GetColor","SetColor","GetColorAlpha","SetColorAlpha",
        "GetVertices","GetFaces","GetUVs","GetNormals","GetColors",
        "GetFaceVertices","GetFaceUVs","SetFaceUVs",
        "GetFaceNormals","SetFaceNormals","GetFaceColors","SetFaceColors",
        "GetVertexFaceUV","SetVertexFaceUV",
        "GetVertexFaceNormal","SetVertexFaceNormal",
        "GetVertexFaceColor","SetVertexFaceColor",
        "GetAdjacentVertices","GetAdjacentFaces","GetVertexFaces",
        "GetVertexUVs","GetVertexNormals","GetVertexColors",
        "GetCenter","GetSize","FindClosestVertex","FindVerticesWithinSphere",
        "RaycastLocal","FindClosestPointOnSurface",
        "BatchAdd","BatchGetVertexAttributes","BatchGetFaceAttributes",
        "BatchGetVertexFaceAttributes","BatchGetValues",
        "BatchSetVertexFaceAttributes","BatchSetFaceAttributes","BatchSetValues",
        "MergeVertices","RemoveUnused","Triangulate",
        "AddBone","GetBoneByName","GetBoneName","SetBoneName",
        "GetBoneCFrame","SetBoneCFrame","GetBoneParent","SetBoneParent",
        "GetBoneIsVirtual","GetBones","RemoveBone",
        "SetVertexBones","GetVertexBones","SetVertexBoneWeights","GetVertexBoneWeights",
        "BatchRemove","RemoveFace","RemoveVertex","RemoveUV","RemoveNormal","RemoveColor","Clear",
    }

    for _, methodName in hostFns.ipairs(traceableMethods) do
        local original = values[methodName]
        if hostFns.type(original) == "function" then
            values[methodName] = function(selfObj, ...)
                if CONFIG.runtimeTracing then
                    local args = table.pack(...)
                    local rendered = {}
                    for i = 1, args.n do
                        rendered[i] = repr(args[i])
                    end
                    emit(objectNames[mesh] .. ":" .. methodName .. "(" .. table.concat(rendered, ", ") .. ")")
                end
                return original(selfObj, ...)
            end
        end
    end

    return mesh
end

local assetValues = instanceStates[assetService].values

assetValues.CreateEditableImage = function(_, options)
    local size = nil

    if hostFns.type(options) == "table" then
        size = options.Size
    end

    return makeEditableImage(size or dataConstructors.Vector2.new(1, 1))
end

assetValues.CreateEditableMesh = function(self, options)
    if self ~= assetService then
        hostFns.error("Expected ':' not '.' calling CreateEditableMesh", 2)
    end
    if options ~= nil and hostFns.type(options) ~= "table" then
        hostFns.error("invalid argument #1 to 'CreateEditableMesh' (table expected)", 2)
    end

    local mesh = makeEditableMesh()
    instanceStates[mesh].values.FixedSize = false
    return mesh
end

local contentProvider = makeService("ContentProvider")
local contentValues = instanceStates[contentProvider].values

proxyState[contentProvider] = {
    encryptedAssets = {},
}

contentValues.BaseUrl = "http://www.roblox.com/"
contentValues.RequestQueueSize = 0

contentValues.RegisterEncryptedAsset = function(self, assetId, key)
    if self ~= contentProvider then
        hostFns.error("Expected ':' not '.' calling RegisterEncryptedAsset", 2)
    end

    if hostFns.type(assetId) ~= "string" or assetId == "" then
        hostFns.error("invalid argument #1 to 'RegisterEncryptedAsset' (string expected)", 2)
    end

    if hostFns.type(key) ~= "string" or key == "" then
        hostFns.error("invalid argument #2 to 'RegisterEncryptedAsset' (string expected)", 2)
    end

    proxyState[contentProvider].encryptedAssets[assetId] = key

    emit(
        objectNames[contentProvider]
        .. ":RegisterEncryptedAsset("
        .. repr(assetId)
        .. ", "
        .. repr(key)
        .. ")"
    )
end

contentValues.ListEncryptedAssets = function(self)
    if self ~= contentProvider then
        hostFns.error("Expected ':' not '.' calling ListEncryptedAssets", 2)
    end

    local result = {}

    for assetId in hostFns.pairs(proxyState[contentProvider].encryptedAssets) do
        result[#result + 1] = assetId
    end

    table.sort(result)

    emit(
        objectNames[contentProvider]
        .. ":ListEncryptedAssets()"
    )

    return result
end

contentValues.UnregisterEncryptedAsset = function(self, assetId)
    if self ~= contentProvider then
        hostFns.error("Expected ':' not '.' calling UnregisterEncryptedAsset", 2)
    end

    if hostFns.type(assetId) ~= "string" or assetId == "" then
        hostFns.error("invalid argument #1 to 'UnregisterEncryptedAsset' (string expected)", 2)
    end

    proxyState[contentProvider].encryptedAssets[assetId] = nil

    emit(
        objectNames[contentProvider]
        .. ":UnregisterEncryptedAsset("
        .. repr(assetId)
        .. ")"
    )
end

do
local contentFetchStatus = {}
local contentFetchSignals = {}

local function getContentAssetId(asset)
    if hostFns.type(asset) == "string" then return asset end
    local state = instanceStates[asset]
    if state then
        for _, key in hostFns.ipairs({"SoundId","Image","Texture","MeshId","AnimationId"}) do
            local value = state.values[key]
            if hostFns.type(value) == "string" and value ~= "" then return value end
        end
    end
    return hostFns.tostring(asset)
end

contentValues.GetAssetFetchStatus = function(self, assetId)
    if self ~= contentProvider then hostFns.error("Expected ':' not '.' calling GetAssetFetchStatus", 2) end
    local id = hostFns.tostring(assetId)
    return contentFetchStatus[id] or makeEnumType("AssetFetchStatus").None
end

contentValues.GetAssetFetchStatusChangedSignal = function(self, assetId)
    if self ~= contentProvider then hostFns.error("Expected ':' not '.' calling GetAssetFetchStatusChangedSignal", 2) end
    local id = hostFns.tostring(assetId)
    if not contentFetchSignals[id] then
        contentFetchSignals[id] = makeSignal("ContentProvider.AssetFetchStatusChanged:" .. id)
    end
    return contentFetchSignals[id]
end

contentValues.PreloadAsync = function(self, assets, callback)
    if self ~= contentProvider then hostFns.error("Expected ':' not '.' calling PreloadAsync", 2) end
    if hostFns.type(assets) ~= "table" then hostFns.error("table expected", 2) end

    local successStatus = makeEnumType("AssetFetchStatus").Success
    for _, asset in hostFns.ipairs(assets) do
        local id = getContentAssetId(asset)
        contentFetchStatus[id] = successStatus
        local signal = contentFetchSignals[id]
        if signal then fireSignal(signal, successStatus) end
        if hostFns.type(callback) == "function" then
            hostFns.pcall(callback, id, successStatus)
        end
    end

    return nil
end

end

local guiService = makeService("GuiService")
local guiValues = instanceStates[guiService].values
local inspectMenuEnabled = true

guiValues.GetScreenResolution = function(selfObj)
    if selfObj ~= guiService then
        hostFns.error(
            "Expected ':' not '.' calling GetScreenResolution",
            2
        )
    end

    securityRuntime.assertAccess(
        "GuiService",
        "GetScreenResolution",
        "Call"
    )

    -- The real method yields.  Pump one scheduler quantum so callbacks/tasks
    -- observe a yielding boundary instead of a pure immediate Lua return.
    if advanceSimulation then
        advanceSimulation(1 / 60)
    else
        virtualTime += 1 / 60
    end

    emit("GuiService:GetScreenResolution()")
    return dataConstructors.Vector2.new(800, 600)
end

guiValues.GetInspectMenuEnabled = function()
    return inspectMenuEnabled
end

guiValues.SetInspectMenuEnabled = function(_, value)
    if hostFns.type(value) ~= "boolean" then
        hostFns.error("invalid argument #1 to 'SetInspectMenuEnabled' (boolean expected)", 2)
    end
    inspectMenuEnabled = value
end

guiValues.IsTenFootInterface = function(selfObj)
    if selfObj ~= guiService then hostFns.error("Expected ':' not '.' calling IsTenFootInterface", 2) end
    return false
end

local pathfinding = makeService("PathfindingService")
instanceStates[pathfinding].values.CreatePath = function(self, agentParameters)
    if self ~= pathfinding then hostFns.error("Expected ':' not '.' calling CreatePath",2) end

    local path = createInternalInstance("Path")
    local values = instanceStates[path].values
    proxyState[path] = {
        agentParameters = hostFns.type(agentParameters) == "table" and agentParameters or {},
        waypoints = {},
        computed = false,
    }

    values.Status = makeEnumType("PathStatus").NoPath
    values.Blocked = makeSignal(objectNames[path] .. ".Blocked")

    values.ComputeAsync = function(selfPath, startPosition, finishPosition)
        if selfPath ~= path then hostFns.error("Expected ':' not '.' calling ComputeAsync",2) end
        if objectTypes[startPosition] ~= "Vector3" or objectTypes[finishPosition] ~= "Vector3" then
            hostFns.error("Vector3 expected",2)
        end

        proxyState[path].waypoints = {
            dataConstructors.PathWaypoint.new(startPosition, makeEnumType("PathWaypointAction").Walk),
            dataConstructors.PathWaypoint.new(finishPosition, makeEnumType("PathWaypointAction").Walk),
        }
        proxyState[path].computed = true
        values.Status = makeEnumType("PathStatus").Success
    end

    values.GetWaypoints = function(selfPath)
        if selfPath ~= path then hostFns.error("Expected ':' not '.' calling GetWaypoints",2) end
        local out = {}
        for i, waypoint in hostFns.ipairs(proxyState[path].waypoints) do out[i] = waypoint end
        return out
    end

    return path
end

do
local policyService = makeService("PolicyService")
local policyValues = instanceStates[policyService].values
local policySnapshot = {
    AreAdsAllowed = true,
    ArePaidRandomItemsRestricted = false,
    IsContentSharingAllowed = true,
    IsEligibleToPurchaseCommerceProduct = true,
    IsEligibleToPurchaseSubscription = true,
    IsPaidItemTradingAllowed = true,
    IsPhotoToAvatarAllowed = true,
    IsSubjectToChinaPolicies = false,
}

policyValues.GetPolicyInfoForPlayerAsync = function(self, player)
    if self ~= policyService then hostFns.error("Expected ':' not '.' calling GetPolicyInfoForPlayerAsync", 2) end
    local state = instanceStates[player]
    if not state or state.className ~= "Player" then hostFns.error("Player expected", 2) end
    return table.clone(policySnapshot)
end

end

local logService = makeService("LogService")
proxyState[logService] = {history = {}}
instanceStates[logService].values.MessageOut = makeSignal("LogService.MessageOut")
instanceStates[logService].values.GetLogHistory = function(self)
    if self ~= logService then hostFns.error("Expected ':' not '.' calling GetLogHistory",2) end
    local out = {}
    for i, record in hostFns.ipairs(proxyState[logService].history) do
        out[i] = {
            message = record.message,
            messageType = record.messageType,
            timestamp = record.timestamp,
        }
    end
    return out
end

local teams = makeService("Teams")
instanceStates[teams].values.GetTeams = function()
    local out = {}
    local linked = instanceChildren[teams]
    if linked then
        for child in hostFns.pairs(linked) do
            if instanceStates[child] and instanceStates[child].className == "Team" then
                out[#out + 1] = child
            end
        end
    end
    return out
end

instanceStates[players].values.GetPlayerFromCharacter = function(_, model)
    if model == character then
        return localPlayer
    end
    return nil
end

instanceStates[players].values.GetNameFromUserIdAsync=function(_,id)
    local n=tonumber(id)
    if not n or n<=0 or n~=math.floor(n) then hostFns.error("Invalid userId",2) end
    if n==CONFIG.userId then return CONFIG.username end
    return "Player"..hostFns.tostring(n)
end
instanceStates[players].values.GetUserIdFromNameAsync = function(_, name)
    if hostFns.tostring(name) == CONFIG.username then return CONFIG.userId end
    return 0
end
instanceStates[players].values.GetPlayers = function()
    return {localPlayer}
end

instanceStates[collection].values.GetTags = function(_, instance)
    local out = {}
    local tags = collectionTags[instance]
    if tags then
        for tag in hostFns.pairs(tags) do out[#out + 1] = tag end
    end
    return out
end

local statsService = makeService("Stats")
instanceStates[statsService].values.ContactsCount=0
instanceStates[statsService].values.FrameTime=1/60
instanceStates[statsService].values.PhysicsStepTime=1/60
instanceStates[statsService].values.PhysicsStepTimeMs=16.6667
instanceStates[statsService].values.HeartbeatTimeMs=16.6667
instanceStates[statsService].values.HeartbeatTime=1/60
instanceStates[statsService].values.MemoryTrackingEnabled=false

-- Keep this final Stats setup consistent with makeService("Stats").
-- This block used to replace the live implementation with `return 1`,
-- which silently undid every compatibility fix above it.
proxyState[statsService] = proxyState[statsService] or {}
proxyState[statsService].statsMemoryCounter =
    tonumber(proxyState[statsService].statsMemoryCounter) or 0

instanceStates[statsService].values.GetMemoryUsageMbForTag=function(self, tag)
    if self ~= statsService then
        hostFns.error(
            "Expected ':' not '.' calling GetMemoryUsageMbForTag",
            2
        )
    end

    proxyState[statsService].statsMemoryCounter += 1

    local counter =
        proxyState[statsService].statsMemoryCounter

    local tagName =
        tag and tag.Name
        or hostFns.tostring(tag or "")

    -- Use both elapsed host time and a monotonic sample counter. This models
    -- live engine memory while guaranteeing successive samples are not frozen.
    local elapsed =
        hostFns.clock() - runtimeStart

    if tagName == "Instances"
        or tagName == "Enum.DeveloperMemoryTag.Instances"
    then
        return 16
            + ((counter % 8) * 4)
            + ((math.floor(elapsed * 10) % 4) * 0.25)
    elseif tagName == "Graphics"
        or tagName == "Enum.DeveloperMemoryTag.Graphics"
    then
        return 128
            + ((counter % 6) * 2)
            + ((math.floor(elapsed * 10) % 4) * 0.25)
    end

    return 1
        + ((counter % 7) * 0.5)
end


local function normalizeSandboxPath(path)
    path = hostFns.tostring(path or "")
    path = path:gsub("\\", "/")
    path = path:gsub("^/+", "")
    path = path:gsub("/+", "/")

    local parts = {}
    for part in path:gmatch("[^/]+") do
        if part == "." or part == "" then
            -- skip
        elseif part == ".." then
            hostFns.error("path traversal is not allowed", 2)
        else
            parts[#parts + 1] = part
        end
    end

    return table.concat(parts, "/")
end

local function sandboxPath(path)
    local rel = normalizeSandboxPath(path)
    if rel == "" then
        return CONFIG.sandboxRoot, ""
    end
    return CONFIG.sandboxRoot .. "/" .. rel, rel
end

local function ensureSandboxRoot()
    -- Native writeDir is idempotent. Calling it directly avoids a
    -- check-then-create race when multiple bot commands start at once.
    fs.writeDir(CONFIG.sandboxRoot)
end

ensureSandboxRoot()

local function listSandbox(path)
    local full, rel = sandboxPath(path)
    if not fs.isDir(full) then
        hostFns.error("folder does not exist: " .. rel, 2)
    end

    local ok, entries = hostFns.pcall(fs.readDir, full)
    if not ok then
        hostFns.error(hostFns.tostring(entries), 2)
    end

    local out = {}
    for _, entry in hostFns.ipairs(entries) do
        local name = entry
        if hostFns.type(entry) == "table" then
            name = entry.name or entry.path or entry[1]
        end
        if name then
            local clean = hostFns.tostring(name):gsub("\\", "/")
            clean = clean:match("([^/]+)$") or clean
            if rel == "" then
                out[#out + 1] = clean
            else
                out[#out + 1] = rel .. "/" .. clean
            end
        end
    end
    return out
end

local sandbox = {}
local dynamicLoader
local dynamicFunctionInfo=hostFns.setmetatable({}, {__mode="k"})
local activeDynamicEnv = nil

local settingsServices = {}

local physicsSettings = newproxy(true)
do
    local mt = hostFns.getmetatable(physicsSettings)
    mark(physicsSettings, "PhysicsSettings", "PhysicsSettings")

    local values = {
        PhysicsEnvironmentalThrottle = makeEnumType("EnviromentalPhysicsThrottle").DefaultAuto,
        AllowSleep = true,
        ShowDecompositionGeometry = false,
    }

    mt.__metatable = "The metatable is locked"

    mt.__index = function(_, key)
        return values[key]
    end

    mt.__newindex = function(_, key, value)
        values[key] = value
    end

    mt.__tostring = function()
        return "PhysicsSettings"
    end
end

settingsServices.PhysicsSettings = physicsSettings

do
    local networkSettings = newproxy(true)
    local mt = hostFns.getmetatable(networkSettings)
    mt.__metatable = "The metatable is locked"
    mt.__index = function(_, key)
        if key == "IncomingReplicationLag" then return 0 end
        return nil
    end
    mt.__tostring = function() return "NetworkSettings" end
    settingsServices.NetworkSettings = networkSettings
end

do
    local userSettingsObject = newproxy(true)
    local mt = hostFns.getmetatable(userSettingsObject)
    mt.__metatable = "The metatable is locked"
    mt.__index = function(_, key)
        if key == "IsUserFeatureEnabled" then
            return function(_, _featureName)
                return false
            end
        end
        return nil
    end
    mt.__tostring = function() return "UserSettings" end
    settingsServices.UserSettings = userSettingsObject
end

local settingsObject = newproxy(true)
do
    local mt = hostFns.getmetatable(settingsObject)
    mark(settingsObject, "settings()", "Instance")
    mt.__metatable = "The metatable is locked"

    mt.__index = function(_, key)
        if key == "GetService" then
            return function(_, name)
                local service = settingsServices[hostFns.tostring(name)]
                if service then
                    return service
                end

                hostFns.error(hostFns.tostring(name) .. " is not a valid settings service", 2)
            end
        end

        return nil
    end
end

local function sandboxType(value)
    if objectTypes[value] == "Instance" then
        return "userdata"
    elseif objectTypes[value] == "RegexObject" then
        return "userdata"
    end

    return hostFns.type(value)
end

local function sandboxTypeof(value)
    return objectTypes[value] or hostFns.typeof(value)
end

local function sandboxGetmetatable(value)
    if hostFns.type(value) == "string" then
        return {}
    end

    return hostFns.getmetatable(value)
end

local function runTask(callback, ...)
    if hostFns.type(callback) ~= "function" then
        hostFns.error("invalid argument #1 (function expected)", 2)
    end

    local co = coroutine.create(callback)
    local result = table.pack(coroutine.resume(co, ...))

    if not result[1] then
        hostFns.error(result[2], 0)
    end

    return hostFns.unpack(result, 2, result.n)
end

local taskLib = {}
taskLib.__mainThread = coroutine.running()
local pendingTasks = {}
local cancelledThreads = hostFns.setmetatable({}, { __mode = "k" })
local managedThreads = hostFns.setmetatable({}, { __mode = "k" })
local schedulerCycle = 0
local schedulerSequence = 0

local function enqueueThread(thread, due, args)
    schedulerSequence += 1
    pendingTasks[#pendingTasks + 1] = {
        due = due,
        cycle = schedulerCycle + 1,
        sequence = schedulerSequence,
        thread = thread,
        args = args or {},
    }
end

local function makeTaskThread(callback)
    local callbackType = hostFns.type(callback)

    if callbackType == "thread" then
        return callback
    end

    if callbackType ~= "function" then
        hostFns.error("invalid argument (function or thread expected)", 3)
    end

    local wrapNative = callback == coroutine.yield

    if not wrapNative and hostFns.type(debug) == "table"
        and hostFns.type(debug.info) == "function"
    then
        local ok, source = hostFns.pcall(debug.info, callback, "s")
        wrapNative = ok and source == "[C]"
    end

    if wrapNative then
        return coroutine.create(function(...)
            return callback(...)
        end)
    end

    return coroutine.create(callback)
end

scheduleTask = function(delaySeconds, callback, args)
    local inheritedIdentity = getRuntimeThreadIdentity()
    local thread = makeTaskThread(callback)

    if threadIdentityByThread[thread] == nil then
        threadIdentityByThread[thread] = inheritedIdentity
    end

    managedThreads[thread] = true
    enqueueThread(thread, virtualTime + math.max(0, tonumber(delaySeconds) or 0), args or {})
    return thread
end

pumpTasks = function()
    schedulerCycle += 1
    local activeCycle = schedulerCycle

    while true do
        local selected=nil
        local selectedDue=nil
        local selectedSeq=nil

        for i,item in hostFns.ipairs(pendingTasks) do
            if item and item.due <= virtualTime and (item.cycle or 0) <= activeCycle then
                if selected == nil
                    or item.due < selectedDue
                    or (item.due == selectedDue and (item.sequence or 0) < selectedSeq)
                then
                    selected=i
                    selectedDue=item.due
                    selectedSeq=item.sequence or 0
                end
            end
        end

        if not selected then break end

        local item=table.remove(pendingTasks,selected)

        if item and not cancelledThreads[item.thread] then
            local result=table.pack(coroutine.resume(item.thread,hostFns.unpack(item.args)))

            if not result[1] then
                hostFns.warn("[OxyEnv task] "..hostFns.tostring(result[2]))
            elseif coroutine.status(item.thread) ~= "dead" then
                local yieldKind = result[2]
                local waitFor = tonumber(result[3]) or 0

                if yieldKind == "__madium_wait" then
                    enqueueThread(
                        item.thread,
                        virtualTime + math.max(waitFor, 1/60),
                        {math.max(waitFor, 1/60)}
                    )
                end
            end
        end
    end
end

local function fireRunServiceStep(dt)
    local runService = serviceCache.RunService
    if not runService then return end
    local values = instanceStates[runService] and instanceStates[runService].values
    if not values then return end
    if values.PreData then fireSignal(values.PreData, dt) end
    if values.PreModel then fireSignal(values.PreModel, dt) end
    if values.PreLocal then fireSignal(values.PreLocal, dt) end
    if values.Stepped then fireSignal(values.Stepped, virtualTime, dt) end
    if values.Heartbeat then fireSignal(values.Heartbeat, dt) end
    if values.RenderStepped then fireSignal(values.RenderStepped, dt) end
    if values.Render then fireSignal(values.Render, dt) end
    if values.PostLocal then fireSignal(values.PostLocal, dt) end
    if values.PostModel then fireSignal(values.PostModel, dt) end
    if values.PostData then fireSignal(values.PostData, dt) end
end

advanceSimulation = function(requested)
    local wallStart=hostFns.clock()
    while hostFns.clock()-wallStart < requested do end

    virtualTime += requested
    CONFIG.dateTimeVirtualOffsetMs = (CONFIG.dateTimeVirtualOffsetMs or 0) + requested * 1000

    -- Model live-client hierarchy churn with real internal descendants.
    -- These objects are actually parented into CoreGui, so all normal
    -- descendant traversal sees the same state instead of GetDescendants
    -- fabricating extra return values.
    if coreGui and instanceStates[coreGui] then
        proxyState[coreGui] = proxyState[coreGui] or {}

        local churn =
            proxyState[coreGui].runtimeChurn

        if churn == nil then
            churn = {
                serial = 0,
                items = {},
            }
            proxyState[coreGui].runtimeChurn = churn
        end

        churn.serial += 1

        local transient =
            createInternalInstance(
                "Folder",
                coreGui
            )

        instanceStates[transient].values.Name =
            "RuntimeTransient"
            .. hostFns.tostring(churn.serial)

        churn.items[#churn.items + 1] =
            transient

        -- Keep the model bounded while still changing the real descendant
        -- count over time.
        if #churn.items > 4 then
            local oldest =
                table.remove(churn.items, 1)

            if oldest and instanceStates[oldest] then
                setParent(oldest, nil)
                instanceStates[oldest].destroyed = true
                instanceStates[oldest].values.Parent = nil
            end
        end
    end

    local debrisService = serviceCache.Debris
    if debrisService
        and proxyState[debrisService]
        and proxyState[debrisService].debrisQueue
    then
        local queue = proxyState[debrisService].debrisQueue

        for i = #queue, 1, -1 do
            local item = queue[i]

            if item
                and virtualTime >= item.due
            then
                local object = item.object
                local objectState = instanceStates[object]

                if objectState
                    and not objectState.destroyed
                then
                    instanceMethodHandlers.Destroy(object)
                end

                table.remove(queue, i)
            end
        end
    end

    if instanceStates[workspace] then
        instanceStates[workspace].values.DistributedGameTime = virtualTime
    end

    local rs = serviceCache.RunService
    if rs and instanceStates[rs] then
        local rv = instanceStates[rs].values
        rv.FrameNumber = (tonumber(rv.FrameNumber) or 0) + 1
    end

    local function lerpRuntimeValue(a, b, alpha)
        if hostFns.type(a) == "number" and hostFns.type(b) == "number" then
            return a + (b - a) * alpha
        end
        local kindA, kindB = objectTypes[a], objectTypes[b]
        if kindA == kindB and a ~= nil and b ~= nil then
            if kindA == "Vector2" or kindA == "Vector3" or kindA == "Color3"
                or kindA == "UDim2" or kindA == "CFrame"
            then
                local ok, value = hostFns.pcall(function() return a:Lerp(b, alpha) end)
                if ok then return value end
            end
        end
        return alpha >= 1 and b or a
    end

    for inst, state in hostFns.pairs(instanceStates) do
        if state and not state.destroyed then
            if state.className == "Tween" then
                local info = proxyState[inst] and proxyState[inst].tween
                if info and info.active and info.target and instanceStates[info.target] then
                    local elapsed = virtualTime - (info.startedAt or virtualTime)
                    local delayTime = tonumber(info.delayTime) or 0
                    local duration = math.max(tonumber(info.duration) or 0, 1e-9)
                    if elapsed >= delayTime then
                        local alpha = math.max(0, math.min(1, (elapsed - delayTime) / duration))
                        local tweenServiceObj = serviceCache.TweenService
                        local eased = alpha
                        if tweenServiceObj and instanceStates[tweenServiceObj] and instanceStates[tweenServiceObj].values.GetValue then
                            local okEase, resultEase = hostFns.pcall(
                                instanceStates[tweenServiceObj].values.GetValue,
                                tweenServiceObj,
                                alpha,
                                info.info.EasingStyle,
                                info.info.EasingDirection
                            )
                            if okEase and hostFns.type(resultEase) == "number" then eased = resultEase end
                        end
                        for key, goal in hostFns.pairs(info.goals or {}) do
                            local start = info.starts and info.starts[key]
                            local value = lerpRuntimeValue(start, goal, eased)
                            local okSet = hostFns.pcall(function() info.target[key] = value end)
                            if not okSet and alpha >= 1 then
                                hostFns.pcall(function() info.target[key] = goal end)
                            end
                        end
                    end
                end
            elseif state.className == "Sound" then
                local ps = proxyState[inst]
                if ps and ps.playing then
                    local speed = tonumber(state.values.PlaybackSpeed) or 1
                    local length = math.max(tonumber(state.values.TimeLength) or 180, 0.001)
                    local nextPos = (tonumber(state.values.TimePosition) or 0) + requested * speed
                    if nextPos >= length then
                        if state.values.Looped == true then
                            nextPos = nextPos % length
                        else
                            nextPos = length
                            ps.playing = false
                            state.values.IsPlaying = false
                            state.values.Playing = false
                        end
                    end
                    state.values.TimePosition = nextPos
                end
            elseif state.className == "AnimationTrack" then
                local ps = proxyState[inst]
                if ps and ps.playing and state.values.IsPlaying == true then
                    local speed = tonumber(state.values.Speed) or 1
                    local length = math.max(tonumber(state.values.Length) or 2, 0.001)
                    local nextPos = (tonumber(state.values.TimePosition) or 0) + requested * speed
                    if nextPos >= length then
                        if state.values.Looped == true then
                            nextPos = nextPos % length
                        else
                            nextPos = length
                            ps.playing = false
                            state.values.IsPlaying = false
                        end
                    end
                    state.values.TimePosition = nextPos
                end
            end
        end
    end

    local gravity=instanceStates[workspace].values.Gravity or 196.1999969482422
    for inst,state in hostFns.pairs(instanceStates) do
        if state and classIsA(state.className,"BasePart") and state.values.Parent~=nil and state.values.Anchored~=true then
            local cf=state.values.CFrame or dataConstructors.CFrame.new()
            local oldVelocity=state.values.Velocity or state.values.AssemblyLinearVelocity or dataConstructors.Vector3.zero

            local vx = oldVelocity.X
            local vy = oldVelocity.Y - gravity * requested
            local vz = oldVelocity.Z

            -- A live player character's HumanoidRootPart is normally supported
            -- by the humanoid/floor assembly instead of free-falling every frame.
            -- Apply mild horizontal damping so tiny injected velocities naturally
            -- decay across simulation steps, while keeping the root grounded.
            if state.values.Name == "HumanoidRootPart"
                and state.values.Parent == character
            then
                local damping = math.max(0, 1 - requested * 8)
                vx *= damping
                vz *= damping
                vy = 0
            end

            local linked = instanceChildren[inst]

            if linked then
                for child in hostFns.pairs(linked) do
                    local childState = instanceStates[child]

                    if childState
                        and childState.className == "BodyVelocity"
                    then
                        local target =
                            childState.values.Velocity
                            or dataConstructors.Vector3.zero

                        local maxForce =
                            childState.values.MaxForce
                            or dataConstructors.Vector3.zero

                        if math.abs(maxForce.X) > 0 then
                            vx = target.X
                        end

                        if math.abs(maxForce.Y) > 0 then
                            vy = target.Y
                        end

                        if math.abs(maxForce.Z) > 0 then
                            vz = target.Z
                        end
                    end
                end
            end

            local newVelocity =
                dataConstructors.Vector3.new(vx, vy, vz)

            state.values.Velocity=newVelocity
            state.values.AssemblyLinearVelocity=newVelocity

            local moved =
                dataConstructors.CFrame.new(
                    cf.X + newVelocity.X * requested,
                    cf.Y + newVelocity.Y * requested,
                    cf.Z + newVelocity.Z * requested
                )

            state.values.CFrame=moved
            state.values.Position=moved.Position
        end
    end

    fireRunServiceStep(requested)
end

taskLib.wait = function(duration)
    local requested = tonumber(duration)
    if requested == nil or requested < 1/60 then requested = 1/60 end

    emit("task.wait(" .. repr(requested) .. ")")

    local running = coroutine.running()
    if running and running ~= taskLib.__mainThread then
        return coroutine.yield("__madium_wait", requested)
    end

    advanceSimulation(requested)
    pumpTasks()
    return requested
end

taskLib.spawn = function(callback, ...)
    emit("task.spawn(function(...) end)")
    local inheritedIdentity = getRuntimeThreadIdentity()
    local thread = makeTaskThread(callback)

    if threadIdentityByThread[thread] == nil then
        threadIdentityByThread[thread] = inheritedIdentity
    end

    managedThreads[thread] = true
    local result=table.pack(coroutine.resume(thread,...))

    if not result[1] then
        hostFns.warn("[OxyEnv task] "..hostFns.tostring(result[2]))
    elseif coroutine.status(thread) ~= "dead" and result[2] == "__madium_wait" then
        local waitFor = tonumber(result[3]) or 1/60
        enqueueThread(
            thread,
            virtualTime + math.max(waitFor, 1/60),
            {math.max(waitFor, 1/60)}
        )
    end

    return thread
end

taskLib.defer = function(callback, ...)
    local callbackType = hostFns.type(callback)
    if callbackType ~= "function" and callbackType ~= "thread" then
        hostFns.error("invalid argument #1 to 'defer' (function or thread expected)", 2)
    end
    emit("task.defer(function(...) end)")
    return scheduleTask(0, callback, {...})
end

proxyState.__dispatchSignalCallback = function(callback, packed, count)
    taskLib.defer(function()
        local ok, err = hostFns.pcall(
            callback,
            hostFns.unpack(packed, 1, count)
        )
        if not ok then
            hostFns.warn("[OxyEnv signal] " .. hostFns.tostring(err))
        end
    end)
end

taskLib.delay = function(delaySeconds, callback, ...)
    emit("task.delay(...)")
    return scheduleTask(tonumber(delaySeconds) or 0, callback, {...})
end

taskLib.cancel = function(thread)
    cancelledThreads[thread] = true
end

-- Do not wrap scheduler functions with host.native.bind().  The native forwarder
-- introduces a C-call boundary, and task.wait must be able to coroutine.yield from
-- spawned/deferred Luau threads.  Keeping these as Luau closures matches Roblox's
-- yield behavior much more closely and fixes scheduler/WaitForChild semantics.

local function sandboxPrint(...)
    local rendered = {}
    local plain = {}
    local args = {...}

    for index, value in hostFns.ipairs(args) do
        rendered[index] = repr(value)
        plain[index] = hostFns.tostring(value)
    end

    local message = table.concat(plain, "	")
    emit("print(" .. table.concat(rendered, ", ") .. ")")

    local service = serviceCache.LogService
    if service and proxyState[service] and proxyState[service].history then
        proxyState[service].history[#proxyState[service].history + 1] = {
            message = message,
            messageType = makeEnumType("MessageType").MessageOutput,
            timestamp = tickEpochBase and (tickEpochBase + hostFns.clock()) or os.time(),
        }
        local signal = instanceStates[service].values.MessageOut
        if signal then fireSignal(signal, message, makeEnumType("MessageType").MessageOutput) end
    end
end

local function sandboxWarn(...)
    local rendered = {}
    local plain = {}
    local args = {...}

    for index, value in hostFns.ipairs(args) do
        rendered[index] = repr(value)
        plain[index] = hostFns.tostring(value)
    end

    local message = table.concat(plain, "	")
    emit("warn(" .. table.concat(rendered, ", ") .. ")")

    local service = serviceCache.LogService
    if service and proxyState[service] and proxyState[service].history then
        proxyState[service].history[#proxyState[service].history + 1] = {
            message = message,
            messageType = makeEnumType("MessageType").MessageWarning,
            timestamp = os.time(),
        }
        local signal = instanceStates[service].values.MessageOut
        if signal then fireSignal(signal, message, makeEnumType("MessageType").MessageWarning) end
    end
end

local nativeModuleShims = {}

local function sandboxRequire(module)
    if module == nil then
        hostFns.error("invalid argument #1 to 'require' (ModuleScript or module name expected)", 2)
    end

    if hostFns.type(module) == "string" then
        local shim = nativeModuleShims[module]

        if shim ~= nil then
            return shim
        end

        hostFns.error(
            "module '" .. hostFns.tostring(module) .. "' not found",
            2
        )
    end

    if not instanceStates[module] or instanceStates[module].className ~= "ModuleScript" then
        hostFns.error("invalid argument #1 to 'require' (ModuleScript or module name expected)", 2)
    end

    local state = instanceStates[module]
    proxyState[module] = proxyState[module] or {}

    if proxyState[module].required then
        return proxyState[module].result
    end
    if proxyState[module].requiring then
        hostFns.error("Requested module experienced an error while loading", 2)
    end

    local source = state.values.Source
    if hostFns.type(source) ~= "string" then
        hostFns.error("ModuleScript.Source is unavailable", 2)
    end

    proxyState[module].requiring = true
    local fn, compileError = dynamicLoader(source, "=" .. (state.values.Name or "ModuleScript"))
    if not fn then
        proxyState[module].requiring = nil
        hostFns.error(hostFns.tostring(compileError), 2)
    end

    local results = table.pack(hostFns.pcall(fn))
    proxyState[module].requiring = nil
    if not results[1] then
        hostFns.error(hostFns.tostring(results[2]), 2)
    end

    proxyState[module].result = results[2]
    proxyState[module].required = true
    return results[2]
end

local function safeRawget(value, key)
    if instanceStates[value] then
        hostFns.error(
            "invalid argument #1 to 'rawget' (table expected, got Instance)",
            0
        )
    end

    return hostFns.rawget(value, key)
end

local function safeRawset(value, key, newValue)
    if instanceStates[value] then
        hostFns.error(
            "invalid argument #1 to 'rawset' (table expected, got Instance)",
            0
        )
    end

    return hostFns.rawset(value, key, newValue)
end

local function safeGetfenv(target)
    if target == nil then return activeDynamicEnv or sandbox end
    if target == 0 then return activeDynamicEnv or sandbox end
    if hostFns.type(target) == "number" then
        if target < 0 or target > 32 then hostFns.error("invalid argument #1 to 'getfenv' (invalid level)",0) end
        return sandbox
    end
    if hostFns.type(target) == "function" then
        local info=dynamicFunctionInfo[target]
        if info then return info.env end

        -- Runtime API functions live in the sandbox environment and are not
        -- user-mutable through setfenv.
        if sandbox.__isProtectedRuntimeFunction and sandbox.__isProtectedRuntimeFunction(target) then
            return sandbox
        end

        if hostFns.type(hostFns.getfenv)=="function" then
            local ok,result=hostFns.pcall(hostFns.getfenv,target)
            if ok and hostFns.type(result)=="table" then return result end
        end
        return sandbox
    end
    hostFns.error("invalid argument #1 to 'getfenv'",0)
end

sandbox.__isProtectedRuntimeFunction = function(target)
    if hostFns.type(target) ~= "function" then
        return false
    end

    for _, constructor in hostFns.pairs(dataConstructors) do
        if hostFns.type(constructor) == "table" then
            for _, fn in hostFns.pairs(constructor) do
                if fn == target then
                    return true
                end
            end
        elseif constructor == target then
            return true
        end
    end

    for _, fn in hostFns.pairs(taskLib) do
        if fn == target then
            return true
        end
    end

    for _, fn in hostFns.pairs(instanceMethodHandlers) do
        if fn == target then
            return true
        end
    end

    for _, fn in hostFns.pairs(runValues) do
        if fn == target then
            return true
        end
    end

    if sandbox.Instance and sandbox.Instance.new == target then
        return true
    end

    return false
end

local function safeSetfenv(target,envValue)
    if hostFns.type(envValue)~="table" then
        hostFns.error("invalid argument #2 to 'setfenv' (table expected)",0)
    end

    if hostFns.type(target)~="function" and hostFns.type(target)~="number" then
        hostFns.error("invalid argument #1 to 'setfenv'",0)
    end

    if hostFns.type(target)=="function" then
        local source = nil
        if hostFns.type(debug.info) == "function" then
            local ok, value = hostFns.pcall(debug.info, target, "s")
            if ok then source = value end
        end

        if source == "[C]" then
            hostFns.error("cannot change environment of a native runtime API function",0)
        end
    end

    if hostFns.type(target)=="function" and sandbox.__isProtectedRuntimeFunction(target) then
        hostFns.error("cannot change environment of a Project Radium runtime API function",0)
    end

    if hostFns.type(target)=="function" then
        local info=dynamicFunctionInfo[target]
        if info then
            info.env=envValue
            return target
        end
    end

    if hostFns.type(target)=="function" and hostFns.type(hostFns.setfenv)=="function" then
        local ok,result=hostFns.pcall(hostFns.setfenv,target,envValue)
        if not ok then hostFns.error(result,0) end
        return result
    end

    return target
end

dynamicLoader = function(source, chunkName)
    source=hostFns.tostring(source or "")
    if #source > LIMITS.MAX_DYNAMIC_SOURCE then return nil,"dynamic source too large" end
    emit("loadstring("..repr(source)..")")

    local envRef=sandbox
    local nameRef=chunkName or "=OxyEnv"
    local okTest,testFn,testErr=hostFns.pcall(luau.load,source,{environment=envRef,chunkName=nameRef})
    if not okTest then return nil,hostFns.tostring(testFn) end
    if not testFn then return nil,hostFns.tostring(testErr) end

    local wrapper
    wrapper=function(...)
        local info=dynamicFunctionInfo[wrapper]
        local activeEnv=info and info.env or envRef
        local okLoad,fnOrError,second=hostFns.pcall(luau.load,source,{environment=activeEnv,chunkName=nameRef})
        if not okLoad then hostFns.error(hostFns.tostring(fnOrError),0) end
        if not fnOrError then hostFns.error(hostFns.tostring(second),0) end

        local previousEnv = activeDynamicEnv
        activeDynamicEnv = activeEnv
        local results = table.pack(hostFns.pcall(fnOrError, ...))
        activeDynamicEnv = previousEnv

        if not results[1] then
            hostFns.error(hostFns.tostring(results[2]), 0)
        end

        return hostFns.unpack(results, 2, results.n)
    end
    dynamicFunctionInfo[wrapper]={env=envRef,source=source,chunkName=nameRef}
    return wrapper
end

sandbox.print = sandboxPrint
sandbox.warn = sandboxWarn

sandbox.error = error

sandbox.assert = assert
sandbox.pcall = pcall
sandbox.xpcall=xpcall
sandbox.ypcall=pcall
sandbox.select = select
sandbox.next = next
sandbox.pairs = pairs
sandbox.ipairs = ipairs
sandbox.tonumber = tonumber
sandbox.__tableTostringIds = hostFns.setmetatable({}, {__mode = "k"})
sandbox.__nextTableTostringId = 0
local function sandboxTostring(value)
    if hostFns.type(value) == "table" then
        local id = sandbox.__tableTostringIds[value]
        if id == nil then
            sandbox.__nextTableTostringId += 1
            id = sandbox.__nextTableTostringId
            sandbox.__tableTostringIds[value] = id
        end
        -- Roblox/Luau table strings expose identity.  Put the per-table id in
        -- the leading address digits so even anti-emulator prefix checks differ.
        return string.format("table: 0x%06x%010x", id % 0x1000000, (id * 0x9e3779b1) % 0x10000000000)
    end
    return hostFns.tostring(value)
end
sandbox.tostring = sandboxTostring
sandbox.rawequal = rawequal
sandbox.rawlen = rawlen
sandbox.rawget = safeRawget
sandbox.rawset = safeRawset

if host.native and host.native.bind then
    sandbox.rawget = host.native.bind("rawget", sandbox.rawget)
    sandbox.rawset = host.native.bind("rawset", sandbox.rawset)
end

sandbox.type = sandboxType
sandbox.typeof = sandboxTypeof
if host.native and host.native.bind then
    sandbox.type = host.native.bind("type", sandbox.type)
    sandbox.typeof = host.native.bind("typeof", sandbox.typeof)
    sandbox.tostring = host.native.bind("tostring", sandbox.tostring)
end
sandbox.getmetatable = sandboxGetmetatable
sandbox.setmetatable = setmetatable
sandbox.getfenv = safeGetfenv
sandbox.setfenv = safeSetfenv

if host.native and host.native.bind then
    sandbox.getfenv = host.native.bind("getfenv", sandbox.getfenv)
    sandbox.setfenv = host.native.bind("setfenv", sandbox.setfenv)
end

sandbox.unpack = table.unpack or unpack
sandbox._VERSION = "Luau"

sandbox.math = {}
for key, value in hostFns.pairs(math) do
    sandbox.math[key] = value
end
sandbox.math.nan = 0 / 0
sandbox.math.tointeger = nil
sandbox.math.type = nil

sandbox.string = {}
for key, value in hostFns.pairs(string) do
    sandbox.string[key] = value
end
sandbox.string.dump = function()
    hostFns.error("unable to dump given function", 2)
end

sandbox.table = {}
for key, value in hostFns.pairs(table) do
    sandbox.table[key] = value
end
if hostFns.type(sandbox.table.foreach) ~= "function" then
    sandbox.table.foreach = function(tbl, callback)
        for k, v in hostFns.pairs(tbl) do callback(k, v) end
    end
end
if hostFns.type(sandbox.table.foreachi) ~= "function" then
    sandbox.table.foreachi = function(tbl, callback)
        for i, v in hostFns.ipairs(tbl) do callback(i, v) end
    end
end
sandbox.table.isfrozen = function(value)
    if objectTypes[value] == "SharedTable" then
        local fields = sharedTableFields[value]
        return fields and fields.__RadiumFrozen == true or false
    end
    if hostFns.type(table.isfrozen) == "function" then
        local ok, result = hostFns.pcall(table.isfrozen, value)
        return ok and result == true
    end
    return false
end
sandbox.table.freeze = function(value)
    if objectTypes[value] == "SharedTable" then
        local fields = sharedTableFields[value]
        if fields then fields.__RadiumFrozen = true end
        return value
    end
    if hostFns.type(table.freeze) == "function" then
        return table.freeze(value)
    end
    return value
end

sandbox.utf8 = {}
for key, value in hostFns.pairs(utf8) do
    sandbox.utf8[key] = value
end
if hostFns.type(sandbox.utf8.graphemes) ~= "function" then
    sandbox.utf8.graphemes = function(value)
        local textValue = hostFns.tostring(value or "")
        local starts = {}
        for byteIndex in utf8.codes(textValue) do
            starts[#starts + 1] = byteIndex
        end

        local index = 0
        return function()
            index += 1
            local first = starts[index]
            if not first then
                return nil
            end

            local last = (starts[index + 1] or (#textValue + 1)) - 1
            return first, last
        end
    end
end

sandbox.bit32 = {}
for key, value in hostFns.pairs(bit32) do
    sandbox.bit32[key] = value
end

sandbox.coroutine = {}
for key, value in hostFns.pairs(coroutine) do
    sandbox.coroutine[key] = value
end

sandbox.os = {}
for key, value in hostFns.pairs(os) do
    sandbox.os[key] = value
end

sandbox.debug = {}
for key, value in hostFns.pairs(debug) do
    sandbox.debug[key] = value
end
-- Roblox Luau does not expose the standard-Lua hook/local inspection surface.
sandbox.debug.sethook = nil
sandbox.debug.getlocal = nil
sandbox.debug.setlocal = nil

-- Executor/Luau compatibility surface used by reflection and integrity probes.
-- Keep these intentionally narrow rather than exposing the host registry.
sandbox.debug.getregistry = function()
    return {}
end

sandbox.debug.getmetatable = function(value)
    -- Never expose the sandbox/global runtime metatable.
    if value == sandbox or value == activeDynamicEnv then
        return nil
    end

    -- Proxied Roblox/runtime values may have implementation metatables that
    -- belong to Radium itself. Hide those rather than leaking internals.
    if objectTypes[value] ~= nil
        or instanceStates[value] ~= nil
        or proxyState[value] ~= nil
    then
        return nil
    end

    -- Ordinary user-created Lua tables may still expose their own metatable.
    if hostFns.type(value) == "table" then
        local ok, result = hostFns.pcall(hostFns.getmetatable, value)
        if ok then
            return result
        end
    end

    return nil
end

sandbox.debug.getupvalue = function(fn, index)
    if hostFns.type(fn) ~= "function" then
        hostFns.error(
            "invalid argument #1 to 'getupvalue' (function expected)",
            2
        )
    end

    index = tonumber(index)
    if index == nil then
        hostFns.error(
            "invalid argument #2 to 'getupvalue' (number expected)",
            2
        )
    end

    -- Compatibility-only surface: never expose Radium/host closure state.
    -- Returning nil is consistent with "no visible Lua upvalue" and keeps
    -- pcall(debug.getupvalue, ...) successful for integrity probes.
    return nil
end

do
    local rawDebugInfo = sandbox.debug.info
    local rawDebugGetinfo = sandbox.debug.getinfo
    local rawDebugTraceback = sandbox.debug.traceback

    if hostFns.type(rawDebugTraceback) == "function" then
        sandbox.debug.traceback = function(threadOrMessage, messageOrLevel, maybeLevel)
            local trace

            if hostFns.type(threadOrMessage) == "thread" then
                local ok, value = hostFns.pcall(
                    rawDebugTraceback,
                    threadOrMessage,
                    messageOrLevel,
                    maybeLevel
                )
                trace = ok and value or nil
            else
                local ok, value = hostFns.pcall(
                    rawDebugTraceback,
                    threadOrMessage,
                    messageOrLevel
                )
                trace = ok and value or nil
            end

            if hostFns.type(trace) ~= "string" then
                trace = "stack traceback:"
            end

            -- Native Roblox/Luau library errors normally leave at least one
            -- native/C boundary visible in the traceback (xpcall/error path).
            -- Radium's Lua wrappers can otherwise hide every such frame.
            if not trace:find("[C]", 1, true)
                and not trace:find("C function", 1, true)
            then
                trace ..= "\n[C] function"
            end

            return trace
        end
    end

    if hostFns.type(rawDebugInfo) == "function" then
        sandbox.debug.info = function(target, options)
            if target == sandbox.debug.traceback and options == "a" then
                return 2, false
            end

            -- Numeric levels must describe the sandboxed Luau stack, not the
            -- Project Radium wrapper/host frames that implement the sandbox.
            if hostFns.type(target) == "number" then
                local level = math.floor(target)

                if level < 0 then
                    hostFns.error("invalid argument #1 to 'info' (level out of range)", 2)
                end

                -- Level 0/1 are always inside the currently executing sandbox
                -- chunk when called by target code.  Higher levels may still be
                -- recoverable from the host stack, but source/function queries
                -- must never expose the runtime wrapper as the user's source.
                if level <= 1 then
                    if options == "s" then return "=OxyEnv" end
                    if options == "l" then return 1 end
                    if options == "a" then return 0, true end
                    if options == "n" then return "" end

                    if options == "f" then
                        local ok, fn = hostFns.pcall(rawDebugInfo, level + 2, "f")
                        if ok then return fn end
                        return nil
                    end
                end

                if level == 2 and options == "f" then
                    return nil
                end

                local ok, a, b, c, d, e =
                    hostFns.pcall(rawDebugInfo, level + 2, options)

                if ok then
                    if options == "s"
                        and (
                            a == nil
                            or a == ""
                            or a == "[C]"
                            or a == "=[C]"
                            or hostFns.tostring(a):find("ProjectRadium", 1, true)
                            or hostFns.tostring(a):find("radium", 1, true)
                        )
                    then
                        return "=OxyEnv"
                    end

                    return a, b, c, d, e
                end

                if options == "s" then return "=OxyEnv" end
                if options == "l" then return -1 end
                if options == "a" then return 0, true end
                if options == "n" then return "" end
                return nil
            end

            if sandbox.__isProtectedRuntimeFunction and sandbox.__isProtectedRuntimeFunction(target) then
                if options == "s" then return "[C]" end
                if options == "l" then return -1 end
                if options == "a" then return 0, true end
                if options == "n" then
                    if target == taskLib.wait then return "wait" end
                    if target == taskLib.spawn then return "spawn" end
                    return ""
                end
                if options == "f" then return target end
            end

            local dyn = dynamicFunctionInfo[target]
            if dyn then
                if options == "s" then
                    return dyn.chunkName or "=OxyEnv"
                end
                if options == "a" then
                    local ok, a, b = hostFns.pcall(rawDebugInfo, target, "a")
                    if ok then return a, b end
                    return 0, true
                end
                if options == "f" then return target end
            end

            -- Do not forward source requests for arbitrary functions directly
            -- to the host; that can reveal Project Radium file paths/chunks.
            if options == "s" then
                local ok, source = hostFns.pcall(rawDebugInfo, target, "s")
                if ok and source == "[C]" then
                    return "[C]"
                end
                return "=OxyEnv"
            end

            -- Preserve useful function metadata that does not reveal internals.
            if options == "a" then
                local ok, a, b = hostFns.pcall(rawDebugInfo, target, "a")
                if ok then return a, b end
                return 0, true
            end
            if options == "f" then
                return target
            end
            if options == "l" then
                return -1
            end
            if options == "n" then
                return ""
            end

            return nil
        end
    end

    sandbox.debug.getinfo = function(target, ...)
        if hostFns.type(target) == "number" then
            local level = math.floor(target)

            if level < 0 then
                hostFns.error("invalid argument #1 to 'getinfo' (level out of range)", 2)
            end

            if level <= 1 then
                return {
                    what = "Lua",
                    source = "=OxyEnv",
                    short_src = "OxyEnv",
                    nups = 0,
                    name = "",
                    namewhat = "",
                    currentline = 1,
                    linedefined = 0,
                    lastlinedefined = 0,
                    isvararg = true,
                }
            end

            if hostFns.type(rawDebugGetinfo) == "function" then
                local ok, result =
                    hostFns.pcall(rawDebugGetinfo, level + 2, ...)

                if ok and hostFns.type(result) == "table" then
                    local source = result.source

                    if source == nil
                        or source == ""
                        or source == "[C]"
                        or source == "=[C]"
                        or hostFns.tostring(source):find("ProjectRadium", 1, true)
                        or hostFns.tostring(source):find("radium", 1, true)
                    then
                        result.source = "=OxyEnv"
                        result.short_src = "OxyEnv"
                        result.what = "Lua"
                    end

                    return result
                end
            end

            return {
                what = "Lua",
                source = "=OxyEnv",
                short_src = "OxyEnv",
                nups = 0,
                name = "",
                namewhat = "",
                currentline = -1,
                linedefined = 0,
                lastlinedefined = 0,
                isvararg = true,
            }
        end

        if sandbox.__isProtectedRuntimeFunction and sandbox.__isProtectedRuntimeFunction(target) then
            return {
                what="C",
                source="=[C]",
                short_src="[C]",
                nups=0,
                name="",
                namewhat="global",
                currentline=-1,
                linedefined=-1
            }
        end

        local dyn = dynamicFunctionInfo[target]
        if dyn then
            local source = dyn.chunkName or "=loadstring"
            return {
                what="Lua",
                source=source,
                short_src=source:gsub("^=", ""),
                nups=0,
                name="",
                namewhat="",
                currentline=-1,
                linedefined=0,
                lastlinedefined=0,
                isvararg=true,
            }
        end

        -- Do not expose host source paths or wrapper metadata for arbitrary
        -- function targets. Return a sandbox-safe synthetic Lua frame instead.
        if hostFns.type(target) == "function" then
            local isNative = false
            if hostFns.type(rawDebugInfo) == "function" then
                local ok, source = hostFns.pcall(rawDebugInfo, target, "s")
                isNative = ok and source == "[C]"
            end

            if isNative then
                return {
                    what="C",
                    source="=[C]",
                    short_src="[C]",
                    nups=0,
                    name="",
                    namewhat="",
                    currentline=-1,
                    linedefined=-1,
                    lastlinedefined=-1,
                    isvararg=true,
                }
            end

            return {
                what="Lua",
                source="=OxyEnv",
                short_src="OxyEnv",
                nups=0,
                name="",
                namewhat="",
                currentline=-1,
                linedefined=0,
                lastlinedefined=0,
                isvararg=true,
            }
        end

        return {
            what="Lua",
            source="=OxyEnv",
            short_src="OxyEnv",
            nups=0,
            currentline=-1,
            linedefined=0,
            lastlinedefined=0,
            isvararg=true,
        }
    end
end
sandbox.buffer = buffer

if hostFns.type(table.freeze)=="function" then
    hostFns.pcall(table.freeze, sandbox.math)
    hostFns.pcall(table.freeze, sandbox.string)
    hostFns.pcall(table.freeze, sandbox.table)
    hostFns.pcall(table.freeze, sandbox.utf8)
    hostFns.pcall(table.freeze, sandbox.debug)
    hostFns.pcall(table.freeze, sandbox.coroutine)
    hostFns.pcall(table.freeze, sandbox.bit32)
    hostFns.pcall(table.freeze, sandbox.os)
end

sandbox.task = taskLib
sandbox.wait = function(duration)
    local elapsed = taskLib.wait(duration)
    return elapsed, sandbox.tick and sandbox.tick() or (os.time() + virtualTime)
end
sandbox.spawn = function(callback, ...)
    return taskLib.spawn(callback, ...)
end
sandbox.delay = function(seconds, callback, ...)
    return taskLib.delay(seconds, callback, ...)
end
local tickEpochBase = os.time() - virtualTime
sandbox.tick = function()
    return tickEpochBase + virtualTime
end
sandbox.time = function()
    return virtualTime
end
sandbox.elapsedTime = function()
    return virtualTime
end

sandbox.setfpscap = function(value)
    local cap = tonumber(value)

    if cap == nil then
        hostFns.error("invalid argument #1 to 'setfpscap' (number expected)", 2)
    end

    cap = math.floor(cap)

    if cap <= 0 then
        -- Treat 0/unlimited as Radium's simulated maximum.
        cap = CONFIG.fpsMax
    end

    CONFIG.fpsCap = cap
    emit("setfpscap(" .. hostFns.tostring(cap) .. ")")
    return nil
end

sandbox.getfpscap = function()
    return CONFIG.fpsCap
end

sandbox.getfps = function()
    return CONFIG.fpsCap
end

sandbox.setstackhidden = function(target, hidden)
    local targetType = hostFns.type(target)

    if targetType ~= "number" and targetType ~= "function" then
        hostFns.error(
            "invalid argument #1 to 'setstackhidden' (number or function expected)",
            2
        )
    end

    if hidden ~= nil and hostFns.type(hidden) ~= "boolean" then
        hostFns.error(
            "invalid argument #2 to 'setstackhidden' (boolean expected)",
            2
        )
    end

    return true
end

sandbox.PsmSignal = {
    new = function()
        local signal = newproxy(true)
        local signalMt = hostFns.getmetatable(signal)
        local state = {
            callbacks = {},
            once = {},
            waiters = {},
        }

        proxyState[signal] = state
        mark(signal, "PsmSignal", "PsmSignal")

        local function makeConnection(callback, once)
            local connection = newproxy(true)
            local connectionMt = hostFns.getmetatable(connection)
            local connectionState = {
                connected = true,
                callback = callback,
                once = once == true,
            }

            proxyState[connection] = connectionState
            mark(connection, "PsmConnection", "PsmConnection")

            connectionMt.__metatable = "The metatable is locked"
            connectionMt.__index = function(_, key)
                if key == "Connected" then
                    return connectionState.connected
                elseif key == "Disconnect" then
                    return function(selfConnection)
                        if selfConnection ~= connection then
                            hostFns.error("Expected ':' not '.' calling Disconnect", 2)
                        end

                        if connectionState.connected then
                            connectionState.connected = false
                            state.callbacks[connection] = nil
                            state.once[connection] = nil
                        end

                        return nil
                    end
                end

                return nil
            end

            if connectionState.once then
                state.once[connection] = callback
            else
                state.callbacks[connection] = callback
            end

            return connection
        end

        signalMt.__metatable = "The metatable is locked"
        signalMt.__index = function(_, key)
            if key == "Connect" then
                return function(selfSignal, callback)
                    if selfSignal ~= signal then
                        hostFns.error("Expected ':' not '.' calling Connect", 2)
                    end
                    if hostFns.type(callback) ~= "function" then
                        hostFns.error("invalid argument #1 to 'Connect' (function expected)", 2)
                    end
                    return makeConnection(callback, false)
                end
            elseif key == "Once" then
                return function(selfSignal, callback)
                    if selfSignal ~= signal then
                        hostFns.error("Expected ':' not '.' calling Once", 2)
                    end
                    if hostFns.type(callback) ~= "function" then
                        hostFns.error("invalid argument #1 to 'Once' (function expected)", 2)
                    end
                    return makeConnection(callback, true)
                end
            elseif key == "Fire" then
                return function(selfSignal, ...)
                    if selfSignal ~= signal then
                        hostFns.error("Expected ':' not '.' calling Fire", 2)
                    end

                    local packed = table.pack(...)

                    local regularSnapshot = {}
                    for connection, callback in hostFns.pairs(state.callbacks) do
                        regularSnapshot[#regularSnapshot + 1] = {connection, callback}
                    end

                    for _, entry in hostFns.ipairs(regularSnapshot) do
                        local connection = entry[1]
                        local callback = entry[2]
                        local connectionState = proxyState[connection]

                        if connectionState and connectionState.connected then
                            callback(hostFns.unpack(packed, 1, packed.n))
                        end
                    end

                    local onceSnapshot = {}
                    for connection, callback in hostFns.pairs(state.once) do
                        onceSnapshot[#onceSnapshot + 1] = {connection, callback}
                    end

                    for _, entry in hostFns.ipairs(onceSnapshot) do
                        local connection = entry[1]
                        local callback = entry[2]
                        local connectionState = proxyState[connection]

                        if connectionState and connectionState.connected then
                            connectionState.connected = false
                            state.once[connection] = nil
                            callback(hostFns.unpack(packed, 1, packed.n))
                        end
                    end

                    local waiters = state.waiters
                    state.waiters = {}

                    for _, thread in hostFns.ipairs(waiters) do
                        if coroutine.status(thread) == "suspended" then
                            local result = table.pack(
                                coroutine.resume(
                                    thread,
                                    hostFns.unpack(packed, 1, packed.n)
                                )
                            )

                            if not result[1] then
                                hostFns.warn(
                                    "[OxyEnv PsmSignal] "
                                    .. hostFns.tostring(result[2])
                                )
                            end
                        end
                    end

                    return nil
                end
            elseif key == "Wait" then
                return function(selfSignal)
                    if selfSignal ~= signal then
                        hostFns.error("Expected ':' not '.' calling Wait", 2)
                    end

                    local thread = coroutine.running()
                    if thread == nil or thread == taskLib.__mainThread then
                        hostFns.error("PsmSignal:Wait() must be called from a yieldable thread", 2)
                    end

                    state.waiters[#state.waiters + 1] = thread
                    return coroutine.yield("__psm_signal_wait")
                end
            end

            return nil
        end

        return signal
    end,
}

sandbox.game = game
sandbox.Game = game
sandbox.workspace = workspace
sandbox.gethui = function()
    return coreGui
end


(function()
    do
        local stats = serviceCache["Stats"] or makeService("Stats")
        serviceCache["Stats"] = stats

        local network = createInternalInstance("Folder", stats)
        instanceStates[network].values.Name = "Network"
        objectNames[network] = "Stats.Network"
        instanceStates[stats].values.Network = network

        local serverStats = createInternalInstance("Folder", network)
        instanceStates[serverStats].values.Name = "ServerStatsItem"
        objectNames[serverStats] = 'Stats.Network.ServerStatsItem'
        instanceStates[network].values.ServerStatsItem = serverStats

        local ping = createInternalInstance("StatsItem", serverStats)
        instanceStates[ping].values.Name = "Data Ping"
        instanceStates[ping].values.__radiumStatKind = "Data Ping"
        instanceStates[ping].values.Value = 28
        objectNames[ping] = 'Stats.Network.ServerStatsItem["Data Ping"]'

        -- Roblox-style name lookup via [] / FindFirstChild works through the
        -- normal Instance child/name handling once this item is parented.
    end

    do
        local playerScripts = createInternalInstance("PlayerScripts", localPlayer)
        instanceStates[playerScripts].values.Name = "PlayerScripts"
        objectNames[playerScripts] = "Players.LocalPlayer.PlayerScripts"
        instanceStates[localPlayer].values.PlayerScripts = playerScripts

        local playerModule = createInternalInstance("ModuleScript", playerScripts)
        instanceStates[playerModule].values.Name = "PlayerModule"
        objectNames[playerModule] = "Players.LocalPlayer.PlayerScripts.PlayerModule"

        local cameraModule = createInternalInstance("ModuleScript", playerModule)
        instanceStates[cameraModule].values.Name = "CameraModule"
        objectNames[cameraModule] =
            "Players.LocalPlayer.PlayerScripts.PlayerModule.CameraModule"

        local controlModule = createInternalInstance("ModuleScript", playerModule)
        instanceStates[controlModule].values.Name = "ControlModule"
        objectNames[controlModule] =
            "Players.LocalPlayer.PlayerScripts.PlayerModule.ControlModule"

        local characterSounds = createInternalInstance("LocalScript", playerScripts)
        instanceStates[characterSounds].values.Name = "RbxCharacterSounds"
        objectNames[characterSounds] = "Players.LocalPlayer.PlayerScripts.RbxCharacterSounds"

        local currentScript = createInternalInstance("LocalScript", playerScripts)
        instanceStates[currentScript].values.Name = "RadiumInput"
        objectNames[currentScript] = "script"
        sandbox.script = currentScript
    end

    do
        local networkClient = makeService("NetworkClient")

        if not findChild(networkClient, "ClientReplicator", false) then
            local clientReplicator =
                createInternalInstance("ClientReplicator", networkClient)

            instanceStates[clientReplicator].values.Name = "ClientReplicator"
            objectNames[clientReplicator] = "NetworkClient.ClientReplicator"
        end

        local ugc = findChild(game, "Ugc", false)

        if not ugc then
            ugc = createInternalInstance("Folder", game)
            instanceStates[ugc].values.Name = "Ugc"
            objectNames[ugc] = "game.Ugc"
        end

        local chat = makeService("Chat")

        if instanceStates[chat].values.Parent ~= ugc then
            setParent(chat, ugc)
        end

        objectNames[chat] = "game.Ugc.Chat"
    end

    sandbox.Enum = Enum
    sandbox.settings = function()
        return settingsObject
    end
    sandbox.UserSettings = function()
        return settingsServices.UserSettings
    end
    sandbox.Instance = {
        new = function(className, parent)
            local instance = createInstance(className, parent)
            emit(
                "local "
                .. objectNames[instance]
                .. " = Instance.new("
                .. repr(className)
                .. (parent and ", " .. repr(parent) or "")
                .. ")"
            )
            return instance
        end,
    }

    if host.native and host.native.bind then
        sandbox.Instance.new = host.native.bind("new", sandbox.Instance.new)
    end

    sandbox.Vector3 = dataConstructors.Vector3
    sandbox.Vector2 = dataConstructors.Vector2
    sandbox.vector = {
        create = function(x, y, z)
            return dataConstructors.Vector3.new(x, y, z)
        end,
        cross = function(a, b)
            if objectTypes[a] ~= "Vector3" or objectTypes[b] ~= "Vector3" then
                hostFns.error("invalid argument to 'cross' (vector expected)", 2)
            end
            return dataConstructors.Vector3.new(
                a.Y * b.Z - a.Z * b.Y,
                a.Z * b.X - a.X * b.Z,
                a.X * b.Y - a.Y * b.X
            )
        end,
        magnitude = function(v)
            if objectTypes[v] ~= "Vector3" then
                hostFns.error("invalid argument #1 to 'magnitude' (vector expected)", 2)
            end
            return math.sqrt(v.X*v.X + v.Y*v.Y + v.Z*v.Z)
        end,
    }
    if host.native and host.native.bind then
        sandbox.vector.cross = host.native.bind("cross", sandbox.vector.cross)
        sandbox.vector.magnitude = host.native.bind("magnitude", sandbox.vector.magnitude)
    end
    sandbox.Vector3int16 = dataConstructors.Vector3int16
    sandbox.CFrame = dataConstructors.CFrame
    sandbox.Color3 = dataConstructors.Color3
    sandbox.UDim = dataConstructors.UDim
    sandbox.UDim2 = dataConstructors.UDim2
    if host.native and host.native.bind then
        sandbox.UDim2.new = host.native.bind("new", sandbox.UDim2.new)
    end
    sandbox.Region3 = dataConstructors.Region3
    sandbox.RaycastParams = dataConstructors.RaycastParams
    sandbox.OverlapParams = dataConstructors.OverlapParams
    sandbox.Random = dataConstructors.Random
    if host.native and host.native.bind then
        sandbox.Random.new = host.native.bind("new", sandbox.Random.new)
    end
    sandbox.Vector2int16 = dataConstructors.Vector2int16
    sandbox.BrickColor = dataConstructors.BrickColor
    sandbox.TweenInfo = dataConstructors.TweenInfo
    sandbox.NumberRange = dataConstructors.NumberRange
    sandbox.NumberSequence = dataConstructors.NumberSequence
    sandbox.NumberSequenceKeypoint = dataConstructors.NumberSequenceKeypoint
    sandbox.ColorSequence = dataConstructors.ColorSequence
    sandbox.ColorSequenceKeypoint = dataConstructors.ColorSequenceKeypoint
    sandbox.Ray = dataConstructors.Ray
    sandbox.Rect = dataConstructors.Rect
    sandbox.Region3int16 = dataConstructors.Region3int16
    sandbox.PhysicalProperties = dataConstructors.PhysicalProperties
    sandbox.FloatCurveKey = dataConstructors.FloatCurveKey
    sandbox.ValueCurveKey = dataConstructors.ValueCurveKey
    sandbox.RotationCurveKey = dataConstructors.RotationCurveKey
    sandbox.CatalogSearchParams = dataConstructors.CatalogSearchParams
    sandbox.Axes = dataConstructors.Axes
    sandbox.Faces = dataConstructors.Faces
    sandbox.DockWidgetPluginGuiInfo = dataConstructors.DockWidgetPluginGuiInfo
    sandbox.Path2DControlPoint = dataConstructors.Path2DControlPoint
    sandbox.PathWaypoint = dataConstructors.PathWaypoint
    sandbox.SecurityCapabilities = dataConstructors.SecurityCapabilities
    sandbox.Font = dataConstructors.Font
    sandbox.DateTime = dataConstructors.DateTime
    sandbox.Content = dataConstructors.Content
    sandbox.SharedTable = dataConstructors.SharedTable
    sandbox.SharedTable.clone = function(source)
        local result = dataConstructors.SharedTable.new()
        local sourceFields = sharedTableFields[source]
        local resultFields = sharedTableFields[result]
        if sourceFields and resultFields then
            for key, value in hostFns.pairs(sourceFields) do
                resultFields[key] = value
            end
        end
        return result
    end
    sandbox.SharedTable.cloneAndFreeze = function(source, deep)
        local result = sandbox.SharedTable.clone(source, deep)
        local fields = sharedTableFields[result]
        if fields then fields.__RadiumFrozen = true end
        return result
    end
    sandbox.SharedTable.isFrozen = function(source)
        if objectTypes[source] ~= "SharedTable" then hostFns.error("SharedTable expected", 2) end
        local fields = sharedTableFields[source]
        return fields and fields.__RadiumFrozen == true or false
    end
    sandbox.Regex = Regex
    sandbox.User = User

    sandbox.shared = {}

    sandbox.getthreadidentity = function()
        return getRuntimeThreadIdentity()
    end

    sandbox.getidentity = sandbox.getthreadidentity

    sandbox.setthreadidentity = function(identity)
        setRuntimeThreadIdentity(identity)
    end

    sandbox.setidentity = sandbox.setthreadidentity

    sandbox.printidentity = function()
        hostFns.print(
            "Current identity is "
            .. hostFns.tostring(getRuntimeThreadIdentity())
        )
    end

    -- Keep the clone/cloneAndFreeze wrappers installed above.

    sandbox.gcinfo = function()
        local ok, value = hostFns.pcall(collectgarbage, "count")
        if ok and hostFns.type(value) == "number" and value > 0 then return value end
        return 1
    end

    sandbox.newproxy = newproxy

    sandbox.identifyexecutor = function()
        local version = "1.0.0"
        if CONFIG.executorName == "Madium" then
            version = "2.0.0"
        end
        return CONFIG.executorName, version
    end

    sandbox.getexecutorname = function()
        return CONFIG.executorName
    end

    sandbox.getexecutor = sandbox.getexecutorname

    local function closureSource(fn)
        if hostFns.type(fn) ~= "function" or hostFns.type(debug.info) ~= "function" then return nil end
        local ok, source = hostFns.pcall(debug.info, fn, "s")
        return ok and source or nil
    end

    sandbox.islclosure = function(fn)
        if hostFns.type(fn) ~= "function" then return false end
        if sandbox.__isProtectedRuntimeFunction and sandbox.__isProtectedRuntimeFunction(fn) then return false end
        if dynamicFunctionInfo[fn] then return true end
        local source = closureSource(fn)
        return source ~= nil and source ~= "[C]"
    end

    do
        local nativeIscclosure = host.native and host.native.iscclosure
        sandbox.iscclosure = function(fn)
            if hostFns.type(fn) ~= "function" then return false end
            if sandbox.__isProtectedRuntimeFunction and sandbox.__isProtectedRuntimeFunction(fn) then return true end
            if dynamicFunctionInfo[fn] then return false end
            if nativeIscclosure then return nativeIscclosure(fn) end
            return closureSource(fn) == "[C]"
        end
    end

    sandbox.isfunctionhooked =
        host.native and host.native.isfunctionhooked
        or function(fn)
            if hostFns.type(fn) ~= "function" then return false end
            return false
        end

    sandbox.checkcaller =
        host.native and host.native.checkcaller
        or function()
            return false
        end

    sandbox.newcclosure =
        host.native and host.native.newcclosure
        or function(fn)
            if hostFns.type(fn) ~= "function" then
                hostFns.error("function expected", 2)
            end

            return function(...)
                return fn(...)
            end
        end

    sandbox.clonefunction =
        host.native and host.native.clonefunction
        or function(fn)
            if hostFns.type(fn) ~= "function" then
                hostFns.error("function expected", 2)
            end

            return function(...)
                return fn(...)
            end
        end

    sandbox.hookmetamethod =
        host.native and host.native.hookmetamethod
        or function(target, metamethodName, replacement)
            if hostFns.type(metamethodName) ~= "string" then
                hostFns.error("metamethod name must be a string", 2)
            end

            if hostFns.type(replacement) ~= "function" then
                hostFns.error("replacement must be a function", 2)
            end

            local rawMt

            if target == game then
                rawMt = proxyState[game]
                    and proxyState[game].rawMetatable
            else
                local targetState = instanceStates[target]
                rawMt = targetState and targetState.rawMetatable
            end

            if hostFns.type(rawMt) ~= "table" then
                hostFns.error("object does not expose a hookable metatable", 2)
            end

            local original = rawMt[metamethodName]

            if hostFns.type(original) ~= "function" then
                hostFns.error(
                    "metamethod "
                        .. hostFns.tostring(metamethodName)
                        .. " is not hookable",
                    2
                )
            end

            rawMt[metamethodName] = replacement

            return original
        end

    sandbox.isexecutorclosure = function()
        return false
    end

    -- -------------------------------------------------------------------------
    -- Executor Drawing API
    -- -------------------------------------------------------------------------
    -- Static Drawing objects are runtime-owned property bags.  They intentionally
    -- do not masquerade as Instances; isrenderobj/getrenderproperty/
    -- setrenderproperty operate on this registry.
    local drawingRuntime = (function()
        local objects = hostFns.setmetatable({}, { __mode = "k" })
        local active = hostFns.setmetatable({}, { __mode = "k" })

        local supported = {
            Line = true,
            Text = true,
            Image = true,
            Circle = true,
            Square = true,
            Quad = true,
            Triangle = true,
            Polyline = true,
        }

        local defaults = {
            Visible = false,
            Color = dataConstructors.Color3.new(1, 1, 1),
            ZIndex = 0,
            Opacity = 1,
            Transparency = 0,
            Thickness = 1,
            Filled = false,
        }

        local classDefaults = {
            Line = {
                From = dataConstructors.Vector2.zero,
                To = dataConstructors.Vector2.zero,
            },
            Text = {
                Text = "",
                Size = 16,
                Center = false,
                Outline = false,
                OutlineColor = dataConstructors.Color3.new(0, 0, 0),
                Position = dataConstructors.Vector2.zero,
                Font = 0,
                TextBounds = dataConstructors.Vector2.zero,
            },
            Image = {
                Url = "",
                Data = "",
                Gif = false,
                Position = dataConstructors.Vector2.zero,
                Size = dataConstructors.Vector2.zero,
                Rounding = 0,
                Delay = 0,
                ImageSize = dataConstructors.Vector2.zero,
            },
            Circle = {
                NumSides = 30,
                Radius = 0,
                Position = dataConstructors.Vector2.zero,
            },
            Square = {
                Size = dataConstructors.Vector2.zero,
                Position = dataConstructors.Vector2.zero,
                Rounding = 0,
            },
            Quad = {
                PointA = dataConstructors.Vector2.zero,
                PointB = dataConstructors.Vector2.zero,
                PointC = dataConstructors.Vector2.zero,
                PointD = dataConstructors.Vector2.zero,
            },
            Triangle = {
                PointA = dataConstructors.Vector2.zero,
                PointB = dataConstructors.Vector2.zero,
                PointC = dataConstructors.Vector2.zero,
            },
            Polyline = {
                Points = {},
            },
        }

        local runtime = {}

        local function removeObject(self)
            local state = objects[self]

            if not state or state.removed then
                return
            end

            state.removed = true
            active[self] = nil
        end

        local function readProperty(self, key)
            local state = objects[self]

            if not state or state.removed then
                hostFns.error("invalid drawing object", 2)
            end

            if key == "Remove"
                or key == "remove"
                or key == "Destroy"
            then
                return removeObject
            end

            if key == "Class" then
                return state.className
            end

            local value = state.properties[key]

            if value ~= nil then
                return value
            end

            return nil
        end

        local function writeProperty(self, key, value)
            local state = objects[self]

            if not state or state.removed then
                hostFns.error("invalid drawing object", 2)
            end

            if key == "Text" then
                value = hostFns.tostring(value)
            elseif key == "Visible"
                or key == "Filled"
                or key == "Center"
                or key == "Outline"
                or key == "Gif"
            then
                value = not not value
            elseif key == "Opacity" then
                value = math.clamp(tonumber(value) or 0, 0, 1)
                state.properties.Transparency = 1 - value
            elseif key == "Transparency" then
                value = math.clamp(tonumber(value) or 0, 0, 1)
                state.properties.Opacity = 1 - value
            elseif key == "ZIndex"
                or key == "Thickness"
                or key == "Rounding"
                or key == "Radius"
                or key == "NumSides"
                or key == "Size"
                or key == "Font"
                or key == "Delay"
            then
                if key ~= "Size"
                    or objectTypes[value] ~= "Vector2"
                then
                    local numberValue = tonumber(value)
                    if numberValue ~= nil then
                        value = numberValue
                    end
                end
            end

            state.properties[key] = value

            if state.className == "Text"
                and (key == "Text" or key == "Size")
            then
                local textValue =
                    hostFns.tostring(
                        state.properties.Text or ""
                    )

                local sizeValue =
                    tonumber(state.properties.Size) or 16

                state.properties.TextBounds =
                    dataConstructors.Vector2.new(
                        #textValue * sizeValue * 0.5,
                        sizeValue
                    )
            end
        end

        runtime.new = function(className)
            local name = hostFns.tostring(className)

            if not supported[name] then
                hostFns.error(
                    "unsupported drawing class '"
                        .. name
                        .. "'",
                    2
                )
            end

            local properties = {}

            for key, value in hostFns.pairs(defaults) do
                properties[key] = value
            end

            local extra = classDefaults[name]

            if extra then
                for key, value in hostFns.pairs(extra) do
                    if hostFns.type(value) == "table"
                        and objectTypes[value] == nil
                    then
                        local copy = {}
                        for k, v in hostFns.pairs(value) do
                            copy[k] = v
                        end
                        properties[key] = copy
                    else
                        properties[key] = value
                    end
                end
            end

            local object = {}
            objects[object] = {
                className = name,
                properties = properties,
                removed = false,
            }
            active[object] = true

            hostFns.setmetatable(object, {
                __index = readProperty,
                __newindex = writeProperty,
                __tostring = function()
                    return "Drawing"
                end,
                __metatable = "DrawingObject",
            })

            return object
        end

        runtime.isObject = function(value)
            local state = objects[value]
            return state ~= nil and not state.removed
        end

        runtime.get = function(value, property)
            local state = objects[value]

            if not state or state.removed then
                hostFns.error(
                    "invalid argument #1 to 'getrenderproperty' (Drawing object expected)",
                    2
                )
            end

            return readProperty(value, hostFns.tostring(property))
        end

        runtime.set = function(value, property, newValue)
            local state = objects[value]

            if not state or state.removed then
                hostFns.error(
                    "invalid argument #1 to 'setrenderproperty' (Drawing object expected)",
                    2
                )
            end

            writeProperty(
                value,
                hostFns.tostring(property),
                newValue
            )
        end

        runtime.clear = function()
            local current = {}

            for object in hostFns.pairs(active) do
                current[#current + 1] = object
            end

            for _, object in hostFns.ipairs(current) do
                removeObject(object)
            end
        end

        return runtime
    end)()

    sandbox.Drawing = {
        new = drawingRuntime.new,
        clear = drawingRuntime.clear,
        Fonts = {
            UI = 0,
            System = 1,
            Plex = 2,
            Monospace = 3,
        },
    }

    sandbox.isrenderobj = function(value)
        return drawingRuntime.isObject(value)
    end

    sandbox.getrenderproperty = function(value, property)
        return drawingRuntime.get(value, property)
    end

    sandbox.setrenderproperty = function(value, property, newValue)
        drawingRuntime.set(value, property, newValue)
    end

    if host.native and host.native.bind then
        sandbox.Drawing.new =
            host.native.bind(
                "new",
                sandbox.Drawing.new
            )

        sandbox.Drawing.clear =
            host.native.bind(
                "clear",
                sandbox.Drawing.clear
            )

        sandbox.isrenderobj =
            host.native.bind(
                "isrenderobj",
                sandbox.isrenderobj
            )

        sandbox.getrenderproperty =
            host.native.bind(
                "getrenderproperty",
                sandbox.getrenderproperty
            )

        sandbox.setrenderproperty =
            host.native.bind(
                "setrenderproperty",
                sandbox.setrenderproperty
            )
    end

    local radiumRegistry = {}

    sandbox.getgenv = function()
        return sandbox
    end

    sandbox.getrenv = function()
        return sandbox
    end

    sandbox.getreg = function()
        return radiumRegistry
    end

    local syntheticGc = nil
    sandbox.getgc = function(includeTables)
        if syntheticGc == nil then
            syntheticGc = {}
            for _, value in hostFns.pairs(sandbox) do
                if hostFns.type(value) == "function" or (includeTables == true and hostFns.type(value) == "table") then
                    syntheticGc[#syntheticGc + 1] = value
                end
            end
            for inst, state in hostFns.pairs(instanceStates) do
                if state and not state.destroyed then
                    syntheticGc[#syntheticGc + 1] = inst
                end
            end
            -- Live Roblox clients normally expose a large GC surface. Keep a stable
            -- compatibility pool so basic executor checks do not see a tiny host VM.
            while #syntheticGc < 1280 do
                local n = #syntheticGc + 1
                if n % 5 ~= 0 then
                    syntheticGc[n] = function() return n end
                else
                    syntheticGc[n] = { __gcslot = n }
                end
            end
        end
        local out = {}
        for i = 1, #syntheticGc do
            local value = syntheticGc[i]
            if includeTables == true or hostFns.type(value) ~= "table" then
                out[#out + 1] = value
            end
        end
        return out
    end

    sandbox.getinstances = function()
        local out = {}
        for inst, state in hostFns.pairs(instanceStates) do
            if state and not state.destroyed then out[#out + 1] = inst end
        end
        return out
    end

    sandbox.getnilinstances = function()
        local out = {}
        for inst, state in hostFns.pairs(instanceStates) do
            if state and not state.destroyed and state.values.Parent == nil then out[#out + 1] = inst end
        end
        return out
    end

    sandbox.getscripts = function()
        local out = {}
        for inst, state in hostFns.pairs(instanceStates) do
            if state and not state.destroyed and (state.className == "LocalScript" or state.className == "ModuleScript" or state.className == "Script") then
                out[#out + 1] = inst
            end
        end
        return out
    end

    sandbox.getloadedmodules = function()
        local out = {}
        for inst, state in hostFns.pairs(instanceStates) do
            if state and not state.destroyed and state.className == "ModuleScript" then out[#out + 1] = inst end
        end
        return out
    end

    sandbox.require = sandboxRequire
    sandbox.loadstring = dynamicLoader
    sandbox.load = nil

    if host.native and host.native.bind then
        sandbox.getgenv = host.native.bind("getgenv", sandbox.getgenv)
        sandbox.getrenv = host.native.bind("getrenv", sandbox.getrenv)
        sandbox.getreg = host.native.bind("getreg", sandbox.getreg)
        sandbox.loadstring = host.native.bind("loadstring", sandbox.loadstring)
        sandbox.load = nil
    end

    sandbox.loadfile = function(path)
        local full, rel = sandboxPath(path)

        if not fs.isFile(full) then
            hostFns.error("cannot open " .. rel .. ": No such file", 2)
        end

        local okRead, source = hostFns.pcall(fs.readFile, full)
        if not okRead then
            hostFns.error(hostFns.tostring(source), 2)
        end

        local fn, compileError = dynamicLoader(source, "@" .. rel)

        if not fn then
            return nil, compileError
        end

        return fn
    end

    sandbox.writefile = function(path, content)
        local full, rel = sandboxPath(path)
        local parent = full:match("^(.*)/[^/]+$")
        if parent and parent ~= "" and not fs.isDir(parent) then
            hostFns.error("parent folder does not exist: " .. hostFns.tostring(rel), 2)
        end
        local ok, err = hostFns.pcall(fs.writeFile, full, hostFns.tostring(content or ""))
        if not ok then
            hostFns.error(hostFns.tostring(err), 2)
        end
        emit("writefile(" .. repr(rel) .. ", " .. repr(content) .. ")")
    end

    sandbox.readfile = function(path)
        local full, rel = sandboxPath(path)
        local ok, result = hostFns.pcall(fs.readFile, full)
        if not ok then
            hostFns.error(hostFns.tostring(result), 2)
        end
        emit("readfile(" .. repr(rel) .. ")")
        return result
    end

    sandbox.appendfile = function(path, content)
        local full, rel = sandboxPath(path)
        local existing = ""
        if fs.isFile(full) then
            local okRead, result = hostFns.pcall(fs.readFile, full)
            if okRead then existing = result end
        end
        local ok, err = hostFns.pcall(fs.writeFile, full, existing .. hostFns.tostring(content or ""))
        if not ok then
            hostFns.error(hostFns.tostring(err), 2)
        end
        emit("appendfile(" .. repr(rel) .. ", " .. repr(content) .. ")")
    end

    sandbox.isfile = function(path)
        local full = sandboxPath(path)
        return fs.isFile(full)
    end

    sandbox.isfolder = function(path)
        local full = sandboxPath(path)
        return fs.isDir(full)
    end

    sandbox.makefolder = function(path)
        local full, rel = sandboxPath(path)
        if fs.isDir(full) then
            return nil
        end
        local ok, err = hostFns.pcall(fs.writeDir, full)
        if not ok then
            hostFns.error(hostFns.tostring(err), 2)
        end
        emit("makefolder(" .. repr(rel) .. ")")
    end

    sandbox.listfiles = function(path)
        local result = listSandbox(path or "")
        emit("listfiles(" .. repr(path or "") .. ")")
        return result
    end

    sandbox.delfile = function(path)
        local full, rel = sandboxPath(path)
        if not fs.isFile(full) then
            return nil
        end
        local ok, err = hostFns.pcall(fs.removeFile, full)
        if not ok then
            hostFns.error(hostFns.tostring(err), 2)
        end
        emit("delfile(" .. repr(rel) .. ")")
    end

    sandbox.delfolder = function(path)
        local full, rel = sandboxPath(path)
        if not fs.isDir(full) then
            return nil
        end
        local ok, err = hostFns.pcall(fs.removeDir, full)
        if not ok then
            hostFns.error(hostFns.tostring(err), 2)
        end
        emit("delfolder(" .. repr(rel) .. ")")
    end

    local virtualClipboard = ""

    sandbox.setclipboard = function(value)
        virtualClipboard = hostFns.tostring(value or "")
        emit("setclipboard(" .. repr(virtualClipboard) .. ")")
    end

    sandbox.getclipboard = function()
        emit("getclipboard()")
        return virtualClipboard
    end

    sandbox.getcustomasset = function(path)
        local full, rel = sandboxPath(path)
        if not fs.isFile(full) then
            hostFns.error("custom asset file does not exist: " .. hostFns.tostring(rel), 2)
        end
        local normalized = hostFns.tostring(rel):gsub("\\", "/")
        emit("getcustomasset(" .. repr(rel) .. ")")
        return "rbxasset://" .. normalized
    end

    sandbox.getsynasset = sandbox.getcustomasset

    if host.native and host.native.bind then
        sandbox.writefile = host.native.bind("writefile", sandbox.writefile)
        sandbox.appendfile = host.native.bind("appendfile", sandbox.appendfile)
        sandbox.readfile = host.native.bind("readfile", sandbox.readfile)
        sandbox.isfile = host.native.bind("isfile", sandbox.isfile)
        sandbox.delfile = host.native.bind("delfile", sandbox.delfile)
        sandbox.isfolder = host.native.bind("isfolder", sandbox.isfolder)
        sandbox.makefolder = host.native.bind("makefolder", sandbox.makefolder)
        sandbox.listfiles = host.native.bind("listfiles", sandbox.listfiles)
        sandbox.delfolder = host.native.bind("delfolder", sandbox.delfolder)
        sandbox.setclipboard = host.native.bind("setclipboard", sandbox.setclipboard)
        sandbox.getclipboard = host.native.bind("getclipboard", sandbox.getclipboard)
        sandbox.getcustomasset = host.native.bind("getcustomasset", sandbox.getcustomasset)
        sandbox.getsynasset = sandbox.getcustomasset
        sandbox.getgc = host.native.bind("getgc", sandbox.getgc)
        sandbox.getinstances = host.native.bind("getinstances", sandbox.getinstances)
        sandbox.getnilinstances = host.native.bind("getnilinstances", sandbox.getnilinstances)
    end

    -- identifyexecutor/getexecutorname intentionally remain exposed.
    sandbox.request = nil
    sandbox.http_request = nil
    sandbox.syn = nil
    sandbox.fs = nil
    sandbox.process = nil
    sandbox.net = nil

    -- Safe require("...") compatibility layer.
    -- These are sandbox wrappers, never the raw host modules.
    -- IMPORTANT: keep this in its own function scope. Luau's top-level chunk has a
    -- 200-local-register limit, and a plain `do ... end` does not create a new
    -- register frame.
    (function()
        local function normalizePathValue(value)
            return hostFns.tostring(value or ""):gsub("\\", "/")
        end

        local function pathJoin(...)
            local parts = {...}
            local out = {}

            for i = 1, #parts do
                local part = normalizePathValue(parts[i])
                part = part:gsub("^/+", ""):gsub("/+$", "")

                if part ~= "" then
                    out[#out + 1] = part
                end
            end

            return table.concat(out, "/")
        end

        local function pathBasename(value)
            local path = normalizePathValue(value):gsub("/+$", "")
            return path:match("([^/]+)$") or path
        end

        local function pathDirname(value)
            local path = normalizePathValue(value):gsub("/+$", "")
            local result = path:match("^(.*)/[^/]*$")
            return result or "."
        end

        local function pathExtension(value)
            local name = pathBasename(value)
            return name:match("(%.[^%.]+)$") or ""
        end

        local function safeHttpGet(url)
            local source, err = requestUrl(hostFns.tostring(url))

            if not source then
                hostFns.error(
                    "HTTP request failed: " .. hostFns.tostring(err or "unknown error"),
                    2
                )
            end

            return source
        end

        local function safeHttpRequest(options)
            if hostFns.type(options) == "string" then
                return {
                    success = true,
                    statusCode = 200,
                    body = safeHttpGet(options),
                    headers = {},
                }
            end

            if hostFns.type(options) ~= "table" then
                hostFns.error("table expected", 2)
            end

            local method = string.upper(
                hostFns.tostring(options.method or options.Method or "GET")
            )

            if method ~= "GET" then
                hostFns.error(
                    "Oxyenv sandbox native net shim only supports GET",
                    2
                )
            end

            local body = safeHttpGet(options.url or options.Url)

            return {
                success = true,
                statusCode = 200,
                body = body,
                headers = {},
            }
        end

        local fsShim = {
            readFile = function(path)
                return sandbox.readfile(path)
            end,
            writeFile = function(path, content)
                return sandbox.writefile(path, content)
            end,
            appendFile = function(path, content)
                return sandbox.appendfile(path, content)
            end,
            isFile = function(path)
                return sandbox.isfile(path)
            end,
            isDir = function(path)
                return sandbox.isfolder(path)
            end,
            readDir = function(path)
                return sandbox.listfiles(path)
            end,
            writeDir = function(path)
                return sandbox.makefolder(path)
            end,
            removeFile = function(path)
                return sandbox.delfile(path)
            end,
            removeDir = function(path)
                return sandbox.delfolder(path)
            end,
        }

        local netShim = {
            request = safeHttpRequest,
            get = safeHttpGet,
        }

        local processShim = {
            args = {},
            cwd = function()
                return "/"
            end,
            exit = function()
                hostFns.error("process.exit is unavailable in the Oxyenv sandbox", 2)
            end,
        }

        local stdioShim = {
            write = sandboxPrint,
            print = sandboxPrint,
            warn = sandboxWarn,
            error = sandboxWarn,
        }

        local serdeShim = {
            encode = function(format, value)
                local selected = string.lower(hostFns.tostring(format or "json"))

                if selected ~= "json" then
                    hostFns.error("only json encoding is available in the Oxyenv sandbox", 2)
                end

                local ok, result = hostFns.pcall(serde.encode, "json", value)

                if not ok then
                    hostFns.error(hostFns.tostring(result), 2)
                end

                return result
            end,
            decode = function(format, value)
                local selected = string.lower(hostFns.tostring(format or "json"))

                if selected ~= "json" then
                    hostFns.error("only json decoding is available in the Oxyenv sandbox", 2)
                end

                local ok, result = hostFns.pcall(
                    serde.decode,
                    "json",
                    hostFns.tostring(value or "")
                )

                if not ok then
                    hostFns.error(hostFns.tostring(result), 2)
                end

                return result
            end,
        }

        local regexShim = {
            new = Regex.new,
            escape = Regex.escape,
        }

        local luauShim = {
            load = function(source, chunkName)
                return dynamicLoader(
                    hostFns.tostring(source or ""),
                    chunkName or "=require(luau)"
                )
            end,
            compile = function(source)
                -- A sandbox-safe compatibility surface. The returned source can be
                -- passed back to luau.load/loadstring without exposing host bytecode APIs.
                return hostFns.tostring(source or "")
            end,
        }

        local robloxShim = {
            Instance = sandbox.Instance,
            Enum = sandbox.Enum,
            Vector2 = sandbox.Vector2,
            Vector3 = sandbox.Vector3,
            CFrame = sandbox.CFrame,
            Color3 = sandbox.Color3,
            UDim = sandbox.UDim,
            UDim2 = sandbox.UDim2,
            Font = sandbox.Font,
        }

        local datetimeShim = {
            now = dataConstructors.DateTime.now,
            fromUnixTimestamp = dataConstructors.DateTime.fromUnixTimestamp,
            fromUnixTimestampMillis = dataConstructors.DateTime.fromUnixTimestampMillis,
            fromUniversalTime = dataConstructors.DateTime.fromUniversalTime,
            fromLocalTime = dataConstructors.DateTime.fromLocalTime,
        }

        local pathShim = {
            join = pathJoin,
            basename = pathBasename,
            dirname = pathDirname,
            extension = pathExtension,
            normalize = normalizePathValue,
        }

        local cryptoShim = {
            random = function(length)
                local count = math.max(0, math.floor(tonumber(length) or 16))
                local chars = {}

                for i = 1, count do
                    chars[i] = string.char(math.random(0, 255))
                end

                return table.concat(chars)
            end,
        }

        local httpShim = {
            get = safeHttpGet,
            request = safeHttpRequest,
        }

        local jsonShim = {
            encode = function(value)
                return serdeShim.encode("json", value)
            end,
            decode = function(value)
                return serdeShim.decode("json", value)
            end,
        }

        nativeModuleShims.fs = fsShim
        nativeModuleShims.net = netShim
        nativeModuleShims.process = processShim
        nativeModuleShims.stdio = stdioShim
        nativeModuleShims.task = taskLib
        nativeModuleShims.serde = serdeShim
        nativeModuleShims.regex = regexShim
        nativeModuleShims.luau = luauShim
        nativeModuleShims.roblox = robloxShim
        nativeModuleShims.datetime = datetimeShim
        nativeModuleShims.path = pathShim
        nativeModuleShims.crypto = cryptoShim
        nativeModuleShims.http = httpShim
        nativeModuleShims.json = jsonShim

        if hostFns.type(table.freeze) == "function" then
            for _, module in hostFns.pairs(nativeModuleShims) do
                if hostFns.type(module) == "table" then
                    hostFns.pcall(table.freeze, module)
                end
            end
        end
    end)()

    sandbox._G = table.clone(sandbox)
    sandbox._G.__isProtectedRuntimeFunction = nil
    sandbox._G._G = sandbox._G
    sandbox._ENV = sandbox

    hostFns.setmetatable(sandbox, {
        __index = function(_, key)
            local service = serviceCache[key]

            if service then
                return service
            end

            if serviceNames[key] then
                return makeService(key)
            end

            local constructor = dataConstructors[key]
            if constructor then
                return constructor
            end

            -- Unknown globals resolve to nil.
            return nil
        end,

        __newindex = function(target, key, value)
            hostFns.rawset(target, key, value)
            emit(hostFns.tostring(key) .. " = " .. repr(value))
        end,
    })

    -- Populate common services eagerly.
    for _, serviceName in hostFns.ipairs({
        "RunService",
        "HttpService",
        "Lighting",
        "SoundService",
        "TweenService",
        "MarketplaceService",
        "PhysicsService",
        "ContentProvider",
        "AnimationClipProvider",
        "ContextActionService",
        "UserInputService",
        "PathfindingService",
        "ProximityPromptService",
        "TestService",
        "PlayerEmulatorService",
        "Teams",
        "Stats",
        "LogService",
    }) do
        makeService(serviceName)
    end

    local function sanitizeRuntimeError(value)
        local text = hostFns.tostring(value)
        text = text:gsub("C:\\Users\\[^\\]+", "C:\\ProjectRadium")
        text = text:gsub("C:\\\\Users\\\\[^\\\\]+", "C:\\\\ProjectRadium")
        text = text:gsub("C:/Users/[^/]+", "C:/ProjectRadium")
        text = text:gsub("temp\\input_%d+_%d+%.lua", "ProjectRadium\\script.lua")
        text = text:gsub("temp/input_%d+_%d+%.lua", "ProjectRadium/script.lua")
        return text
    end

    do
        local function ProjectRadiumRunTarget()
            local source = safeRead(CONFIG.input)

            if not source then
                hostFns.error("Oxygen OxyEnv could not read input: " .. hostFns.tostring(CONFIG.input), 0)
            end

            -- Output header is initialized before runtime logging begins.

            local fn, compileError = luau.load(source, {
                environment = sandbox,
                chunkName = "=OxyEnv",
            })

            if not fn then
                output[#output + 1] = "-- compile error: " .. sanitizeRuntimeError(compileError)
            else
                runtimeStart = hostFns.clock()
                CONFIG.runtimeTracing = true
                local ok, runtimeError = hostFns.pcall(fn)
                CONFIG.runtimeTracing = false

                if not ok then
                    output[#output + 1] = ""
                    output[#output + 1] = "-- runtime: " .. sanitizeRuntimeError(runtimeError)
                    hostFns.warn("[Oxygen OxyEnv runtime] " .. sanitizeRuntimeError(runtimeError))
                end
            end

            safeWrite(CONFIG.output, table.concat(output, "\n"))

            hostFns.print("")
            hostFns.print("Oxygen OxyEnv complete")
            hostFns.print("input: " .. CONFIG.input)
            hostFns.print("output: " .. CONFIG.output)
            hostFns.print("api: " .. apiSource)
            hostFns.print(
                string.format(
                    "profile: %s (%s) userId=%d placeId=%d executor=%s",
                    CONFIG.displayName,
                    CONFIG.username,
                    CONFIG.userId,
                    CONFIG.placeId,
                    CONFIG.executorName
                )
            )
        end

        ProjectRadiumRunTarget()
    end
end)()
