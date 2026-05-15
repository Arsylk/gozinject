set_project("gozinject")
set_version("1.0.0")

add_rules("mode.debug", "mode.release")

local function join_path(...)
	local parts = { ... }
	return table.concat(parts, "/"):gsub("//+", "/")
end

local function basename(p)
	return (p:gsub("[\\/]+$", ""):match("([^\\/]+)$")) or p
end

---------------------------------------------------------------------------
-- Targets
---------------------------------------------------------------------------

target("injector")
set_kind("phony")
on_build(function(target)
	local output = join_path(os.projectdir(), "dist", "injector")
	os.mkdir(join_path(os.projectdir(), "dist"))
	os.mkdir(join_path(os.projectdir(), "dist", "tmp"))

	print("Building gozinject for android/arm64 ...")
	os.vrunv("go", { "build", "-trimpath", "-ldflags=-s -w", "-o", output, "./src" }, {
		envs = {
			GOOS = "android",
			GOARCH = "arm64",
			CGO_ENABLED = "0",
			GOTMPDIR = join_path(os.projectdir(), "dist", "tmp"),
		},
	})
end)
on_clean(function(target)
	os.tryrm(join_path(os.projectdir(), "dist", "injector"))
end)
target_end()

---------------------------------------------------------------------------
-- Tasks
---------------------------------------------------------------------------

task("run")
set_menu({
	usage = "xmake run [options]",
	description = "Build, deploy, and run the injector on device",
	options = {
		{ "s", "serial", "kv", nil, "ADB device serial" },
		{ nil, "pkg", "kv", "com.termux", "Target package" },
		{ nil, "lib", "kv", nil, "Path to library to inject (local)" },
		{ nil, "stealth", "k", nil, "Enable stealth/ghost mode" },
		{ nil, "memfd", "k", nil, "Use memfd_create for fileless injection" },
		{ nil, "logcat", "k", nil, "Stream child logcat after injection" },
		{ nil, "debug", "k", nil, "Enable debug logging" },
	},
})
on_run(function()
	local opt = import("core.base.option")
	local pkg = opt.get("pkg")
	local serial = opt.get("serial")
	local local_lib = opt.get("lib")
	local want_stealth = opt.get("stealth")
	local want_memfd = opt.get("memfd")
	local want_logcat = opt.get("logcat")
	local want_debug = opt.get("debug")

	if not local_lib then
		print("Error: --lib is required (path to .so payload)")
		return
	end

	local remote_tmp = "/data/local/tmp"
	local lib_name = basename(local_lib)
	local remote_lib = remote_tmp .. "/" .. lib_name

	local function adb(args)
		local full = serial and { "-s", serial } or {}
		for _, v in ipairs(args) do
			table.insert(full, v)
		end
		os.vrunv("adb", full)
	end

	local function adb_su(args)
		local full = serial and { "-s", serial } or {}
		table.insert(full, "shell")
		table.insert(full, "-tt")
		table.insert(full, "su")
		table.insert(full, "-c")
		table.insert(full, '"' .. table.concat(args, " ") .. '"')
		os.vrunv("adb", full)
	end

	-- Build
	os.vrunv("xmake", { "b", "injector" })

	-- Use a randomized name for the injector binary on device in stealth/memfd mode
	local use_stealth_name = want_stealth or want_memfd
	local remote_injector_name = use_stealth_name
		and string.format("app_process_%04x", math.random(0, 0xffff))
		or "injector"
	local remote_injector = remote_tmp .. "/" .. remote_injector_name

	-- Deploy
	print("Deploying to device...")
	adb({ "push", "dist/injector", remote_injector })
	adb({ "push", local_lib, remote_lib })
	adb_su({ "chmod", "755", remote_injector })

	-- Build injector command
	print("Running injector for package: " .. pkg)
	local run_args = serial and { "-s", serial } or {}
	table.insert(run_args, "shell")
	table.insert(run_args, "-tt")
	table.insert(run_args, "su")
	table.insert(run_args, "-c")

	local injector_cmd = remote_injector .. " -pkg " .. pkg .. " -lib " .. remote_lib
	if want_stealth then injector_cmd = injector_cmd .. " -stealth" end
	if want_memfd then injector_cmd = injector_cmd .. " -memfd" end
	if want_debug then injector_cmd = injector_cmd .. " -debug" end
	if want_logcat then injector_cmd = injector_cmd .. " -logcat" end
	table.insert(run_args, '"' .. injector_cmd .. '"')

	os.execv("adb", run_args)

	-- Cleanup device artifacts in stealth modes
	if use_stealth_name then
		print("Cleaning up device artifacts...")
		adb_su({ "rm", "-f", remote_injector })
		adb_su({ "rm", "-f", remote_lib })
	end
end)
task_end()
