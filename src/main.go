package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	pkgName := flag.String("pkg", "pkg", "target package name (e.g. com.termux)")
	libPath := flag.String("lib", "lib", "path to native library to inject")
	debug := flag.Bool("debug", false, "enable debug logging")
	stealth := flag.Bool("stealth", false, "enable ephemeral payload delivery (ghost mode)")
	memfd := flag.Bool("memfd", false, "use memfd_create for fileless injection (maximum stealth)")
	logcat := flag.Bool("logcat", false, "start logcat for child pid after inject")

	flag.Parse()

	if *debug {
		SetLogLevel("debug")
	}

	if *pkgName == "" || *libPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	LogInfo("starting spawn injector", "package", *pkgName, "payload", *libPath)

	// Step 1: Kill existing app instance
	LogDebug("killing existing app instance", "package", *pkgName)
	err := ForceStopApp(*pkgName)
	if err != nil {
		LogWarn("failed to force-stop app", "error", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Step 2: Locate zygote64
	LogDebug("locating zygote64")
	zygotePid, err := FindProcessPid("zygote64")
	if err != nil {
		LogError("could not find zygote64 pid", "error", err)
		os.Exit(1)
	}
	LogInfo("found zygote64", "pid", zygotePid)

	// Step 3: Resolve main activity
	LogDebug("resolving main activity", "package", *pkgName)
	mainActivity, err := ResolveMainActivity(*pkgName)
	if err != nil {
		LogWarn("could not resolve main activity", "error", err)
		mainActivity = fmt.Sprintf("%s/.MainActivity", *pkgName)
	} else {
		LogInfo("resolved main activity", "package", *pkgName, "activity", mainActivity)
	}

	// Step 4: Choose injection mode and execute
	var childPid int

	if *memfd {
		// Maximum stealth: memfd_create path (no file on disk at any point)
		LogInfo("using memfd injection mode")
		childPid, err = RunMemfdInjector(*pkgName, *libPath, zygotePid, mainActivity)
	} else {
		// Standard or stealth file-based injection
		actualLibPath := *libPath
		stagedPayloadPath := ""

		if *stealth {
			LogInfo("stealth mode enabled")
			path, err := stageEphemeralPayload(*pkgName, *libPath)
			if err != nil {
				LogError("failed to stage ephemeral payload", "error", err)
				os.Exit(1)
			}
			actualLibPath = path
			stagedPayloadPath = path
			LogDebug("staged ephemeral payload", "path", path)
		}

		childPid, err = RunInjector(*pkgName, actualLibPath, zygotePid, mainActivity)

		if stagedPayloadPath != "" {
			cleanupStagedPayload(stagedPayloadPath, err == nil)
		}
	}

	if err != nil {
		LogError("injection failed", "error", err)
		os.Exit(1)
	}

	LogInfo("injection sequence complete", "pid", childPid)

	if *logcat && childPid > 0 {
		LogInfo("starting logcat", "pid", childPid)
		cmd := exec.Command("logcat", "-v", "brief", fmt.Sprintf("--pid=%d", childPid))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

func stageEphemeralPayload(pkgName string, srcPath string) (string, error) {
	payloadData, err := os.ReadFile(srcPath)
	if err != nil {
		return "", err
	}

	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Stage into /data/local/tmp with an innocuous name.
	// This path is universally accessible by the linker's default namespace.
	// The shellcode will unlink the file immediately after dlopen succeeds,
	// so it only exists on disk for milliseconds during the injection window.
	stagingDir := "/data/local/tmp"

	stagedName := fmt.Sprintf(".org.chromium.%s.tmp", hex.EncodeToString(randomBytes))
	stagedPath := filepath.Join(stagingDir, stagedName)
	if err := os.WriteFile(stagedPath, payloadData, 0755); err != nil {
		return "", err
	}
	if err := os.Chmod(stagedPath, 0755); err != nil {
		_ = os.Remove(stagedPath)
		return "", err
	}

	return stagedPath, nil
}

// getAppUid returns the numeric UID for an app's data directory.
func getAppUid(pkgName string) int {
	out, err := exec.Command("stat", "-c", "%u", fmt.Sprintf("/data/data/%s", pkgName)).Output()
	if err != nil {
		return 0
	}
	var uid int
	fmt.Sscanf(string(out), "%d", &uid)
	return uid
}

func cleanupStagedPayload(path string, logSuccess bool) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil {
		LogWarn("failed to unlink ephemeral payload", "path", path, "error", err)
		return
	}
	if logSuccess {
		LogInfo("unlinked ephemeral payload")
	}
}
