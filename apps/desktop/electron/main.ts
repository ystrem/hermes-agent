import { execFile, execFileSync, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import { pathToFileURL } from 'node:url'

import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  net as electronNet,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  Notification,
  powerMonitor,
  powerSaveBlocker,
  protocol,
  safeStorage,
  screen,
  session,
  shell,
  systemPreferences
} from 'electron'
import nodePty from 'node-pty'

import { stopBackendChild as stopBackendChildImpl } from './backend-child'
import { dashboardFallbackArgs, sourceDeclaresServe } from './backend-command'
import { createBackendConnectionState } from './backend-connection-state'
import { buildDesktopBackendEnv, normalizeHermesHomeRoot } from './backend-env'
import { canImportHermesCli, verifyHermesCli } from './backend-probes'
import { waitForDashboardPortAnnouncement } from './backend-ready'
import { shouldLatchBackendStartFailure } from './backend-start-failure'
import { detectRemoteDisplay, isWindowsBinaryPathInWsl, isWslEnvironment } from './bootstrap-platform'
import { runBootstrap } from './bootstrap-runner'
import {
  authModeFromStatus,
  buildGatewayWsUrl,
  buildGatewayWsUrlWithTicket,
  connectionScopeKey,
  cookiesHaveLiveSession,
  cookiesHavePrivySession,
  cookiesHaveSession,
  gatewayTicketFailure,
  gatewayWsUrlIpcResult,
  modeIsRemoteLike,
  normalizeRemoteBaseUrl,
  normAuthMode,
  pathWithGlobalRemoteProfile,
  profileRemoteOverride,
  resolveAuthMode,
  resolveTestWsUrl,
  tokenPreview
} from './connection-config'
import { adoptServedDashboardToken } from './dashboard-token'
import {
  buildPosixCleanupScript,
  buildWindowsCleanupScript,
  modeRemovesAgent,
  modeRemovesUserData,
  resolveRemovableAppPath,
  shouldRemoveAppBundle,
  uninstallArgsForMode
} from './desktop-uninstall'
import { installEmbedReferer } from './embed-referer'
import { createEventDeduper } from './event-dedupe'
import { readDirForIpc } from './fs-read-dir'
import { probeGatewayWebSocket } from './gateway-ws-probe'
import { scanGitRepos } from './git-repo-scan'
import {
  fileDiffVsHead,
  repoStatus,
  reviewCommit,
  reviewCommitContext,
  reviewCreatePr,
  reviewDiff,
  reviewList,
  reviewPush,
  reviewRevert,
  reviewRevParse,
  reviewShipInfo,
  reviewStage,
  reviewUnstage
} from './git-review-ops'
import { gitRootForIpc } from './git-root'
import {
  addWorktree,
  listBaseBranches,
  listBranches,
  listWorktrees,
  removeWorktree,
  switchBranch
} from './git-worktree-ops'
import {
  DATA_URL_READ_MAX_BYTES,
  DEFAULT_FETCH_TIMEOUT_MS,
  encryptDesktopSecret as encryptDesktopSecretStrict,
  resolveReadableFileForIpc,
  resolveRequestedPathForIpc,
  resolveTimeoutMs,
  TEXT_PREVIEW_SOURCE_MAX_BYTES
} from './hardening'
import { createLinkTitleWindow, guardLinkTitleSession, readLinkTitleWindowTitle } from './link-title-window'
import { ensureMainWindow } from './main-window-lifecycle'
import { serializeJsonBody, setJsonRequestHeaders } from './oauth-net-request'
import { createKeepAwake } from './power-save'
import { decideProfileDeleteAction, profileNameFromDeleteRequest, resolveRouteProfile } from './profile-delete-routing'
import { RemoteLivenessTracker, RemoteRevalidationCoordinator, revalidateRemoteConnection } from './remote-liveness'
import {
  buildSessionWindowUrl,
  chatWindowWebPreferences,
  createSessionWindowRegistry,
  instanceWindowBounds,
  SESSION_WINDOW_MIN_HEIGHT,
  SESSION_WINDOW_MIN_WIDTH
} from './session-windows'
import { ensureSpawnHelperExecutable } from './spawn-helper-perms'
import { nativeOverlayWidth as computeNativeOverlayWidth, macTitleBarOverlayHeight } from './titlebar-overlay-width'
import { resolveBehindCount, shouldCountCommits } from './update-count'
import { readLiveUpdateMarker, writeUpdateMarker } from './update-marker'
import { runRebuildWithRetry } from './update-rebuild'
import {
  buildRelaunchScript,
  collectRelaunchArgs,
  collectRelaunchEnv,
  decideRelaunchOutcome,
  resolveUnpackedRelease,
  sandboxFallbackFromEnv,
  sandboxPreflight
} from './update-relaunch'
import { isOfficialSshRemote, OFFICIAL_REPO_HTTPS_URL } from './update-remote'
import { spawnUpdaterProcess } from './updater-process'
import { fetchMarketplaceThemes, searchMarketplaceThemes } from './vscode-marketplace'
import {
  computeWindowOptions,
  debounce,
  sanitizeWindowState,
  MIN_HEIGHT as WINDOW_MIN_HEIGHT,
  MIN_WIDTH as WINDOW_MIN_WIDTH
} from './window-state'
import { hiddenWindowsChildOptions } from './windows-child-options'
import {
  buildPathExtCandidates,
  chooseUpdaterArgs,
  getVenvSitePackagesEntries,
  resolveVenvHermesCommand
} from './windows-hermes-path'
import {
  alreadyHasNoSandbox,
  buildNoSandboxRelaunchArgs,
  decideWindowsSandboxLaunch,
  fallbackMarker,
  grantAllApplicationPackagesAcl,
  markerAfterSuccessfulBoot,
  readSandboxMarker,
  type SandboxFallbackReason,
  shouldAttemptAclRepair,
  shouldRelaunchForGpuSandboxCrash,
  shouldRelaunchForRendererSandboxCrashLoop,
  writeSandboxMarker
} from './windows-sandbox-fallback'
import { installWindowsSystemCaTrust } from './windows-system-ca'
import { readWindowsUserEnvVar } from './windows-user-env'
import { isPackagedInstallPath as isPackagedInstallPathUnderRoots } from './workspace-cwd'
import { readWslWindowsClipboardImage } from './wsl-clipboard-image'
import { resolvePickerDefaultPath } from './wsl-path-bridge'

const USER_DATA_OVERRIDE = process.env.HERMES_DESKTOP_USER_DATA_DIR

if (USER_DATA_OVERRIDE) {
  const resolvedUserData = path.resolve(USER_DATA_OVERRIDE)
  fs.mkdirSync(resolvedUserData, { recursive: true })
  app.setPath('userData', resolvedUserData)
}

const DEV_SERVER = process.env.HERMES_DESKTOP_DEV_SERVER
const IS_PACKAGED = app.isPackaged || Boolean(process.env.HERMES_DESKTOP_IS_PACKAGED)
const IS_MAC = process.platform === 'darwin'
const IS_WINDOWS = process.platform === 'win32'
const IS_WSL = isWslEnvironment()
// Truthful macOS kernel major (Tahoe = 25). Product version lies (16 vs 26) per
// build SDK, so gate Tahoe workarounds on Darwin instead.
const DARWIN_MAJOR = IS_MAC ? Number.parseInt(os.release(), 10) || 0 : 0
const APP_ROOT = app.getAppPath()

// Preload must be plain JS — Electron's sandbox can't run .ts, and tsx's
// ESM loader is broken on Electron 40's Node (ERR_INVALID_RETURN_PROPERTY_VALUE).
// Dev (`npm run dev`) and prod both load the esbuild output from dist/.
const PRELOAD_PATH = path.join(APP_ROOT, 'dist', 'electron-preload.js')

// Remote displays (SSH X11 forwarding, VNC, RDP) make Chromium's GPU
// compositor flicker — accelerated layers can't be presented cleanly over the
// wire, so the window flashes during scroll/streaming/animation. Local
// Windows/macOS (and WSLg, which renders locally via vGPU) composite on the
// GPU and never see it. Fall back to software rendering when a remote display
// is detected; it's rock-steady over the wire and the CPU cost is negligible
// next to the connection's latency. Must run before app `ready` — these
// switches only apply pre-launch. Override with HERMES_DESKTOP_DISABLE_GPU
// (1/true → always disable, 0/false → keep GPU on).
const REMOTE_DISPLAY_REASON = detectRemoteDisplay()

if (REMOTE_DISPLAY_REASON) {
  app.disableHardwareAcceleration()
  // Belt-and-suspenders for X11/VNC, where the Viz compositor can still glitch
  // with only --disable-gpu: force compositing onto the CPU too.
  app.commandLine.appendSwitch('disable-gpu-compositing')
  console.log(
    `[hermes] remote display detected (${REMOTE_DISPLAY_REASON}); disabling GPU hardware acceleration to prevent flicker`
  )
}

// WSLg: Chromium blocklists the Mesa vGPU → software compositing → typing lag.
// /dev/dxg means a real GPU is available; un-blocklist it. Skipped when a remote
// display already forced software (SSH'd-into-WSL).
if (IS_WSL && !REMOTE_DISPLAY_REASON && fs.existsSync('/dev/dxg')) {
  app.commandLine.appendSwitch('ignore-gpu-blocklist')
  app.commandLine.appendSwitch('enable-gpu-rasterization')
  app.commandLine.appendSwitch('enable-zero-copy')
  console.log('[hermes] WSL GPU passthrough (/dev/dxg) detected; enabling GPU acceleration')
}

// Windows sandbox / GPU breakpoint crash recovery (#38216).
//
// Some hosts (AMD RX 6000 drivers, orphan AppContainer SIDs under %LOCALAPPDATA%,
// missing S-1-15-2-2 ACEs) kill Chromium's sandboxed GPU/renderer children with
// 0x80000003. After enough GPU deaths the browser process FATAL-exits before the
// UI is usable. Must run before app `ready` so `--no-sandbox` applies to child
// processes. The sticky marker recovers Start Menu / shortcut launches that
// never go through `hermes desktop`; it is version-scoped so an app update
// re-probes the sandbox instead of degrading forever.
//
// `windowsSandboxFallbackActive` = this process runs without the Chromium
// sandbox (any cause, including a manual --no-sandbox flag) — guards the
// relaunch handlers. `windowsSandboxFallbackSticky` = the fallback machinery
// engaged and the marker must stay `fallback` after a successful boot; a
// manual flag alone is honored but never made sticky.
let windowsSandboxFallbackActive = false
let windowsSandboxFallbackSticky = false
let windowsSandboxFallbackReason: SandboxFallbackReason = 'boot-loop'
let windowsNoSandboxRelaunchAttempted = false

if (IS_WINDOWS) {
  const windowsUserData = app.getPath('userData')
  const priorMarker = readSandboxMarker(windowsUserData)

  // Best-effort ACL repair, only when the last boot aborted or the fallback is
  // engaged — icacls /T recurses the whole install tree, so healthy launches
  // skip it (the installer already granted the ACE at install time). Repair
  // targets the install dir only: granting AppContainer read on userData would
  // expose Hermes sessions/config to every packaged app on the machine.
  if (shouldAttemptAclRepair(priorMarker)) {
    const exeDir = path.dirname(process.execPath)
    const acl = grantAllApplicationPackagesAcl(exeDir, { execFileSync })

    if (acl.ok) {
      console.log(`[hermes] granted ALL APPLICATION PACKAGES RX on ${exeDir} (#38216)`)
    } else if (acl.error && acl.error !== 'missing-target-or-exec') {
      console.warn(`[hermes] AppContainer ACL grant failed on ${exeDir}: ${acl.error}`)
    }
  }

  const sandboxDecision = decideWindowsSandboxLaunch({
    argv: process.argv,
    env: process.env,
    marker: priorMarker,
    appVersion: app.getVersion()
  })

  windowsSandboxFallbackActive = sandboxDecision.enable
  windowsSandboxFallbackSticky = sandboxDecision.nextMarker.state === 'fallback'

  if (sandboxDecision.nextMarker.state === 'fallback' && sandboxDecision.nextMarker.reason) {
    windowsSandboxFallbackReason = sandboxDecision.nextMarker.reason
  }

  if (sandboxDecision.enable && sandboxDecision.reason !== 'already-enabled') {
    app.commandLine.appendSwitch('no-sandbox')
    process.env.ELECTRON_DISABLE_SANDBOX = '1'
    console.log(
      `[hermes] Windows sandbox fallback enabled (${sandboxDecision.reason}); launching with --no-sandbox (#38216)`
    )
  }

  writeSandboxMarker(windowsUserData, sandboxDecision.nextMarker)

  // Catch the first GPU breakpoint death and relaunch before Chromium's
  // "GPU process isn't usable" FATAL abort ends the process with no recovery.
  app.on('child-process-gone', (_event, details) => {
    if (
      !shouldRelaunchForGpuSandboxCrash({
        details,
        alreadyNoSandbox: windowsSandboxFallbackActive || alreadyHasNoSandbox(process.argv, process.env),
        relaunchAttempted: windowsNoSandboxRelaunchAttempted
      })
    ) {
      return
    }

    windowsNoSandboxRelaunchAttempted = true
    windowsSandboxFallbackActive = true
    windowsSandboxFallbackSticky = true
    windowsSandboxFallbackReason = 'gpu-breakpoint'

    try {
      writeSandboxMarker(app.getPath('userData'), fallbackMarker('gpu-breakpoint', app.getVersion()))
    } catch {
      void 0
    }

    console.warn(
      `[hermes] Windows GPU sandbox crashed (exit=${details?.exitCode}); relaunching once with --no-sandbox (#38216)`
    )

    try {
      app.relaunch({ args: buildNoSandboxRelaunchArgs(process.argv.slice(1)) })
      app.exit(0)
    } catch (error) {
      console.error(`[hermes] --no-sandbox relaunch failed: ${error?.message || error}`)
    }
  })
}

ipcMain.handle('hermes:get-remote-display-reason', () => REMOTE_DISPLAY_REASON)

// Keep the renderer running at full speed while the window is in the background
// or occluded. The chat transcript streams to screen through a
// requestAnimationFrame-gated flush; Chromium pauses rAF (and clamps timers)
// for backgrounded/occluded renderers, so without these the live answer stalls
// whenever the window loses focus (switching to your editor mid-turn, detached
// devtools, another window covering it) and only paints on refocus or refresh.
// `backgroundThrottling: false` on the BrowserWindow covers the blurred case;
// these process-level switches additionally stop Chromium from backgrounding or
// occlusion-throttling the renderer. Must run before app `ready`.
app.commandLine.appendSwitch('disable-renderer-backgrounding')
app.commandLine.appendSwitch('disable-backgrounding-occluded-windows')
app.commandLine.appendSwitch('disable-background-timer-throttling')

const SOURCE_REPO_ROOT = path.resolve(APP_ROOT, '../..')

// Build-time install stamp -- the git ref this .exe was built against.
//
// Written by apps/desktop/scripts/write-build-stamp.mjs during `npm run build`
// and bundled into packaged apps via electron-builder's extraResources entry,
// so the runtime stamp ends up at process.resourcesPath/install-stamp.json
// after install. The bootstrap runner (Phase 1D) reads it to know which
// commit to clone when running install.ps1 stages at first launch.
//
// Returns null when the file is missing (dev runs from a checkout where
// build hasn't been invoked, or schema mismatch). Callers must handle null.
//
// Schema:
//   { schemaVersion: 1, commit, branch, builtAt, dirty, source }
const INSTALL_STAMP_SCHEMA_VERSION = 1

function loadInstallStamp() {
  // Try packaged location first (resources/install-stamp.json), then the
  // dev/local build output (apps/desktop/build/install-stamp.json) so
  // someone running `npm run start` after a local `npm run build` also
  // sees a stamp without needing a packaged build.
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'install-stamp.json') : null,
    path.join(APP_ROOT, 'build', 'install-stamp.json')
  ].filter(Boolean)

  for (const p of candidates) {
    try {
      const raw = fs.readFileSync(p, 'utf8')
      const parsed = JSON.parse(raw)

      if (parsed && typeof parsed === 'object' && typeof parsed.commit === 'string' && parsed.commit.length >= 7) {
        if (parsed.schemaVersion !== INSTALL_STAMP_SCHEMA_VERSION) {
          console.warn(
            `[hermes] install-stamp.json schemaVersion ${parsed.schemaVersion} != expected ${INSTALL_STAMP_SCHEMA_VERSION}; ignoring`
          )

          continue
        }

        return Object.freeze({
          schemaVersion: parsed.schemaVersion,
          commit: parsed.commit,
          branch: parsed.branch || null,
          builtAt: parsed.builtAt || null,
          dirty: Boolean(parsed.dirty),
          source: parsed.source || null,
          path: p
        })
      }
    } catch (e) {
      console.warn(`[hermes] install-stamp.json found at ${p} , but parsing failed with ${e}`)
      // Either ENOENT or malformed JSON; try the next candidate
    }
  }

  return null
}

const INSTALL_STAMP = loadInstallStamp()

if (INSTALL_STAMP) {
  console.log(
    `[hermes] install stamp: ${INSTALL_STAMP.commit.slice(0, 12)}${INSTALL_STAMP.branch ? ` (${INSTALL_STAMP.branch})` : ''}${INSTALL_STAMP.dirty ? ' [DIRTY]' : ''} from ${INSTALL_STAMP.source || 'unknown'}`
  )
} else if (IS_PACKAGED) {
  // Dev builds without a stamp are normal; packaged builds without one
  // mean the bootstrap won't know what to clone. Surface clearly.
  console.error(
    '[hermes] WARNING: no install-stamp.json found in packaged build. First-launch bootstrap will not have a pinned ref to install.'
  )
}

// HERMES_HOME — the user-facing root for everything Hermes-related. Mirrors
// scripts/install.ps1's $HermesHome and scripts/install.sh's $HERMES_HOME.
//
// Defaults:
//   Windows: %LOCALAPPDATA%\hermes (matches install.ps1)
//   macOS / Linux: ~/.hermes (matches install.sh)
//
// Special case for Windows: if the user has a legacy ~/.hermes directory
// (e.g., from a prior pip install or a manual setup) AND no
// %LOCALAPPDATA%\hermes yet, prefer the legacy path so we don't orphan their
// existing config / sessions / .env. New installs go to %LOCALAPPDATA%.
//
// HERMES_DESKTOP_USER_DATA_DIR (used by test:desktop:fresh) puts the sandbox
// HERMES_HOME beneath the throwaway userData dir so a fresh-install run never
// touches the user's real ~/.hermes / %LOCALAPPDATA%\hermes.
function resolveHermesHome() {
  if (process.env.HERMES_HOME) {
    return normalizeHermesHomeRoot(process.env.HERMES_HOME)
  }

  if (USER_DATA_OVERRIDE) {
    return path.join(path.resolve(USER_DATA_OVERRIDE), 'hermes-home')
  }

  if (IS_WINDOWS) {
    // A GUI app launched from Explorer inherits the environment block captured
    // at login, so a HERMES_HOME set via `setx` AFTER login is invisible in
    // process.env even though the CLI (a fresh shell) sees it. Without this the
    // backend silently falls back to %LOCALAPPDATA%\hermes and reports "No
    // inference provider configured" despite a valid configured home (#45471).
    // Consult the live User-scoped registry value before the default below.
    const fromRegistry = readWindowsUserEnvVar('HERMES_HOME')

    if (fromRegistry) {
      return normalizeHermesHomeRoot(fromRegistry)
    }
  }

  if (IS_WINDOWS && process.env.LOCALAPPDATA) {
    const localappdata = path.join(process.env.LOCALAPPDATA, 'hermes')
    const legacy = path.join(app.getPath('home'), '.hermes')

    // Migrate transparently to LOCALAPPDATA, but honour an existing legacy
    // ~/.hermes setup (no LOCALAPPDATA install yet) so users don't lose state.
    if (!directoryExists(localappdata) && directoryExists(legacy)) {
      return legacy
    }

    return localappdata
  }

  return path.join(app.getPath('home'), '.hermes')
}

const HERMES_HOME = resolveHermesHome()

function hermesManagedNodePathEntries() {
  // NOTE: keep this ordering in sync with iter_hermes_node_dirs() in
  // hermes_constants.py — this Node main process cannot import the Python
  // module, so the platform-ordering rule is mirrored here.
  const root = path.join(HERMES_HOME, 'node')
  const bin = path.join(root, 'bin')
  const entries = IS_WINDOWS ? [root, bin] : [bin, root]

  return entries.filter(directoryExists)
}

function pathWithHermesManagedNode(...entries) {
  return [...hermesManagedNodePathEntries(), ...entries, process.env.PATH].filter(Boolean).join(path.delimiter)
}

// ACTIVE_HERMES_ROOT — the canonical mutable Hermes install. Same path
// install.ps1 / install.sh use, so a desktop-only user and a CLI-only user end
// up with identical layouts and can share one install.
const ACTIVE_HERMES_ROOT = path.join(HERMES_HOME, 'hermes-agent')
// VENV_ROOT — venv lives inside the repo, exactly like install.ps1 does it.
const VENV_ROOT = path.join(ACTIVE_HERMES_ROOT, 'venv')
// BOOTSTRAP_COMPLETE_MARKER — written by the first-launch bootstrap runner
// (Phase 1D) after install.ps1 has completed all stages and the user has
// finished initial configuration. Presence of this marker means the install
// is in a known-good state and we can skip the bootstrap flow on subsequent
// boots, going straight to `resolveHermesBackend()`. Missing or stale marker
// means we re-run the bootstrap; install.ps1's stages are idempotent so a
// re-run on an already-good install just discovers everything in place.
//
// We deliberately put the marker INSIDE ACTIVE_HERMES_ROOT (not alongside)
// so that deleting the checkout to start fresh also deletes the marker --
// avoids the confusing "marker exists but checkout is gone" state.
const BOOTSTRAP_COMPLETE_MARKER = path.join(ACTIVE_HERMES_ROOT, '.hermes-bootstrap-complete')
const BOOTSTRAP_MARKER_SCHEMA_VERSION = 1

const DESKTOP_CONNECTION_CONFIG_PATH = path.join(app.getPath('userData'), 'connection.json')
const DESKTOP_UPDATE_CONFIG_PATH = path.join(app.getPath('userData'), 'updates.json')
const DESKTOP_WINDOW_STATE_PATH = path.join(app.getPath('userData'), 'window-state.json')
// active-profile.json records which Hermes profile the desktop launches its
// local backend as. When set, startHermes() passes `hermes --profile <name>
// dashboard …`, which deterministically pins HERMES_HOME (see
// _apply_profile_override in hermes_cli/main.py) and bypasses the sticky
// ~/.hermes/active_profile file. Unset (null) preserves the legacy behavior:
// no --profile flag, so the backend honors active_profile / default.
const DESKTOP_PROFILE_CONFIG_PATH = path.join(app.getPath('userData'), 'active-profile.json')
// Mirrors hermes_cli.profiles._PROFILE_ID_RE so we never hand the backend a
// value its profile resolver would reject and exit on.
const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/
// Branch we track for self-update. The GUI work has merged to main, so this
// tracks main. User can also override at runtime via
// hermesDesktop.updates.setBranch().
const DEFAULT_UPDATE_BRANCH = 'main'
// desktop.log lives under HERMES_HOME/logs/ so it sits next to agent.log,
// errors.log, gateway.log produced by hermes_logging.setup_logging — one log
// directory per user, regardless of which UI surface produced the line.
const DESKTOP_LOG_PATH = path.join(HERMES_HOME, 'logs', 'desktop.log')
const DESKTOP_LOG_FLUSH_MS = 120
const DESKTOP_LOG_BUFFER_MAX_CHARS = 64 * 1024
// Bound desktop.log on disk. It is an append-only forensic log, so a boot loop
// (version-skew crash -> backend exits instantly -> renderer keeps hitting
// Retry) appends the full bootstrap transcript every attempt and grows without
// bound — we have seen it reach ~326 GB and exhaust the disk, which then breaks
// update/install (no room for git/venv/npm temp files).
//
// Mirror the Python logs (hermes_logging.py RotatingFileHandler, maxBytes x
// backupCount): cascade live -> .1 -> .2 -> .3, drop the oldest. Steady-state
// stays bounded at ~(backupCount + 1) x cap however hard the app loops.
//
// Bounding alone never RECLAIMS an already-huge file: a plain rotation just
// renames the monster to .1 and strands it for a cycle a healthy app may never
// reach. A multi-GB boot-loop transcript has no diagnostic value, so anything
// past the discard ceiling is deleted outright — the updated app self-heals a
// disk a stale build filled, on the next launch.
const DESKTOP_LOG_MAX_BYTES = 10 * 1024 * 1024
const DESKTOP_LOG_BACKUP_COUNT = 3
const DESKTOP_LOG_DISCARD_BYTES = DESKTOP_LOG_MAX_BYTES * 4
const desktopLogBackupPath = n => `${DESKTOP_LOG_PATH}.${n}`
const BOOT_FAKE_MODE = process.env.HERMES_DESKTOP_BOOT_FAKE === '1'
const BOOT_FAKE_ERROR = process.env.HERMES_DESKTOP_BOOT_FAKE_ERROR || ''

const BOOT_FAKE_STEP_MS = (() => {
  const raw = Number.parseInt(String(process.env.HERMES_DESKTOP_BOOT_FAKE_STEP_MS || ''), 10)

  if (!Number.isFinite(raw) || raw <= 0) {
    return 650
  }

  return Math.max(120, raw)
})()

const APP_NAME = process.env.HERMES_DESKTOP_APP_NAME || 'Hermes'
const TITLEBAR_HEIGHT = 34
const MACOS_TRAFFIC_LIGHTS_HEIGHT = 14

const WINDOW_BUTTON_POSITION = {
  x: 24,
  y: TITLEBAR_HEIGHT / 2 - MACOS_TRAFFIC_LIGHTS_HEIGHT / 2
}

// Right-edge window-control reservation lives in titlebar-overlay-width.ts
// (pure + unit-testable); computeNativeOverlayWidth() applies it per platform.
// It's only the pre-layout fallback — the renderer measures the exact overlay
// width live via the Window Controls Overlay API.
const APP_ICON_PATHS = [
  path.join(APP_ROOT, 'public', 'apple-touch-icon.png'),
  path.join(APP_ROOT, 'dist', 'apple-touch-icon.png'),
  path.join(unpackedPathFor(APP_ROOT), 'dist', 'apple-touch-icon.png')
]

let rendererTitleBarTheme = null
const terminalSessions = new Map()

// Force the NATIVE window appearance (vibrancy material, titlebar, the
// pre-first-paint window background) to follow the APP theme instead of the
// OS appearance. With `vibrancy` set, macOS paints an NSVisualEffectView that
// tracks the window's effective appearance and ignores `backgroundColor` —
// so a dark-themed app on a light-mode Mac flashes a white material on every
// new window until the renderer covers it. The renderer reports its mode via
// 'hermes:native-theme' ('dark' | 'light' | 'system'); we pin
// nativeTheme.themeSource to it and persist the value so cold launches paint
// correctly before the renderer has even loaded.
const NATIVE_THEME_CONFIG_PATH = path.join(app.getPath('userData'), 'native-theme.json')
const THEME_SOURCES = new Set(['dark', 'light', 'system'])

function readPersistedThemeSource() {
  try {
    const parsed = JSON.parse(fs.readFileSync(NATIVE_THEME_CONFIG_PATH, 'utf8'))

    if (parsed && THEME_SOURCES.has(parsed.themeSource)) {
      return parsed.themeSource
    }
  } catch {
    // Missing / malformed → follow the OS like a fresh install.
  }

  return 'system'
}

function writePersistedThemeSource(mode) {
  try {
    fs.mkdirSync(path.dirname(NATIVE_THEME_CONFIG_PATH), { recursive: true })
    fs.writeFileSync(NATIVE_THEME_CONFIG_PATH, JSON.stringify({ themeSource: mode }, null, 2), 'utf8')
  } catch (error) {
    rememberLog(`[theme] write native theme failed: ${error.message}`)
  }
}

nativeTheme.themeSource = readPersistedThemeSource()

// Window translucency (see-through window). One lever, 0–100; 0 = off (the
// default). Mapped to the native window opacity so the desktop shows through
// the whole window. Persisted so a cold launch applies it at window creation,
// before the renderer reports its value. macOS + Windows only; `setOpacity` is
// a no-op on Linux. See store/translucency.
const TRANSLUCENCY_CONFIG_PATH = path.join(app.getPath('userData'), 'translucency.json')

function clampIntensity(value) {
  const n = Math.round(Number(value))

  return Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : 0
}

function readPersistedTranslucency() {
  try {
    return clampIntensity(JSON.parse(fs.readFileSync(TRANSLUCENCY_CONFIG_PATH, 'utf8')).intensity)
  } catch {
    return 0
  }
}

function writePersistedTranslucency(intensity) {
  try {
    fs.mkdirSync(path.dirname(TRANSLUCENCY_CONFIG_PATH), { recursive: true })
    fs.writeFileSync(TRANSLUCENCY_CONFIG_PATH, JSON.stringify({ intensity }, null, 2), 'utf8')
  } catch (error) {
    rememberLog(`[translucency] write failed: ${error.message}`)
  }
}

let translucencyIntensity = readPersistedTranslucency()

// Map the 0–100 lever to a window opacity. Floor at 0.3 so the most see-through
// setting is still usable rather than nearly invisible. 0 → fully opaque.
function windowOpacity() {
  return 1 - (translucencyIntensity / 100) * 0.7
}

// Re-apply translucency to a live window (runtime toggle, no recreation).
// `setOpacity` is a no-op on Linux, which is fine — it just stays opaque there.
function applyWindowTranslucency(win) {
  if (!win || win.isDestroyed() || typeof win.setOpacity !== 'function') {
    return
  }

  try {
    win.setOpacity(windowOpacity())
  } catch (error) {
    rememberLog(`[translucency] apply failed: ${error.message}`)
  }
}

function isHexColor(value) {
  return typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value)
}

// Background color to paint a window with BEFORE its renderer loads, so a new
// (or reopened) window doesn't flash white/light in dark mode. Prefer the theme
// the renderer last reported; fall back to the OS preference on first launch.
function getWindowBackgroundColor() {
  if (rendererTitleBarTheme && isHexColor(rendererTitleBarTheme.background)) {
    return rendererTitleBarTheme.background
  }

  return nativeTheme.shouldUseDarkColors ? '#111111' : '#f7f7f7'
}

// Transparent WCO — renderer chrome shows through. rgba(0,0,0,0) can fall back
// to GetFrameColor() on some Electron builds; rgba(1,0,0,0) is the escape hatch.
const TITLEBAR_OVERLAY_COLOR = 'rgba(1, 0, 0, 0)'

function getTitleBarOverlayOptions() {
  if (IS_MAC) {
    // Tahoe (Darwin 25+) misplaces the traffic lights when the overlay has a
    // nonzero height (electron#49183); 0 there keeps them at the configured
    // inset. See macTitleBarOverlayHeight.
    return { height: macTitleBarOverlayHeight({ darwinMajor: DARWIN_MAJOR, titlebarHeight: TITLEBAR_HEIGHT }) }
  }

  // WSLg paints WCO via the RDP host's own min/max/close, so requesting
  // an Electron overlay there just leaves a dead gap. Plain Linux (KDE,
  // GNOME) can use the native overlay — let it through.
  if (!IS_WINDOWS && IS_WSL) {
    return false
  }

  return {
    color: TITLEBAR_OVERLAY_COLOR,
    height: TITLEBAR_HEIGHT,
    symbolColor:
      rendererTitleBarTheme && isHexColor(rendererTitleBarTheme.foreground)
        ? rendererTitleBarTheme.foreground
        : nativeTheme.shouldUseDarkColors
          ? '#f7f7f7'
          : '#242424'
  }
}

// Push refreshed overlay options to a live window after a theme/appearance
// change. No-op only on plain (non-WSL) Linux, where getTitleBarOverlayOptions()
// returns false; the try/catch additionally guards builds where
// setTitleBarOverlay isn't supported.
function applyTitleBarOverlay(win) {
  const options = getTitleBarOverlayOptions()

  if (!options || typeof options !== 'object') {
    return
  }

  try {
    win?.setTitleBarOverlay?.(options)
  } catch {
    // Overlay not supported on this platform/build — leave the frameless
    // titlebar as-is.
  }
}

const MEDIA_MIME_TYPES = {
  '.avi': 'video/x-msvideo',
  '.bmp': 'image/bmp',
  '.flac': 'audio/flac',
  '.gif': 'image/gif',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.m4a': 'audio/mp4',
  '.mkv': 'video/x-matroska',
  '.mov': 'video/quicktime',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.ogg': 'audio/ogg',
  '.opus': 'audio/ogg; codecs=opus',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.wav': 'audio/wav',
  '.webm': 'video/webm',
  '.webp': 'image/webp'
}

const PREVIEW_HTML_EXTENSIONS = new Set(['.html', '.htm'])
const PREVIEW_WATCH_DEBOUNCE_MS = 120
const LOCAL_PREVIEW_HOSTS = new Set(['0.0.0.0', '127.0.0.1', '::1', '[::1]', 'localhost'])
const TEXT_PREVIEW_MAX_BYTES = 512 * 1024

const PREVIEW_LANGUAGE_BY_EXT = {
  '.c': 'c',
  '.conf': 'ini',
  '.cpp': 'cpp',
  '.css': 'css',
  '.csv': 'csv',
  '.go': 'go',
  '.graphql': 'graphql',
  '.h': 'c',
  '.hpp': 'cpp',
  '.html': 'html',
  '.java': 'java',
  '.js': 'javascript',
  '.json': 'json',
  '.jsx': 'jsx',
  '.kt': 'kotlin',
  '.lua': 'lua',
  '.md': 'markdown',
  '.mjs': 'javascript',
  '.py': 'python',
  '.rb': 'ruby',
  '.rs': 'rust',
  '.sh': 'shell',
  '.sql': 'sql',
  '.svg': 'xml',
  '.toml': 'toml',
  '.ts': 'typescript',
  '.tsx': 'tsx',
  '.txt': 'text',
  '.xml': 'xml',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.zsh': 'shell'
}

function looksBinary(buffer) {
  if (!buffer.length) {
    return false
  }

  let suspicious = 0

  for (const byte of buffer) {
    if (byte === 0) {
      return true
    }

    // Allow common whitespace controls: tab, LF, CR.
    if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
      suspicious += 1
    }
  }

  return suspicious / buffer.length > 0.12
}

function previewFileMetadata(filePath, mimeType) {
  let byteSize = 0
  let binary = false

  try {
    const stat = fs.statSync(filePath)
    byteSize = stat.size

    if (!mimeType.startsWith('image/')) {
      const fd = fs.openSync(filePath, 'r')

      try {
        const sample = Buffer.alloc(Math.min(byteSize, 4096))
        const bytesRead = fs.readSync(fd, sample, 0, sample.length, 0)
        binary = looksBinary(sample.subarray(0, bytesRead))
      } finally {
        fs.closeSync(fd)
      }
    }
  } catch {
    // Metadata is best-effort; the read handlers surface hard errors later.
  }

  return {
    binary,
    byteSize,
    large: byteSize > TEXT_PREVIEW_MAX_BYTES
  }
}

app.setName(APP_NAME)

// Windows toast notifications silently no-op unless an AppUserModelID is set:
// `new Notification().show()` returns without error and nothing appears. The
// AUMID must match the installed Start Menu shortcut's AUMID, which
// electron-builder derives from the build `appId` (com.nousresearch.hermes) —
// keep this string in sync with package.json `build.appId`. macOS/Linux don't
// need this, so gate it on Windows. (Fixes: desktop approval/turn notifications
// never firing on Windows.)
if (IS_WINDOWS) {
  app.setAppUserModelId('com.nousresearch.hermes')
}

// Seed the native About panel with the live Hermes version. This is refreshed
// on every open via the explicit "About" menu handler (refreshAboutPanel), so
// an in-place `hermes update` mid-session is reflected without an app restart;
// the seed here just covers the first open and any non-menu invocation path.
app.setAboutPanelOptions({
  applicationName: APP_NAME,
  applicationVersion: resolveHermesVersion(),
  copyright: 'Copyright © 2026 Nous Research'
})

// Custom scheme for streaming local media (video/audio) into the renderer.
// Reading large media through `readFileDataUrl` failed: it base64-loads the
// whole file into memory and is hard-capped at DATA_URL_READ_MAX_BYTES (16 MB),
// so any non-trivial video silently refused to load. Streaming via a protocol
// handler removes the size cap and gives the <video> element seekable,
// range-aware playback. Must be registered before the app is ready.
const MEDIA_PROTOCOL = 'hermes-media'

// Only audio/video may be streamed. Without this the handler would read any
// non-blocklisted local file (no size cap) for any `fetch(hermes-media://…)`.
const STREAMABLE_MEDIA_EXTS = new Set([
  '.avi',
  '.flac',
  '.m4a',
  '.mkv',
  '.mov',
  '.mp3',
  '.mp4',
  '.ogg',
  '.opus',
  '.wav',
  '.webm'
])

protocol.registerSchemesAsPrivileged([
  {
    scheme: MEDIA_PROTOCOL,
    privileges: {
      secure: true,
      standard: true,
      stream: true,
      supportFetchAPI: true
    }
  }
])

function registerMediaProtocol() {
  protocol.handle(MEDIA_PROTOCOL, async request => {
    let resolvedPath

    try {
      const url = new URL(request.url)

      const filePath = decodeURIComponent(url.pathname.replace(/^\/+/, ''))

      ;({ resolvedPath } = await resolveReadableFileForIpc(filePath, { purpose: 'Media stream' }))
    } catch {
      return new Response('Media not found', { status: 404 })
    }

    if (!STREAMABLE_MEDIA_EXTS.has(path.extname(resolvedPath).toLowerCase())) {
      return new Response('Unsupported media type', { status: 415 })
    }

    // Delegate to Electron's net stack on a file:// URL — it resolves the
    // content-type and honors Range requests so seeking works. Forward the
    // renderer's headers (notably Range) and skip custom-protocol re-entry.
    return electronNet.fetch(pathToFileURL(resolvedPath).toString(), {
      bypassCustomProtocolHandlers: true,
      headers: request.headers
    })
  })
}

let mainWindow = null
const backendConnectionState = createBackendConnectionState<ReturnType<typeof spawn>, any>()
const remoteLiveness = new RemoteLivenessTracker()
const remoteRevalidation = new RemoteRevalidationCoordinator()
// True while connection-config:apply soft-rehomes the primary — suppresses the
// backend-exit toast so an intentional kill doesn't look like a crash.
let softRehomeInProgress = false
// Additional per-profile backends, keyed by profile name. The PRIMARY backend
// (the desktop's launch profile) stays managed by backendConnectionState +
// startHermes(); this pool only holds EXTRA profile
// backends spawned lazily when a session belongs to a different profile. A user
// with no named profiles never populates this map, so their experience is
// byte-for-byte the single-backend behavior.
const backendPool = new Map() // profile -> { process, port, token, connectionPromise, lastActiveAt }
// Keep the pool light: cap concurrent profile backends (LRU eviction) and reap
// idle ones. A user idles at exactly the primary backend; pool backends only
// exist while a non-primary profile is actively being chatted through.
const POOL_MAX_BACKENDS = Math.max(1, Number(process.env.HERMES_DESKTOP_POOL_MAX) || 3)
const POOL_IDLE_MS = Math.max(60_000, Number(process.env.HERMES_DESKTOP_POOL_IDLE_MS) || 10 * 60_000)
// A backend touched within this window has a live renderer socket (the keepalive
// pings every 60s for every open profile). LRU eviction must spare these — a
// concurrent multi-profile session keeps several backends "fresh" at once, and
// killing one to honor the soft cap would abort a running agent.
const POOL_KEEPALIVE_FRESH_MS = 90_000
let poolIdleReaper = null
// Auto-reload budget for renderer crashes. A deterministic startup crash would
// otherwise loop forever (reload → crash → reload), pinning CPU and spamming
// logs. Allow a few reloads per rolling window, then stop and leave the dead
// window so the user can read the error / quit.
const RENDERER_RELOAD_WINDOW_MS = 60_000
const RENDERER_RELOAD_MAX = 3
let rendererReloadTimes = []
// Latched bootstrap failure: when the first-launch install fails, we hold
// onto the error so subsequent startHermes() calls (e.g. the renderer's
// ensureGatewayOpen retrying after the WS won't open) return the same error
// instead of re-running install.ps1 in a hot loop. Cleared explicitly by
// the renderer's "Reload and retry" path or by quitting the app.
let bootstrapFailure = null
// Latched non-bootstrap backend spawn failure — stops getConnection() from
// respawning hermes serve backend children in a tight loop while boot is broken.
let backendStartFailure = null
// Active first-launch install, so the renderer's Cancel button (and app quit)
// can abort the in-flight install.sh/ps1 instead of leaving it running.
let bootstrapAbortController = null
let connectionConfigCache = null
let connectionConfigCacheMtime = null
const hermesLog = []
const previewWatchers = new Map()
let previewShortcutActive = false
let desktopLogBuffer = ''
let desktopLogFlushTimer = null
let desktopLogFlushPromise = Promise.resolve()
let nativeThemeListenerInstalled = false

let bootProgressState = {
  error: null,
  fakeMode: BOOT_FAKE_MODE,
  message: 'Waiting to start Hermes backend',
  phase: 'idle',
  progress: 0,
  running: false,
  timestamp: Date.now()
}

// Pure planner: ordered fs ops to bound a live log of `size`. [] = nothing.
// Each step is ['rm', path] or ['mv', src, dst]; executed best-effort so a
// missing chain link never aborts the rest.
function planDesktopLogRotation(size) {
  if (size < DESKTOP_LOG_MAX_BYTES) {
    return []
  }

  const backups = n => Array.from({ length: n }, (_, i) => desktopLogBackupPath(i + 1))

  // Pathological boot-loop log: reclaim live + every backup outright.
  if (size > DESKTOP_LOG_DISCARD_BYTES) {
    return [DESKTOP_LOG_PATH, ...backups(DESKTOP_LOG_BACKUP_COUNT)].map(p => ['rm', p])
  }

  // Cascade: drop oldest, shift each up, live -> .1.
  const ops = [['rm', desktopLogBackupPath(DESKTOP_LOG_BACKUP_COUNT)]]

  for (let i = DESKTOP_LOG_BACKUP_COUNT - 1; i >= 1; i--) {
    ops.push(['mv', desktopLogBackupPath(i), desktopLogBackupPath(i + 1)])
  }

  ops.push(['mv', DESKTOP_LOG_PATH, desktopLogBackupPath(1)])

  return ops
}

function rotateDesktopLogIfNeededSync() {
  let size

  try {
    size = fs.statSync(DESKTOP_LOG_PATH).size
  } catch {
    return // No live file yet — the append (re)creates it.
  }

  for (const [op, src, dst] of planDesktopLogRotation(size)) {
    try {
      if (op === 'rm') {
        fs.rmSync(src, { force: true })
      } else {
        fs.renameSync(src, dst)
      }
    } catch {
      // Best-effort — logging must never block startup/shutdown.
    }
  }
}

async function rotateDesktopLogIfNeededAsync() {
  let size

  try {
    size = (await fs.promises.stat(DESKTOP_LOG_PATH)).size
  } catch {
    return // No live file yet — the append (re)creates it.
  }

  for (const [op, src, dst] of planDesktopLogRotation(size)) {
    try {
      if (op === 'rm') {
        await fs.promises.rm(src, { force: true })
      } else {
        await fs.promises.rename(src, dst)
      }
    } catch {
      // Best-effort — logging must never crash the shell.
    }
  }
}

function flushDesktopLogBufferSync() {
  if (!desktopLogBuffer) {
    return
  }

  const chunk = desktopLogBuffer
  desktopLogBuffer = ''

  try {
    fs.mkdirSync(path.dirname(DESKTOP_LOG_PATH), { recursive: true })
    rotateDesktopLogIfNeededSync()
    fs.appendFileSync(DESKTOP_LOG_PATH, chunk)
  } catch {
    // Logging must never block app startup/shutdown.
  }
}

function flushDesktopLogBufferAsync() {
  if (!desktopLogBuffer) {
    return desktopLogFlushPromise
  }

  const chunk = desktopLogBuffer
  desktopLogBuffer = ''

  desktopLogFlushPromise = desktopLogFlushPromise
    .then(async () => {
      await fs.promises.mkdir(path.dirname(DESKTOP_LOG_PATH), { recursive: true })
      await rotateDesktopLogIfNeededAsync()
      await fs.promises.appendFile(DESKTOP_LOG_PATH, chunk)
    })
    .catch(() => {
      // Logging must never crash the desktop shell.
    })

  return desktopLogFlushPromise
}

function scheduleDesktopLogFlush() {
  if (desktopLogFlushTimer) {
    return
  }

  desktopLogFlushTimer = setTimeout(() => {
    desktopLogFlushTimer = null
    void flushDesktopLogBufferAsync()
  }, DESKTOP_LOG_FLUSH_MS)
}

function rememberLog(chunk) {
  const text = String(chunk || '').trim()

  if (!text) {
    return
  }

  const lines = text.split(/\r?\n/).map(line => `[hermes] ${line}`)
  hermesLog.push(...lines)

  if (hermesLog.length > 300) {
    hermesLog.splice(0, hermesLog.length - 300)
  }

  desktopLogBuffer += `${lines.join('\n')}\n`

  if (desktopLogBuffer.length >= DESKTOP_LOG_BUFFER_MAX_CHARS) {
    if (desktopLogFlushTimer) {
      clearTimeout(desktopLogFlushTimer)
      desktopLogFlushTimer = null
    }

    void flushDesktopLogBufferAsync()

    return
  }

  scheduleDesktopLogFlush()
}

function openExternalUrl(rawUrl) {
  const raw = String(rawUrl || '').trim()

  if (!raw) {
    return false
  }

  let parsed

  try {
    parsed = new URL(raw)
  } catch {
    return false
  }

  // `file://` URLs come from the artifacts panel (the renderer can't open
  // them itself because Chromium blocks file:// navigation from the app
  // origin). Hand them to `shell.openPath`, which dispatches to the OS
  // file association. If the OS can't open it (`error` is a non-empty
  // string), fall back to revealing the file in the system file manager.
  if (parsed.protocol === 'file:') {
    let localPath

    try {
      localPath = resolveRequestedPathForIpc(parsed.toString(), { purpose: 'Open external file' })
    } catch {
      return false
    }

    void shell
      .openPath(localPath)
      .then(error => {
        if (!error) {
          return
        }

        rememberLog(`[file] openPath failed: ${error}; revealing in folder instead`)

        try {
          shell.showItemInFolder(localPath)
        } catch (revealError) {
          rememberLog(`[file] showItemInFolder failed: ${revealError.message}`)
        }
      })
      .catch(error => rememberLog(`[file] openPath rejected: ${error.message}`))

    return true
  }

  if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
    return false
  }

  const url = parsed.toString()

  if (IS_WSL) {
    rememberLog(`[link] opening via WSL→Windows: ${url}`)

    const proc = spawn('cmd.exe', ['/c', 'start', '""', url], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true
    })

    proc.on('error', error => {
      rememberLog(`[link] cmd.exe start failed: ${error.message}; falling back to xdg-open`)
      shell.openExternal(url).catch(fallback => rememberLog(`[link] xdg-open failed: ${fallback.message}`))
    })
    proc.unref()

    return true
  }

  shell.openExternal(url).catch(error => rememberLog(`[link] openExternal failed: ${error.message}`))

  return true
}

async function openPreviewInBrowser(rawUrl) {
  const raw = String(rawUrl || '').trim()

  if (!raw) {
    return false
  }

  let parsed

  try {
    parsed = new URL(raw)
  } catch {
    return false
  }

  if (parsed.protocol === 'file:') {
    let localPath

    try {
      localPath = resolveRequestedPathForIpc(parsed.toString(), { purpose: 'Open preview in browser' })
    } catch {
      return false
    }

    await shell.openExternal(pathToFileURL(localPath).toString())

    return true
  }

  return openExternalUrl(raw)
}

function ensureWslWindowsFonts() {
  if (!IS_WSL) {
    return
  }

  const fontsDir = ['/mnt/c/Windows/Fonts', '/mnt/c/windows/fonts'].find(candidate => {
    try {
      return fs.statSync(candidate).isDirectory()
    } catch {
      return false
    }
  })

  if (!fontsDir) {
    return
  }

  try {
    const confDir = path.join(app.getPath('home'), '.config', 'fontconfig', 'conf.d')
    const confPath = path.join(confDir, '99-hermes-wsl-windows-fonts.conf')
    let existing = ''

    try {
      existing = fs.readFileSync(confPath, 'utf8')
    } catch {
      existing = ''
    }

    if (existing.includes(fontsDir)) {
      return
    }

    fs.mkdirSync(confDir, { recursive: true })
    fs.writeFileSync(
      confPath,
      `<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "fonts.dtd">\n<fontconfig>\n  <dir>${fontsDir}</dir>\n</fontconfig>\n`
    )
    rememberLog(`[fonts] wired WSL Windows fonts for renderer: ${fontsDir}`)

    const cache = spawn('fc-cache', ['-f', fontsDir], { detached: true, stdio: 'ignore' })
    cache.on('error', () => undefined)
    cache.unref()
  } catch (error) {
    rememberLog(`[fonts] WSL font setup skipped: ${error.message}`)
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function clampBootProgress(value) {
  const numeric = Number(value)

  if (!Number.isFinite(numeric)) {
    return 0
  }

  return Math.max(0, Math.min(100, Math.round(numeric)))
}

function broadcastBootProgress() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    return
  }

  const { webContents } = mainWindow

  if (!webContents || webContents.isDestroyed()) {
    return
  }

  webContents.send('hermes:boot-progress', bootProgressState)
}

// Bootstrap-event broadcast channel + state. The bootstrap runner emits a
// stream of events (manifest, stage, log, complete, failed) that the renderer
// install overlay subscribes to. We also keep a running snapshot:
//   - manifest: the stage list (rendered as a checklist in the overlay)
//   - stages:   per-stage state ('pending' | 'running' | 'succeeded' |
//               'skipped' | 'failed') keyed by stage name
//   - active:   true while a bootstrap is in flight; false otherwise
//   - error:    last 'failed' event's error message
//   - log:      bounded ring buffer of the last 200 log lines for the
//               "Show details" affordance in the overlay
//
// The snapshot is queryable via the hermes:bootstrap:get IPC handler so a
// reloaded renderer (e.g. devtools reload during dev) recovers state.
// Bootstrap log ring: bounded buffer so a long install (npm + playwright
// downloads can emit thousands of lines) doesn't grow unbounded in memory
// AND so the renderer's getBootstrapState() reply stays a reasonable size.
// We keep enough to cover an entire failed stage's transcript so the
// 'Copy output' button gives the user actually-actionable context, not
// just the last few lines.
const BOOTSTRAP_LOG_RING_MAX = 500

let bootstrapState = {
  active: false,
  manifest: null,
  stages: {},
  error: null,
  log: [],
  startedAt: null,
  completedAt: null,
  unsupportedPlatform: null
}

function broadcastBootstrapEvent(ev) {
  if (ev.type === 'manifest') {
    bootstrapState.manifest = ev
    bootstrapState.active = true
    bootstrapState.startedAt = bootstrapState.startedAt || Date.now()
    bootstrapState.stages = {}

    for (const stage of ev.stages || []) {
      bootstrapState.stages[stage.name] = { state: 'pending', json: null, durationMs: null, error: null }
    }
  } else if (ev.type === 'stage') {
    bootstrapState.stages[ev.name] = {
      state: ev.state,
      durationMs: ev.durationMs ?? null,
      json: ev.json ?? null,
      error: ev.error ?? null
    }
  } else if (ev.type === 'log') {
    bootstrapState.log.push({ ts: Date.now(), stage: ev.stage || null, line: ev.line, stream: ev.stream || 'stdout' })

    if (bootstrapState.log.length > BOOTSTRAP_LOG_RING_MAX) {
      bootstrapState.log.splice(0, bootstrapState.log.length - BOOTSTRAP_LOG_RING_MAX)
    }
  } else if (ev.type === 'complete') {
    bootstrapState.active = false
    bootstrapState.completedAt = Date.now()
    bootstrapState.error = null
    bootstrapState.unsupportedPlatform = null
  } else if (ev.type === 'failed') {
    bootstrapState.active = false
    bootstrapState.error = ev.error || 'unknown error'
  } else if (ev.type === 'unsupported-platform') {
    bootstrapState.active = false
    bootstrapState.unsupportedPlatform = {
      platform: ev.platform,
      activeRoot: ev.activeRoot,
      installCommand: ev.installCommand,
      docsUrl: ev.docsUrl
    }
  }

  if (!mainWindow || mainWindow.isDestroyed()) {
    return
  }

  const { webContents } = mainWindow

  if (!webContents || webContents.isDestroyed()) {
    return
  }

  webContents.send('hermes:bootstrap:event', ev)
}

function getBootstrapState() {
  return bootstrapState
}

function updateBootProgress(update, options: { allowDecrease?: boolean } = {}) {
  const nextProgressRaw =
    typeof update.progress === 'number' ? clampBootProgress(update.progress) : bootProgressState.progress

  const nextProgress = options.allowDecrease ? nextProgressRaw : Math.max(bootProgressState.progress, nextProgressRaw)

  bootProgressState = {
    ...bootProgressState,
    ...update,
    error: update.error === undefined ? bootProgressState.error : update.error,
    fakeMode: BOOT_FAKE_MODE || Boolean(update.fakeMode),
    progress: nextProgress,
    timestamp: Date.now()
  }

  if (update.message) {
    rememberLog(`[boot] ${update.message}`)
  }

  broadcastBootProgress()
}

async function advanceBootProgress(phase, message, progress) {
  updateBootProgress({
    phase,
    message,
    progress,
    running: true,
    error: null
  })

  if (BOOT_FAKE_MODE) {
    await sleep(BOOT_FAKE_STEP_MS)
  }
}

function fileExists(filePath) {
  try {
    return fs.statSync(filePath).isFile()
  } catch {
    return false
  }
}

function directoryExists(filePath) {
  try {
    return fs.statSync(filePath).isDirectory()
  } catch {
    return false
  }
}

// --- in-app update mutual exclusion (#50238) -------------------------------
// The Tauri updater writes HERMES_HOME/.hermes-update-in-progress for the whole
// duration of an `--update` run (see update.rs UpdateMarkerGuard). If the user
// relaunches the desktop mid-update — because the window vanished with no
// progress and looks crashed — a fresh instance must NOT spawn its own local
// backend: that backend re-locks the venv shim, the updater's straggler cleanup
// (`force_kill_other_hermes`, taskkill /IM hermes.exe) kills it, the launch
// fails with the 45s "backend didn't come up" error, and the relaunch/kill
// cycle loops. Instead the fresh instance parks until the update finishes, then
// brings the backend up itself (it is the surviving instance — the updater's
// own relaunch hits our single-instance lock and quits). Marker parsing +
// staleness self-heal live in update-marker.ts (unit-tested).

// How long we'll park the launch waiting for a live update to finish before
// giving up and starting the backend anyway (belt-and-suspenders alongside the
// marker's own age ceiling; covers a stuck-but-alive updater).
const UPDATE_WAIT_TIMEOUT_MS = 20 * 60 * 1000
const UPDATE_WAIT_POLL_MS = 1000
// How long the desktop lingers on the "updating, don't reopen" overlay after
// spawning the detached updater, before it quits to release the venv shim. The
// old 600ms was long enough to register the child process but far too short for
// the user to READ the overlay — the window just vanished, looked like a crash,
// and the user relaunched mid-update (the #50238 restart-loop trigger). A
// couple of seconds lets the message land and bridges the gap until the
// updater's own progress window appears. (#50419)
const UPDATE_HANDOFF_DWELL_MS = 2500

// Block until no live update is in progress (or we hit the wait timeout).
// Emits a boot-progress phase so the renderer shows "Update in progress…"
// rather than a frozen splash. Returns true if it parked at all.
async function waitForUpdateToFinish() {
  let marker = readLiveUpdateMarker(HERMES_HOME)

  if (!marker) {
    return false
  }

  rememberLog(`[updates] update in progress (pid=${marker.pid}); deferring backend start until it finishes`)
  const deadline = Date.now() + UPDATE_WAIT_TIMEOUT_MS

  while (marker && Date.now() < deadline) {
    await advanceBootProgress(
      'backend.update-wait',
      'An update is finishing — Hermes will start automatically when it completes…',
      12
    )
    await new Promise(r => setTimeout(r, UPDATE_WAIT_POLL_MS))
    marker = readLiveUpdateMarker(HERMES_HOME)
  }

  if (marker) {
    rememberLog('[updates] update still in progress after wait timeout; starting backend anyway')
  } else {
    rememberLog('[updates] update finished; proceeding with backend start')
  }

  return true
}

function unpackedPathFor(filePath) {
  return filePath.replace(/app\.asar(?=$|[\\/])/, 'app.asar.unpacked')
}

function findOnPath(command) {
  if (!command) {
    return null
  }

  if (path.isAbsolute(command) || command.includes(path.sep) || (IS_WINDOWS && command.includes('/'))) {
    if (!fileExists(command)) {
      return null
    }

    if (isWindowsBinaryPathInWsl(command, { isWsl: IS_WSL })) {
      return null
    }

    return command
  }

  const pathEntries = String(process.env.PATH || '')
    .split(path.delimiter)
    .filter(Boolean)

  // On Windows, try PATHEXT extensions BEFORE the bare (empty-extension) name.
  // A real command must resolve via its .exe/.cmd (Windows command-resolution
  // semantics consult PATHEXT); an extensionless file — e.g. a Git-Bash
  // shell-script shim named `hermes` — must not shadow `hermes.cmd`/`hermes.exe`.
  // The empty entry is kept LAST so callers that already include the extension
  // (py.exe, pwsh.exe, powershell.exe) still resolve.
  const extensions = buildPathExtCandidates(process.env.PATHEXT, IS_WINDOWS)

  for (const entry of pathEntries) {
    for (const extension of extensions) {
      const candidate = path.join(entry, `${command}${extension}`)

      if (fileExists(candidate)) {
        return candidate
      }
    }
  }

  return null
}

function isCommandScript(command) {
  return IS_WINDOWS && /\.(cmd|bat)$/i.test(command || '')
}

function unwrapWindowsVenvHermesCommand(command, backendArgs) {
  return resolveVenvHermesCommand(command, backendArgs, {
    isWindows: IS_WINDOWS,
    isCommandScript,
    fileExists,
    directoryExists,
    canImportHermesCli,
    getVenvPython,
    getVenvSitePackagesEntries,
    buildDesktopBackendEnv,
    hermesHome: HERMES_HOME,
    resolvePath: (...segments) => path.resolve(...segments),
    dirname: p => path.dirname(p),
    basename: p => path.basename(p),
    rememberLog
  })
}

// Does the resolved runtime understand the `serve` subcommand? The desktop
// spawns `hermes serve`; runtimes older than serve only have `dashboard`. We
// detect support so getBackendArgsForRuntime() can route old runtimes through
// the legacy `dashboard --no-open` form instead of crashing on an unknown
// subcommand (would brick every user mid-upgrade — #54568 follow-up).
//
// Fast path: read the runtime's own dashboard.py (instant, covers managed
// installs, dev checkouts, and the Windows venv). Fallback: probe the CLI once
// (covers a bare `hermes` resolved from PATH with no known source root). Result
// is cached per resolved runtime so we probe at most once per backend.
const _serveSupportCache = new Map()

function backendSupportsServe(backend) {
  if (!backend || !backend.command) {
    return true
  }

  const key = `${backend.command}::${backend.root || ''}`

  if (_serveSupportCache.has(key)) {
    return _serveSupportCache.get(key)
  }

  let supported = null

  if (backend.root) {
    try {
      const src = fs.readFileSync(path.join(backend.root, 'hermes_cli', 'subcommands', 'dashboard.py'), 'utf8')
      supported = sourceDeclaresServe(src)
    } catch {
      supported = null // source unreadable — fall through to the probe
    }
  }

  if (supported === null) {
    try {
      const prefix = backend.args && backend.args[0] === '-m' ? backend.args.slice(0, 2) : []
      execFileSync(backend.command, [...prefix, 'serve', '--help'], {
        cwd: backend.root || undefined,
        env: { ...process.env, HERMES_HOME, ...(backend.env || {}) },
        timeout: 15000,
        stdio: 'ignore',
        windowsHide: true
      })
      supported = true
    } catch {
      supported = false
    }
  }

  _serveSupportCache.set(key, supported)
  rememberLog(
    `[backend] \`serve\` ${supported ? 'supported' : 'unsupported → routing via legacy `dashboard`'} for ${backend.label || key}`
  )

  return supported
}

// Given a resolved backend whose args target `serve`, return the args the
// runtime actually understands: unchanged when `serve` is supported, or
// rewritten to `dashboard --no-open` for older runtimes.
function getBackendArgsForRuntime(backend) {
  return backendSupportsServe(backend) ? backend.args : dashboardFallbackArgs(backend.args)
}

function normalizeExecutablePathForCompare(commandPath) {
  if (!commandPath) {
    return null
  }

  let resolved = path.resolve(String(commandPath))

  try {
    resolved = fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved)
  } catch {
    // Fallback to path.resolve() above.
  }

  return IS_WINDOWS ? resolved.toLowerCase() : resolved
}

function looksLikeDesktopAppBinary(commandPath) {
  if (!IS_WINDOWS || !commandPath) {
    return false
  }

  const normalizedCandidate = normalizeExecutablePathForCompare(commandPath)
  const normalizedCurrentExec = normalizeExecutablePathForCompare(process.execPath)

  if (normalizedCandidate && normalizedCurrentExec && normalizedCandidate === normalizedCurrentExec) {
    return true
  }

  let resolved = path.resolve(String(commandPath))

  try {
    resolved = fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved)
  } catch {
    // Keep resolved path fallback.
  }

  const resourcesDir = path.join(path.dirname(resolved), 'resources')

  return (
    fileExists(path.join(resourcesDir, 'app.asar')) || directoryExists(path.join(resourcesDir, 'app.asar.unpacked'))
  )
}

function isHermesSourceRoot(root) {
  return directoryExists(root) && fileExists(path.join(root, 'hermes_cli', 'main.py'))
}

function findPythonForRoot(root) {
  const override = process.env.HERMES_DESKTOP_PYTHON

  if (override && fileExists(override)) {
    return override
  }

  const relativePaths = IS_WINDOWS
    ? [path.join('.venv', 'Scripts', 'python.exe'), path.join('venv', 'Scripts', 'python.exe')]
    : [path.join('.venv', 'bin', 'python'), path.join('venv', 'bin', 'python')]

  for (const relativePath of relativePaths) {
    const candidate = path.join(root, relativePath)

    if (fileExists(candidate)) {
      return candidate
    }
  }

  return findSystemPython()
}

function findSystemPython() {
  if (!IS_WINDOWS) {
    // POSIX systems: PATH lookup is safe.
    for (const command of ['python3', 'python']) {
      const candidate = findOnPath(command)

      if (candidate) {
        return candidate
      }
    }

    return null
  }

  // Windows: PATH-based detection has TWO landmines we have to dodge.
  //
  //  (1) The Microsoft Store "Python stub" lives at
  //      %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe and is on PATH
  //      by default on modern Windows. It's a redirector that opens the
  //      Store window if no Store Python is installed. Running it for
  //      `-m venv` would either succeed (real Store install — fine) or
  //      pop the Store dialog (bad UX during boot).
  //  (2) `py.exe` (Python launcher) is missing from per-user installs
  //      that didn't check the launcher option, so PATH-only checks
  //      miss real Python 3.13 installs (user-reported case).
  //
  // We also restrict ourselves to Python 3.11–3.13. 3.14 is the latest
  // CPython but several Hermes deps (notably pywinpty's Rust-built
  // windows_x86_64_msvc crate) don't yet publish 3.14 wheels, and
  // `pip install -e .` falls back to source-build, which fails without
  // a Rust toolchain. install.ps1 sidesteps this by pinning to 3.11
  // via uv; until we add the same uv-managed Python pathway here, the
  // simplest fix is to refuse 3.14 detection and let the NSIS prereq
  // page offer to install 3.11 alongside.
  //
  // Strategy: probe in three passes, in order from most-precise to
  // least-precise, and ONLY use PATH lookup as a last resort after
  // confirming the candidate isn't the WindowsApps redirector.
  //
  //  Pass 1: PEP 514 registry — every standards-compliant Python
  //          installer registers itself at SOFTWARE\Python\PythonCore.
  //          The MS Store stub does NOT register here, so a hit means
  //          a real Python install. Versions are explicit so we
  //          inherently filter 3.14 out.
  //  Pass 2: Filesystem probe of standard install locations
  //          (Program Files, LocalAppData\Programs\Python). Same
  //          version filtering by directory name.
  //  Pass 3: PATH lookup of `py.exe` (the launcher itself never
  //          triggers the Store) — but call it with a version flag so
  //          we resolve to a SPECIFIC supported version, not whatever
  //          py.exe's default is (which on a 3.14-only box would be
  //          3.14).

  const SUPPORTED_VERSIONS = ['3.11', '3.12', '3.13']
  const SUPPORTED_VERSIONS_NO_DOT = ['311', '312', '313']

  // Pass 1: registry. Use `reg query` since main process doesn't have
  // a reliable in-process registry API across all electron versions.
  for (const hive of ['HKLM', 'HKCU']) {
    for (const version of SUPPORTED_VERSIONS) {
      try {
        const out = execFileSync(
          'reg',
          ['query', `${hive}\\SOFTWARE\\Python\\PythonCore\\${version}\\InstallPath`, '/ve', '/reg:64'],
          hiddenWindowsChildOptions({ encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
        )

        // Output format: "    (Default)    REG_SZ    C:\Path\To\Python\"
        const match = out.match(/REG_SZ\s+(.+?)\s*$/m)

        if (match) {
          const installPath = match[1].trim()
          const pythonExe = path.join(installPath, 'python.exe')

          if (fileExists(pythonExe)) {
            return pythonExe
          }
        }
      } catch {
        // Key not present — try next.
      }
    }
  }

  // Pass 2: filesystem probe of standard locations.
  const programFiles = process.env['ProgramFiles'] || 'C:\\Program Files'
  const localAppData = process.env.LOCALAPPDATA || ''

  for (const versionDir of SUPPORTED_VERSIONS_NO_DOT) {
    const systemWide = path.join(programFiles, `Python${versionDir}`, 'python.exe')

    if (fileExists(systemWide)) {
      return systemWide
    }

    if (localAppData) {
      const perUser = path.join(localAppData, 'Programs', 'Python', `Python${versionDir}`, 'python.exe')

      if (fileExists(perUser)) {
        return perUser
      }
    }
  }

  // Pass 3: py.exe with explicit version flag. The launcher itself is
  // safe to invoke (no Store popup) and `py -3.13 -c "import sys;
  // print(sys.executable)"` resolves to the actual python.exe path of
  // the requested version. We try in version-priority order so the
  // first hit wins.
  const pyExe = findOnPath('py.exe')

  if (pyExe) {
    for (const version of SUPPORTED_VERSIONS) {
      try {
        const out = execFileSync(
          pyExe,
          [`-${version}`, '-c', 'import sys; print(sys.executable)'],
          hiddenWindowsChildOptions({
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
          })
        )

        const candidate = out.trim()

        if (candidate && fileExists(candidate)) {
          return candidate
        }
      } catch {
        // py couldn't find that version — try next.
      }
    }
  }

  // We deliberately do NOT fall back to plain `python.exe` on PATH.
  // Without a way to verify the version safely (running `python -V`
  // risks the Microsoft Store popup), accepting whatever's there
  // could land us on 3.14 and trigger the Rust-build-from-source
  // failure. Better to return null and let the NSIS prereq page
  // offer to install a known-good 3.11 via winget.
  return null
}

// findGitBash — locate bash.exe on Windows. Hermes' terminal tool requires
// bash (POSIX shell), and on Windows that's almost always Git for Windows'
// bundled Git Bash. We check the same set of locations tools/environments/
// local.py:_find_bash() checks at runtime, so a positive result here means
// the agent will be able to start a terminal too.
//
// On non-Windows hosts bash is part of the OS and this just returns the
// first bash on PATH.
function findGitBash() {
  if (!IS_WINDOWS) {
    return findOnPath('bash')
  }

  // install.ps1 drops PortableGit at %LOCALAPPDATA%\hermes\git\... — checked
  // first so users who installed via install.ps1 are detected before we
  // start probing system-wide locations.
  const localAppData = process.env.LOCALAPPDATA || ''
  const candidates = []

  if (localAppData) {
    candidates.push(path.join(localAppData, 'hermes', 'git', 'bin', 'bash.exe'))
    candidates.push(path.join(localAppData, 'hermes', 'git', 'usr', 'bin', 'bash.exe'))
  }

  // Standard Git for Windows install locations.
  candidates.push(path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'Git', 'bin', 'bash.exe'))
  candidates.push(path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Git', 'bin', 'bash.exe'))

  if (localAppData) {
    candidates.push(path.join(localAppData, 'Programs', 'Git', 'bin', 'bash.exe'))
  }

  for (const candidate of candidates) {
    if (fileExists(candidate)) {
      return candidate
    }
  }

  // Last resort — bash on PATH (covers WSL bash, MSYS2, custom installs).
  // On WSL hosts findOnPath itself filters out Windows-binary paths via
  // isWindowsBinaryPathInWsl, so we won't hand back a wsl.exe shim either.
  return findOnPath('bash')
}

function getVenvPython(venvRoot) {
  return path.join(venvRoot, IS_WINDOWS ? path.join('Scripts', 'python.exe') : path.join('bin', 'python'))
}

// Windows console-window flashes are governed by the *parent's* console, not by
// each child spawn. A GUI-subsystem parent (pythonw.exe) has no console, so every
// console-subsystem child it spawns (git, gh, cmd, ...) must allocate its own —
// which flashes a window. A console-subsystem parent (python.exe) instead owns a
// single console that all of its children inherit, so none of them flash.
//
// Note this change adds no new creationflag: the backend spawn is ALREADY wrapped
// in hiddenWindowsChildOptions() (windowsHide: true), but that setting is INERT
// against pythonw.exe — a GUI-subsystem process has no console for it to act on.
// Switching the backend to the venv's console python.exe is what makes the
// existing wrapper load-bearing: with windowsHide the process comes up owning a
// *windowless* console (verified at runtime — it has an attachable console whose
// window handle is NULL), and its children inherit that one windowless console
// instead of each allocating a visible one.
//
// This makes "no flashing windows" a property of the one backend launch rather
// than a flag that has to be remembered at every descendant spawn site. Restoring
// console python also restores stdout, so the backend announces its port on the
// normal HERMES_DASHBOARD_READY stdout line and no ready-file side channel is
// needed.

function makeDashboardReadyFile() {
  const dir = path.join(app.getPath('userData'), 'backend-ready')
  fs.mkdirSync(dir, { recursive: true })

  return path.join(dir, `dashboard-${process.pid}-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.json`)
}

// resolveGitBinary — locate git.exe on Windows. A fresh installer-driven
// install only has PortableGit under %LOCALAPPDATA%\hermes\git (never on
// PATH), so a bare spawn('git') ENOENTs and self-update checks fail with
// "Couldn't check for updates". Mirror findGitBash: PortableGit first, then
// standard Git-for-Windows locations, then PATH. Cached after first probe.
let _gitBinaryCache = null

function resolveGitBinary() {
  if (_gitBinaryCache) {
    return _gitBinaryCache
  }

  if (!IS_WINDOWS) {
    _gitBinaryCache = findOnPath('git') || 'git'

    return _gitBinaryCache
  }

  const localAppData = process.env.LOCALAPPDATA || ''
  const candidates = []

  if (localAppData) {
    candidates.push(path.join(localAppData, 'hermes', 'git', 'cmd', 'git.exe'))
    candidates.push(path.join(localAppData, 'hermes', 'git', 'bin', 'git.exe'))
  }

  candidates.push(path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'Git', 'cmd', 'git.exe'))
  candidates.push(path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Git', 'cmd', 'git.exe'))

  if (localAppData) {
    candidates.push(path.join(localAppData, 'Programs', 'Git', 'cmd', 'git.exe'))
  }

  _gitBinaryCache = candidates.find(fileExists) || findOnPath('git') || 'git'

  return _gitBinaryCache
}

// resolveGhBinary — locate the GitHub CLI. GUI-launched apps get a minimal PATH
// that omits Homebrew (/opt/homebrew/bin, /usr/local/bin) where `gh` usually
// lives, so a bare spawn('gh') ENOENTs even though `gh` works in the user's
// terminal. Check the common install locations first, then PATH. Cached.
let _ghBinaryCache = null

function resolveGhBinary() {
  if (_ghBinaryCache) {
    return _ghBinaryCache
  }

  const candidates = []

  if (IS_WINDOWS) {
    candidates.push(path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'GitHub CLI', 'gh.exe'))

    if (process.env.LOCALAPPDATA) {
      candidates.push(path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Links', 'gh.exe'))
    }
  } else {
    const home = app.getPath('home')
    candidates.push('/opt/homebrew/bin/gh', '/usr/local/bin/gh', '/usr/bin/gh', path.join(home, '.local', 'bin', 'gh'))
  }

  _ghBinaryCache = candidates.find(fileExists) || findOnPath('gh') || 'gh'

  return _ghBinaryCache
}

function recentHermesLog() {
  return hermesLog.slice(-20).join('\n')
}

// ─── Self-update (git-pull against the running backend's hermes root) ──────

function readDesktopUpdateConfig() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DESKTOP_UPDATE_CONFIG_PATH, 'utf8'))
    const branch = typeof parsed?.branch === 'string' ? parsed.branch.trim() : ''

    return { branch: branch || DEFAULT_UPDATE_BRANCH }
  } catch {
    return { branch: DEFAULT_UPDATE_BRANCH }
  }
}

// Atomic file write: temp + rename (atomic on all platforms). Prevents
// partial writes on crash/power loss that corrupt JSON config files.
function writeFileAtomic(targetPath, data, encoding?: BufferEncoding) {
  const tmp = targetPath + '.tmp'
  fs.writeFileSync(tmp, data, encoding)
  fs.renameSync(tmp, targetPath)
}

function writeDesktopUpdateConfig(config) {
  fs.mkdirSync(path.dirname(DESKTOP_UPDATE_CONFIG_PATH), { recursive: true })
  writeFileAtomic(DESKTOP_UPDATE_CONFIG_PATH, JSON.stringify(config, null, 2))
}

// ─── Main-window geometry persistence (window-state.json) ──────────────────

function readWindowState() {
  try {
    return sanitizeWindowState(JSON.parse(fs.readFileSync(DESKTOP_WINDOW_STATE_PATH, 'utf8')))
  } catch {
    return null
  }
}

// Persist the window's restored (non-maximized) bounds plus its maximized flag.
// getNormalBounds() keeps the pre-maximize size, so un-maximizing next session
// lands back where the user actually sized the window.
function persistWindowState() {
  if (!mainWindow || mainWindow.isDestroyed() || mainWindow.isMinimized()) {
    return
  }

  try {
    const { x, y, width, height } = mainWindow.getNormalBounds()
    fs.mkdirSync(path.dirname(DESKTOP_WINDOW_STATE_PATH), { recursive: true })
    writeFileAtomic(
      DESKTOP_WINDOW_STATE_PATH,
      JSON.stringify({ x, y, width, height, isMaximized: mainWindow.isMaximized() }, null, 2)
    )
  } catch (err) {
    rememberLog(`[window-state] persist failed: ${err?.message || err}`)
  }
}

// resized/moved fire many times mid-drag on Linux; debounce to one write.
const schedulePersistWindowState = debounce(persistWindowState, 250)

// Zoom's primary store is a main-process JSON file. The renderer localStorage
// mirror lives under Electron's cache/storage folders, which crash recovery
// can move or recreate — wiping the zoom setting exactly when the user just
// recovered from a crash (#56726). JSON survives; localStorage is kept as a
// secondary mirror so pre-JSON installs migrate transparently on first read.
const DESKTOP_ZOOM_STATE_PATH = path.join(app.getPath('userData'), 'zoom-state.json')

function readZoomState() {
  try {
    const raw = JSON.parse(fs.readFileSync(DESKTOP_ZOOM_STATE_PATH, 'utf8'))
    const level = Number(raw?.zoomLevel)

    return Number.isFinite(level) ? level : null
  } catch {
    return null
  }
}

function writeZoomState(zoomLevel) {
  try {
    fs.mkdirSync(path.dirname(DESKTOP_ZOOM_STATE_PATH), { recursive: true })
    writeFileAtomic(DESKTOP_ZOOM_STATE_PATH, JSON.stringify({ zoomLevel }, null, 2))
  } catch (error) {
    rememberLog(`[zoom] json persist failed: ${error?.message || error}`)
  }
}

// Match the backend's source resolution but bias toward a real git checkout.
// Dev → SOURCE_REPO_ROOT. Packaged/CLI install → ACTIVE_HERMES_ROOT.
// HERMES_DESKTOP_HERMES_ROOT always wins so devs can pin a worktree.
function resolveUpdateRoot() {
  const candidates = [
    process.env.HERMES_DESKTOP_HERMES_ROOT && path.resolve(process.env.HERMES_DESKTOP_HERMES_ROOT),
    !IS_PACKAGED && isHermesSourceRoot(SOURCE_REPO_ROOT) ? SOURCE_REPO_ROOT : null,
    isHermesSourceRoot(ACTIVE_HERMES_ROOT) ? ACTIVE_HERMES_ROOT : null
  ].filter(Boolean)

  return candidates.find(c => directoryExists(path.join(c, '.git'))) || candidates[0] || ACTIVE_HERMES_ROOT
}

function runGit(args, options: any = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      resolveGitBinary(),
      IS_WINDOWS ? ['-c', 'windows.appendAtomically=false', ...args] : args,
      hiddenWindowsChildOptions({
        cwd: options.cwd,
        env: { ...process.env, ...((options.env || {}) as any), GIT_TERMINAL_PROMPT: '0' },
        stdio: ['ignore', 'pipe', 'pipe']
      })
    )

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', chunk => {
      const text = chunk.toString()
      stdout += text
      options.onLine?.('stdout', text)
    })
    child.stderr.on('data', chunk => {
      const text = chunk.toString()
      stderr += text
      options.onLine?.('stderr', text)
    })
    child.once('error', reject)
    child.once('exit', code => resolve({ code, stdout, stderr }))
  })
}

const firstLine = text => (text || '').split('\n').find(Boolean) || ''

async function getOriginUrl(updateRoot) {
  const origin = await runGit(['remote', 'get-url', 'origin'], { cwd: updateRoot })

  return origin.code === 0 ? origin.stdout.trim() : ''
}

function emitUpdateProgress(payload) {
  const merged = { stage: 'idle', message: '', percent: null, error: null, ...payload, at: Date.now() }
  rememberLog(`[updates] ${merged.stage}: ${merged.message || merged.error || ''}`)

  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send('hermes:updates:progress', merged)
  }
}

// Self-heal the tracked update branch: if origin no longer publishes it (e.g.
// bb/gui was merged into main and deleted), fall back to main and persist so
// every later check/apply follows main — no manual flip, even for already-
// installed clients. Read-only ls-remote probe; only flips on a definitive
// "ref absent" (exit 2), never on a transient network error, so a flaky
// connection can't strand a user on the wrong branch.
async function resolveHealedBranch(updateRoot, branch) {
  if (!branch || branch === 'main') {
    return branch || 'main'
  }

  const originUrl = await getOriginUrl(updateRoot)
  const remote = isOfficialSshRemote(originUrl) ? OFFICIAL_REPO_HTTPS_URL : 'origin'
  const probe = await runGit(['ls-remote', '--exit-code', '--heads', remote, branch], { cwd: updateRoot })

  if (probe.code !== 2) {
    return branch
  }

  rememberLog(`[updates] origin/${branch} is gone (merged?); falling back to main`)
  const config = readDesktopUpdateConfig()

  if (config.branch !== 'main') {
    writeDesktopUpdateConfig({ ...config, branch: 'main' })
  }

  return 'main'
}

async function checkUpdates() {
  const updateRoot = resolveUpdateRoot()
  let { branch } = readDesktopUpdateConfig()
  const gitDir = path.join(updateRoot, '.git')

  if (!directoryExists(gitDir)) {
    return {
      supported: false,
      reason: 'not-a-git-checkout',
      message: `${updateRoot} isn't a git checkout — desktop self-update only runs against a source install.`,
      hermesRoot: updateRoot,
      branch
    }
  }

  branch = await resolveHealedBranch(updateRoot, branch)
  const originUrl = await getOriginUrl(updateRoot)

  if (isOfficialSshRemote(originUrl)) {
    const git = args => runGit(args, { cwd: updateRoot }).then(r => r.stdout.trim())

    const [currentSha, target, dirtyStr, currentBranch] = await Promise.all([
      git(['rev-parse', 'HEAD']),
      runGit(['ls-remote', OFFICIAL_REPO_HTTPS_URL, `refs/heads/${branch}`], { cwd: updateRoot }),
      git(['status', '--porcelain']),
      git(['rev-parse', '--abbrev-ref', 'HEAD'])
    ])

    const targetSha = firstLine(target.stdout).split(/\s+/)[0] || ''

    if (target.code !== 0 || !targetSha) {
      return {
        supported: true,
        branch,
        error: 'fetch-failed',
        message: firstLine(target.stderr) || 'git ls-remote failed.',
        hermesRoot: updateRoot,
        fetchedAt: Date.now()
      }
    }

    return {
      supported: true,
      branch,
      currentBranch,
      behind: currentSha && currentSha === targetSha ? 0 : 1,
      currentSha,
      targetSha,
      commits: [],
      dirty: dirtyStr.length > 0,
      hermesRoot: updateRoot,
      fetchedAt: Date.now()
    }
  }

  const fetched = await runGit(['fetch', '--quiet', 'origin', branch], { cwd: updateRoot })

  if (fetched.code !== 0) {
    return {
      supported: true,
      branch,
      error: 'fetch-failed',
      message: firstLine(fetched.stderr) || 'git fetch failed.',
      hermesRoot: updateRoot,
      fetchedAt: Date.now()
    }
  }

  const git = args => runGit(args, { cwd: updateRoot }).then(r => r.stdout.trim())

  const [currentSha, targetSha, dirtyStr, currentBranch, shallowStr, mergeBaseStr] = await Promise.all([
    git(['rev-parse', 'HEAD']),
    git(['rev-parse', `origin/${branch}`]),
    git(['status', '--porcelain']),
    git(['rev-parse', '--abbrev-ref', 'HEAD']),
    git(['rev-parse', '--is-shallow-repository']),
    // merge-base exits non-zero with empty stdout when HEAD shares no common
    // ancestor with the freshly fetched tip — exactly the shallow-clone case.
    git(['merge-base', 'HEAD', `origin/${branch}`])
  ])

  const isShallow = shallowStr === 'true'
  const hasMergeBase = Boolean(mergeBaseStr)

  // Only enumerate the commit count when it is meaningful. On a shallow checkout
  // with no merge-base, `rev-list --count` walks the entire remote ancestry
  // (thousands of commits, see #51922) and resolveBehindCount discards the
  // result anyway in favour of a SHA compare — so skip the expensive query.
  const countStr = shouldCountCommits({ isShallow, hasMergeBase })
    ? await git(['rev-list', `HEAD..origin/${branch}`, '--count'])
    : ''

  const behind = resolveBehindCount({
    countStr,
    currentSha,
    targetSha,
    isShallow,
    hasMergeBase
  })

  const commits = behind > 0 ? await readCommitLog(updateRoot, branch) : []

  return {
    supported: true,
    branch,
    currentBranch,
    behind,
    currentSha,
    targetSha,
    commits,
    dirty: dirtyStr.length > 0,
    hermesRoot: updateRoot,
    fetchedAt: Date.now()
  }
}

async function readCommitLog(cwd, branch) {
  const SEP = '\x1f'
  const REC = '\x1e'

  const { stdout } = await runGit(
    ['log', `HEAD..origin/${branch}`, `--pretty=format:%H${SEP}%s${SEP}%an${SEP}%at${REC}`, '-n', '40'],
    { cwd }
  )

  return stdout
    .split(REC)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const [sha, summary, author, at] = line.split(SEP)

      return { sha, summary, author, at: Number.parseInt(at, 10) * 1000 }
    })
}

let updateInFlight = false

// Set to true when the desktop is about to quit so a detached swap/install/
// uninstall script can take over. On macOS, app.quit() closes windows but
// window-all-closed deliberately keeps the process alive (standard Electron
// macOS convention). Without this flag the process never exits — the detached
// hand-off script spins its PID-wait for the full timeout, and the user sees a
// blank app with no window (and an uninstall that appears to do nothing). When
// set, window-all-closed calls app.quit() on every platform so the process
// actually dies and the hand-off script can proceed immediately.
let isQuittingForHandoff = false

// Resolve the staged updater binary. The Tauri installer copies itself to
// HERMES_HOME/hermes-setup.exe on a successful install (see
// apps/bootstrap-installer paths::copy_self_to_hermes_home). That binary owns
// ALL repo mutation — running `hermes update` + rebuilding the desktop — so
// the desktop never touches its own bits while running. Returns null when the
// updater isn't staged (e.g. a dev/source run that never went through the
// installer); callers degrade gracefully.
function resolveUpdaterBinary() {
  const name = IS_WINDOWS ? 'hermes-setup.exe' : 'hermes-setup'
  const candidate = path.join(HERMES_HOME, name)

  return fileExists(candidate) ? candidate : null
}

function repairMacUpdaterHelper(updater) {
  if (!IS_MAC || !updater) {
    return
  }

  try {
    execFileSync('/usr/bin/xattr', ['-cr', updater], { stdio: 'ignore' })
  } catch (err) {
    rememberLog(`[updates] macOS updater helper quarantine repair skipped: ${err.message}`)
  }

  try {
    execFileSync('/usr/bin/codesign', ['--verify', updater], { stdio: 'ignore' })

    return
  } catch {
    // Unsigned or invalid helper. Apply a local ad-hoc signature so Gatekeeper
    // does not block the staged updater before it can run.
  }

  try {
    execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', updater], { stdio: 'ignore' })
    rememberLog('[updates] repaired macOS updater helper signature')
  } catch (err) {
    rememberLog(`[updates] macOS updater helper signature repair skipped: ${err.message}`)
  }
}

// Path to the venv shim whose lock decides whether `hermes update` can write
// fresh entry points. On Windows this is the file the running backend
// `hermes.exe` holds open; on POSIX it's never mandatory-locked.
function venvHermesShimPath(updateRoot) {
  return IS_WINDOWS
    ? path.join(updateRoot, 'venv', 'Scripts', 'hermes.exe')
    : path.join(updateRoot, 'venv', 'bin', 'hermes')
}

// Best-effort lock probe mirroring the Rust updater's is_locked(): a running
// .exe on Windows refuses an O_RDWR open with a sharing violation. On POSIX
// this practically always succeeds (no mandatory locking), so it returns false
// — correct, since the shim-contention brick is Windows-only.
function isShimLocked(shimPath) {
  if (!IS_WINDOWS) {
    return false
  }

  let fd

  try {
    fd = fs.openSync(shimPath, 'r+')

    return false
  } catch (err) {
    // ENOENT ⇒ not there ⇒ nothing locking it. Anything else (EBUSY/EPERM/
    // EACCES) on Windows means a live handle holds it.
    return err && err.code !== 'ENOENT'
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd)
      } catch {
        void 0
      }
    }
  }
}

// Force-kill the entire process TREE rooted at each PID. Node's child.kill()
// only signals the direct child, so on Windows a backend `hermes.exe` that
// spawned its own grandchildren (a `hermes` REPL, a pty terminal session, the
// gateway) would survive and keep the venv shim locked. taskkill /T /F reaps
// the whole tree synchronously. Windows-only: this is called solely from the
// Windows shim-unlock path, and the backend is NOT spawned detached (so it's
// not a process-group leader — a POSIX negative-pgid kill would be meaningless
// here anyway). POSIX teardown stays with the existing before-quit SIGTERM.
function forceKillProcessTree(pid) {
  if (!IS_WINDOWS) {
    return
  }

  if (!Number.isInteger(pid) || pid <= 0) {
    return
  }

  try {
    execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], hiddenWindowsChildOptions({ stdio: 'ignore' }))
  } catch {
    // Already gone, or no permission — best effort; the unlock wait below is
    // the real gate.
  }
}

// Before handing off the update on Windows, the desktop MUST stop every backend
// it spawned and WAIT for the venv shim to actually unlock. The old code did
// `hermesProcess.kill('SIGTERM')` + `app.quit()` fire-and-forget: SIGTERM on
// Windows doesn't reap the backend's grandchildren, and quit didn't wait for
// teardown, so the updater raced a still-locked `hermes.exe`, the quarantine
// rename failed, uv's `pip install` hit "Access is denied", and the git path
// bailed into a full ZIP re-download that ALSO couldn't write the locked shim —
// a half-applied install (ryanc's update.log). Here we tree-kill the primary +
// pool backends and poll the shim until it's writable (or a bounded timeout),
// so by the time we spawn the updater the lock is genuinely gone.
//
// Windows-only: the venv-shim mandatory lock is a Windows phenomenon. On
// macOS/Linux there's no REPLACE-on-running-exe block, the existing before-quit
// SIGTERM + app.quit() teardown already works (the macOS path is flawless), and
// aggressively SIGKILL-ing the backend here would be an untested behavior change
// for no benefit. So we no-op off Windows and leave that path exactly as it was.
async function releaseBackendLockForUpdate(updateRoot) {
  return releaseBackendLock(updateRoot, 'updates')
}

// Shared backend teardown + venv-shim unlock wait. Used by BOTH the self-update
// hand-off and the desktop uninstaller — they have the identical Windows
// problem: the desktop's backend (and the grandchildren IT spawned — a hermes
// REPL, a pty terminal, the gateway) keep `hermes.exe` and other files in the
// venv mandatory-locked, so any in-place replace/delete of the install tree
// races a live handle and half-fails (#37532). We tree-kill every backend PID
// the desktop owns, then poll the shim until it's genuinely writable.
//
// `tag` only flavors the log lines. No-op off Windows (POSIX has no mandatory
// locks — the before-quit SIGTERM + the cleanup script's own PID-wait suffice).
async function releaseBackendLock(updateRoot, tag) {
  if (!IS_WINDOWS) {
    return { unlocked: true }
  }

  // Collect every backend PID the desktop owns: primary window backend + pool.
  const pids = []
  const hermesProcess = backendConnectionState.getProcess()

  if (hermesProcess && Number.isInteger(hermesProcess.pid)) {
    pids.push(hermesProcess.pid)
  }

  for (const entry of backendPool.values()) {
    if (entry.process && Number.isInteger(entry.process.pid)) {
      pids.push(entry.process.pid)
    }
  }

  // Graceful first (lets Python flush), then tree-kill to catch grandchildren.
  if (hermesProcess && !hermesProcess.killed) {
    try {
      hermesProcess.kill('SIGTERM')
    } catch {
      void 0
    }
  }

  stopAllPoolBackends()

  for (const pid of pids) {
    forceKillProcessTree(pid)
  }

  const shim = venvHermesShimPath(updateRoot)
  const deadlineMs = Date.now() + 15000

  while (Date.now() < deadlineMs) {
    if (!isShimLocked(shim)) {
      rememberLog(`[${tag}] venv shim unlocked; safe to proceed`)

      return { unlocked: true }
    }

    // A supervised backend can respawn between kill and check (grandchildren,
    // pool entries registered mid-teardown). Re-collect and re-kill each pass
    // instead of trusting the initial sweep.
    const stragglers = []

    const currentHermesProcess = backendConnectionState.getProcess()

    if (currentHermesProcess && Number.isInteger(currentHermesProcess.pid)) {
      stragglers.push(currentHermesProcess.pid)
    }

    for (const entry of backendPool.values()) {
      if (entry.process && Number.isInteger(entry.process.pid)) {
        stragglers.push(entry.process.pid)
      }
    }

    for (const pid of stragglers) {
      forceKillProcessTree(pid)
    }

    await new Promise(r => setTimeout(r, 300))
  }

  // Do NOT proceed past a held lock: handing off to the updater while another
  // process (a second desktop window, a user terminal, an unkillable child)
  // still maps the venv's files guarantees a half-updated venv — the updater's
  // dependency sync dies on access-denied partway through uninstalls, leaving
  // imports broken (the July 2026 brotlicffi/_sodium.pyd incidents). Failing
  // the update loudly and keeping the app running is strictly better than a
  // bricked install that needs manual venv surgery.
  rememberLog(
    `[${tag}] venv shim still locked after 15s; aborting hand-off (something outside this app holds the venv)`
  )

  return { unlocked: false }
}

// applyUpdates — hand off to the installer's --update flow, then exit.
//
// The desktop is a pure consumer: it does NOT git pull / pip install / rebuild
// itself (the old open-coded git dance lived here and drifted from
// `hermes update`). Instead we spawn the staged Hermes-Setup binary with
// --update and quit, so it can run `hermes update` (which refuses while we
// hold the venv shim) and rebuild the desktop with our exe already gone.
//
// Detection (checkUpdates / commit changelog / "N behind") stays in the UI;
// only this apply action changed.
async function applyUpdates(opts = {}) {
  if (updateInFlight) {
    throw new Error('An update is already in progress.')
  }

  updateInFlight = true

  try {
    const updater = resolveUpdaterBinary()

    if (!updater && !IS_WINDOWS) {
      // macOS/Linux drag-install: no staged Tauri hermes-setup. Unlike Windows
      // (where a venv-shim file lock forces the quit→hand-off→rebuild dance),
      // there's no mandatory file locking here, so the desktop can drive the
      // whole update itself: `hermes update` (backend) + `hermes desktop
      // --build-only` (OS-aware GUI rebuild), then swap the running .app bundle
      // with the freshly built one and relaunch.
      return await applyUpdatesPosixInApp(opts)
    }

    if (!updater) {
      // No staged updater binary — this is a CLI-installed user (they ran
      // `hermes desktop`, never the Tauri installer that self-copies
      // hermes-setup.exe into HERMES_HOME). They DO have a working `hermes`
      // on PATH / in the venv, so the correct path is the one-liner in their
      // native medium. We show the EXACT command, branch-pinned to the
      // checkout they're on — bare `hermes update` defaults to main and would
      // silently switch a bb/gui (or any non-main) install off-branch. Mirror
      // the GUI button's contract: append --branch <current> for non-main
      // checkouts, keep it bare for main so the card stays clean.
      const updateRoot = resolveUpdateRoot()
      let command = 'hermes update'

      try {
        const head = await runGit(['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: updateRoot })
        const current = (head.stdout || '').trim()

        if (head.code === 0 && current && current !== 'HEAD') {
          const branch = await resolveHealedBranch(updateRoot, current)

          if (branch !== 'main') {
            command = `hermes update --branch ${branch}`
          }
        }
      } catch {
        // Best-effort: fall back to bare `hermes update` if branch detection fails.
      }

      rememberLog(`[updates] no staged updater; surfacing manual \`${command}\` for CLI install at ${updateRoot}`)
      emitUpdateProgress({ stage: 'manual', message: command, percent: null })

      return { ok: true, manual: true, command, hermesRoot: updateRoot }
    }

    emitUpdateProgress({
      stage: 'restart',
      message:
        'Updating Hermes — this window will close and the updater will open. Don’t reopen Hermes yourself; it restarts automatically when the update finishes.',
      percent: 100
    })
    repairMacUpdaterHelper(updater)

    const updateRoot = resolveUpdateRoot()
    const { branch: configuredBranch } = readDesktopUpdateConfig()
    const branch = await resolveHealedBranch(updateRoot, configuredBranch || DEFAULT_UPDATE_BRANCH)
    const updaterArgs = ['--update', '--branch', branch]
    const targetApp = IS_MAC ? runningAppBundle() : null

    if (targetApp) {
      updaterArgs.push('--target-app', targetApp)
    }

    const venvBin = path.join(updateRoot, 'venv', IS_WINDOWS ? 'Scripts' : 'bin')

    // Stop our own backend(s) and wait for the venv shim to unlock BEFORE we
    // spawn the updater. Without this the updater races a still-locked
    // hermes.exe (held by the backend child / its grandchildren) and the update
    // bricks. See releaseBackendLockForUpdate for the full failure analysis.
    const lock = await releaseBackendLockForUpdate(updateRoot)

    if (!lock.unlocked) {
      // Something OUTSIDE this app holds the venv (a second window, a user
      // terminal running hermes, an unkillable child). Handing off anyway
      // guarantees a half-updated venv — abort loudly instead and let the
      // user close the holder and retry. Restart our own backend so the app
      // keeps working after the failed attempt.
      const message =
        'Update aborted: another process is holding the Hermes install open ' +
        '(a second Hermes window or a terminal running hermes?). Close it and retry.'

      emitUpdateProgress({ stage: 'error', message, percent: null })
      startHermes().catch(() => {})

      return { ok: false, error: message }
    }

    // Detached so the updater outlives this process — it needs us GONE before
    // `hermes update` will run (the venv shim is locked while we live).
    const child = spawnUpdaterProcess(updater, updaterArgs, {
      cwd: HERMES_HOME,
      env: {
        ...process.env,
        HERMES_HOME,
        PATH: pathWithHermesManagedNode(venvBin)
      },
      detached: true,
      stdio: 'ignore'
    })

    // Write the update-in-progress marker IMMEDIATELY — before the 2.5s
    // quit dwell. The Tauri updater won't write its own marker for several
    // seconds (window init + manifest), and during that gap our renderer
    // can reconnect and spawn a fresh backend that re-locks .pyd files in
    // the venv. By writing the marker ourselves the renderer's
    // waitForUpdateToFinish() gate sees a live update and parks instead.
    // The updater overwrites this with its own PID later; same format.
    if (Number.isInteger(child.pid)) {
      writeUpdateMarker(HERMES_HOME, child.pid)
    }

    rememberLog(`[updates] launched updater: ${updater} ${updaterArgs.join(' ')}; exiting desktop to release venv shim`)

    // Linger on the "updating — don't reopen" overlay long enough for the user
    // to actually read it (and to bridge the gap until the updater's own window
    // appears), THEN quit to release the venv shim. The updater rebuilds and
    // relaunches us when it's done. (#50419 — a 600ms quit looked like a crash
    // and lured users into the #50238 relaunch loop.)
    isQuittingForHandoff = true
    setTimeout(() => {
      app.quit()
    }, UPDATE_HANDOFF_DWELL_MS)

    return { ok: true, handedOff: true, updater }
  } finally {
    updateInFlight = false
  }
}

async function handOffWindowsBootstrapRecovery(reason) {
  if (!IS_WINDOWS || !IS_PACKAGED) {
    return false
  }

  const updater = resolveUpdaterBinary()

  if (!updater) {
    return false
  }

  const updateRoot = resolveUpdateRoot()
  const { branch: configuredBranch } = readDesktopUpdateConfig()

  const branch = directoryExists(path.join(updateRoot, '.git'))
    ? await resolveHealedBranch(updateRoot, configuredBranch || DEFAULT_UPDATE_BRANCH)
    : configuredBranch || DEFAULT_UPDATE_BRANCH

  const venvBin = path.join(updateRoot, 'venv', IS_WINDOWS ? 'Scripts' : 'bin')
  const venvHermes = path.join(venvBin, IS_WINDOWS ? 'hermes.exe' : 'hermes')
  const venvPython = path.join(venvBin, IS_WINDOWS ? 'python.exe' : 'python')

  // Choose the gentle in-place --update when ANY real-install signal is present,
  // not just the `hermes.exe` console-script shim. That shim is generated at the
  // END of venv setup and is absent in exactly the interrupted/quarantined states
  // this recovery exists to heal — gating on it alone forced the destructive
  // --repair (full venv recreate) and drove reinstall loops. The venv interpreter
  // and the bootstrap-complete marker are present earlier and are better signals.
  const haveRealInstall =
    fileExists(venvPython) || fileExists(venvHermes) || fileExists(path.join(updateRoot, '.hermes-bootstrap-complete'))

  const updaterArgs = chooseUpdaterArgs(haveRealInstall, branch)

  await releaseBackendLockForUpdate(updateRoot)

  const child = spawnUpdaterProcess(updater, updaterArgs, {
    cwd: HERMES_HOME,
    env: {
      ...process.env,
      HERMES_HOME,
      PATH: pathWithHermesManagedNode(venvBin)
    },
    detached: true,
    stdio: 'ignore'
  })

  // Same marker pre-write as applyUpdates — see comment there. The recovery
  // hand-off has the same window where the renderer can respawn a backend
  // before the updater writes its own marker.
  if (Number.isInteger(child.pid)) {
    writeUpdateMarker(HERMES_HOME, child.pid)
  }

  rememberLog(
    `[bootstrap] handed off ${reason} recovery to updater: ${updater} ${updaterArgs.join(' ')}; exiting desktop to release app.asar`
  )
  // Same dwell as the in-app update hand-off (#50419): give the updater's
  // window time to appear before we vanish, so the recovery doesn't look like
  // a crash and provoke a mid-recovery relaunch.
  isQuittingForHandoff = true
  setTimeout(() => {
    app.quit()
  }, UPDATE_HANDOFF_DWELL_MS)

  return true
}

// Resolve the hermes CLI to drive an in-app update: prefer the venv shim in
// the install we're updating, fall back to `hermes` on PATH.
function resolveHermesCliBinary(updateRoot) {
  const venvHermes = path.join(updateRoot, 'venv', 'bin', 'hermes')

  if (fileExists(venvHermes)) {
    return venvHermes
  }

  return findOnPath('hermes') || null
}

// Spawn a command and stream each output line to the update progress channel.
function runStreamedUpdate(command, args, { cwd, env, stage }: any = {}) {
  return new Promise(resolve => {
    let child

    try {
      child = spawn(
        command,
        args,
        hiddenWindowsChildOptions({
          cwd,
          env: { ...process.env, ...(env || {}) },
          stdio: ['ignore', 'pipe', 'pipe']
        })
      )
    } catch (err) {
      resolve({ code: 1, error: err.message })

      return
    }

    const emitLines = chunk => {
      for (const line of chunk.toString().split('\n')) {
        const trimmed = line.trim()

        if (trimmed) {
          emitUpdateProgress({ stage, message: trimmed, percent: null })
        }
      }
    }

    child.stdout.on('data', emitLines)
    child.stderr.on('data', emitLines)
    child.once('error', err => resolve({ code: 1, error: err.message }))
    child.once('exit', code => resolve({ code }))
  })
}

// The running app's .app bundle (packaged macOS): execPath is
// <App>.app/Contents/MacOS/<exe>; climb three levels to the bundle root.
function runningAppBundle() {
  if (!IS_MAC) {
    return null
  }

  let dir = path.dirname(app.getPath('exe')) // .../Contents/MacOS

  for (let i = 0; i < 2; i++) {
    dir = path.dirname(dir)
  } // -> .../X.app

  return dir.endsWith('.app') ? dir : null
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

// macOS/Linux in-app update: backend (`hermes update`) + OS-aware GUI rebuild
// (`hermes desktop --build-only`), then atomically swap the running .app bundle
// with the freshly built one and relaunch. Degrades to "backend updated,
// restart to load the new GUI" if the swap can't be performed.
async function applyUpdatesPosixInApp(opts: any) {
  const updateRoot = resolveUpdateRoot()
  const hermes = resolveHermesCliBinary(updateRoot)

  if (!hermes) {
    emitUpdateProgress({ stage: 'manual', message: 'hermes update', percent: null })

    return { ok: true, manual: true, command: 'hermes update', hermesRoot: updateRoot }
  }

  // Put the Hermes-managed Node and the venv on PATH so `hermes desktop`'s
  // npm build can find them on a machine with no system Node. Windows portable
  // Node lives directly under %LOCALAPPDATA%\hermes\node, not node\bin.
  // PYTHONUNBUFFERED: `hermes update` writes to a pipe here, so CPython
  // block-buffers stdout and long quiet steps (the pre-update backup can zip
  // multi-GB archives for minutes) stream nothing to the progress UI — users
  // read the silence as a hang and cancel a healthy update.
  const env: Record<string, string> = {
    HERMES_HOME,
    PYTHONUNBUFFERED: '1',
    PATH: pathWithHermesManagedNode(path.join(updateRoot, 'venv', 'bin'))
  }

  // `hermes update` reaps stale `hermes serve` backends (a code update
  // leaves the running process serving old Python against the freshly-updated
  // JS bundle). But OUR backend is one of those processes, and killing it
  // mid-update produces the boot→kill→crash loop in #37532 — the desktop
  // already restarts its own backend via the rebuild+relaunch below, so the
  // reap must spare it. Hand the live backend's PID to the update process;
  // _kill_stale_dashboard_processes reads HERMES_DESKTOP_CHILD_PID and excludes
  // it while still reaping any genuinely-orphaned backends. (#37532)
  // Exclude every desktop-managed backend (primary + all pool profiles) from
  // the update reaper. _kill_stale_dashboard_processes accepts a comma-separated
  // list (a single int still parses for back-compat).
  const desktopChildPids = []
  const hermesProcess = backendConnectionState.getProcess()

  if (hermesProcess && Number.isInteger(hermesProcess.pid)) {
    desktopChildPids.push(hermesProcess.pid)
  }

  for (const entry of backendPool.values()) {
    if (entry.process && Number.isInteger(entry.process.pid)) {
      desktopChildPids.push(entry.process.pid)
    }
  }

  if (desktopChildPids.length) {
    env.HERMES_DESKTOP_CHILD_PID = desktopChildPids.join(',')
  }

  // Branch-pin so a non-main checkout doesn't get switched to main (and self-heal
  // to main when the pinned branch no longer exists on origin).
  let branchArgs = []

  try {
    const head = await runGit(['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: updateRoot })
    const current = (head.stdout || '').trim()

    if (head.code === 0 && current && current !== 'HEAD') {
      branchArgs = ['--branch', await resolveHealedBranch(updateRoot, current)]
    }
  } catch {
    // best effort
  }

  emitUpdateProgress({ stage: 'update', message: 'Updating Hermes (git + dependencies)…', percent: 10 })

  const updated = (await runStreamedUpdate(hermes, ['update', '--yes', ...branchArgs], {
    cwd: updateRoot,
    env,
    stage: 'update'
  })) as any

  if (updated.code !== 0) {
    emitUpdateProgress({ stage: 'error', message: 'hermes update failed.', error: updated.error || 'update-failed' })

    return { ok: false, error: 'hermes update failed' }
  }

  emitUpdateProgress({ stage: 'rebuild', message: 'Rebuilding the desktop app…', percent: 60 })

  // Retry-once: a first rebuild can fail on a still-settling tree or a
  // self-healed (network-blocked) Electron download; a second run builds clean
  // off the healed dist so we reach the swap+relaunch below instead of bailing.
  const rebuilt = await runRebuildWithRetry(attempt => {
    if (attempt > 0) {
      emitUpdateProgress({ stage: 'rebuild', message: 'Retrying the desktop rebuild…', percent: 60 })
    }

    return runStreamedUpdate(hermes, ['desktop', '--build-only'], { cwd: updateRoot, env, stage: 'rebuild' })
  })

  if (rebuilt.code !== 0) {
    emitUpdateProgress({
      stage: 'error',
      message: 'Backend updated, but the desktop rebuild failed. Restart Hermes to retry.',
      error: rebuilt.error || 'rebuild-failed'
    })

    return { ok: false, backendUpdated: true, error: 'desktop rebuild failed' }
  }

  // Linux in-app update terminal state (#45205). `hermes desktop --build-only`
  // rebuilds the unpacked app in place under apps/desktop/release/<plat>-unpacked.
  // We can only HONESTLY relaunch into the new GUI when the *running* binary IS
  // that rebuilt one — i.e. execPath lives under release/<plat>-unpacked. The
  // outcome is decided by three signals (see update-relaunch.ts):
  //
  //   underUnpacked + sandboxOk  → 'relaunch': detached watcher re-execs us in
  //       place (mirrors the macOS handoff). Without it the update succeeds but
  //       the app never restarts and the overlay hangs on "applying" forever.
  //   !underUnpacked             → 'guiSkew': the running shell is an AppImage/
  //       .deb/.rpm/dev/unresolved binary we did NOT replace. Claiming "loads
  //       next launch" is a lie (GUI/backend skew, #37541) — surface an
  //       explicit closeable terminal state telling the user the GUI package
  //       was NOT changed and must be updated/reinstalled.
  //   underUnpacked + !sandboxOk → 'manual': we'd be relaunching the rebuilt
  //       binary, but a fresh rebuild can leave chrome-sandbox without
  //       root:root + setuid (mode 4755) and Electron then refuses to launch
  //       ("quit and never came back"). DO NOT quit into a dead app — keep the
  //       working window and surface the closeable manual-restart state.
  if (!IS_MAC) {
    const unpackedDir = resolveUnpackedRelease(process.execPath, updateRoot, process.platform)
    const underUnpacked = unpackedDir !== null

    const preflight = underUnpacked
      ? sandboxPreflight(unpackedDir, p => fs.statSync(p))
      : { ok: false, reason: 'not-under-unpacked', path: null }

    const sandboxFallback = sandboxFallbackFromEnv(process.env, process.argv.slice(1))
    const sandboxOk = preflight.ok || sandboxFallback

    if (underUnpacked && !preflight.ok) {
      rememberLog(
        `[updates] sandbox preflight: not launchable (${preflight.reason}) at ${preflight.path}; ` +
          `fallback=${sandboxFallback ? 'env/--no-sandbox' : 'none'}`
      )
    }

    const outcome = decideRelaunchOutcome({ underUnpacked, sandboxOk })

    if (outcome === 'relaunch') {
      emitUpdateProgress({ stage: 'restart', message: 'Restarting Hermes…', percent: 100 })
      // Preserve launch context across the re-exec: replay the original args
      // (filtered of Electron internals) and the env/cwd that define which
      // backend/profile/root this instance talks to. Without this the
      // relaunched instance comes up with default context instead of the user's.
      const relaunchArgs = collectRelaunchArgs(process.argv.slice(1))
      const relaunchEnv = collectRelaunchEnv(process.env)

      const relaunchScript = buildRelaunchScript({
        pid: process.pid,
        execPath: process.execPath,
        args: relaunchArgs,
        env: relaunchEnv,
        cwd: process.cwd()
      })

      const scriptPath = path.join(app.getPath('temp'), `hermes-desktop-update-${Date.now()}.sh`)

      try {
        fs.writeFileSync(scriptPath, relaunchScript, { mode: 0o755 })
        const child = spawn('/bin/bash', [scriptPath], { detached: true, stdio: 'ignore' })
        child.unref()
        rememberLog(
          `[updates] launched linux relaunch: ${scriptPath} -> ${process.execPath} ` +
            `(args=${relaunchArgs.length}, env=${Object.keys(relaunchEnv).length})`
        )
        isQuittingForHandoff = true
        setTimeout(() => app.quit(), UPDATE_HANDOFF_DWELL_MS)

        return { ok: true, handedOff: true }
      } catch (err) {
        rememberLog(`[updates] linux relaunch failed: ${err.message}; falling back to manual restart`)

        return {
          ok: true,
          backendUpdated: true,
          guiUpdated: false,
          manualRestart: true,
          message: 'Backend updated. Quit and reopen Hermes to load the new version.'
        }
      }
    }

    if (outcome === 'guiSkew') {
      emitUpdateProgress({
        stage: 'guiSkew',
        message:
          'Backend updated, but the desktop app package was not changed. ' +
          'Update or reinstall the Hermes desktop app to match.',
        percent: 100
      })
      rememberLog(
        `[updates] gui/backend skew: execPath ${process.execPath} not under release/*-unpacked; ` +
          'backend updated, GUI package unchanged (AppImage/.deb/.rpm/dev/unresolved)'
      )

      return { ok: true, backendUpdated: true, guiUpdated: false, guiSkew: true }
    }

    // outcome === 'manual': we're the rebuilt binary, but its sandbox helper is
    // not launchable and no fallback applies. Keep this working window alive.
    rememberLog(
      `[updates] sandbox not launchable (${preflight.reason}); skipping auto-relaunch, ` +
        'returning manual-restart so the user keeps a working window'
    )

    return {
      ok: true,
      backendUpdated: true,
      guiUpdated: false,
      manualRestart: true,
      sandboxBlocked: true,
      message:
        'Backend updated. The rebuilt app can’t relaunch automatically ' +
        '(sandbox helper needs root). Quit and reopen Hermes to finish.'
    }
  }

  const rebuiltApp = [
    path.join(updateRoot, 'apps', 'desktop', 'release', 'mac-arm64', 'Hermes.app'),
    path.join(updateRoot, 'apps', 'desktop', 'release', 'mac', 'Hermes.app')
  ].find(directoryExists)

  const targetApp = runningAppBundle()

  // No bundle to swap (dev run, Linux AppImage, or unresolved paths): the
  // backend is updated; the next launch picks up the rebuilt GUI.
  if (!rebuiltApp || !targetApp) {
    emitUpdateProgress({
      stage: 'done',
      message: 'Backend updated. Restart Hermes to load the new version.',
      percent: 100
    })

    return { ok: true, backendUpdated: true, rebuiltApp: rebuiltApp || null }
  }

  emitUpdateProgress({ stage: 'restart', message: 'Installing the updated app and restarting…', percent: 95 })

  // Detached swapper: wait for THIS process to exit (so the bundle is free),
  // ditto the rebuilt app over the running one, clear quarantine, relaunch.
  const swapScript = `#!/bin/bash
set -u
APP_PID=${process.pid}
SRC=${shellQuote(rebuiltApp)}
DST=${shellQuote(targetApp)}
for _ in $(seq 1 240); do
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 0.5
done
if [ "$SRC" != "$DST" ]; then
  if /usr/bin/ditto "$SRC" "$DST.hermes-update-new"; then
    rm -rf "$DST.hermes-update-old" 2>/dev/null || true
    mv "$DST" "$DST.hermes-update-old" 2>/dev/null || rm -rf "$DST"
    mv "$DST.hermes-update-new" "$DST"
    rm -rf "$DST.hermes-update-old" 2>/dev/null || true
  fi
fi
/usr/bin/xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true
/usr/bin/open "$DST"
`

  const scriptPath = path.join(app.getPath('temp'), `hermes-desktop-update-${Date.now()}.sh`)

  try {
    fs.writeFileSync(scriptPath, swapScript, { mode: 0o755 })
  } catch (err) {
    emitUpdateProgress({
      stage: 'done',
      message: 'Backend + app updated. Restart Hermes to load the new version.',
      percent: 100
    })
    rememberLog(`[updates] could not write swap script: ${err.message}; rebuilt app at ${rebuiltApp}`)

    return { ok: true, backendUpdated: true, rebuiltApp }
  }

  const child = spawn('/bin/bash', [scriptPath], { detached: true, stdio: 'ignore' })
  child.unref()
  rememberLog(`[updates] launched mac swap+relaunch: ${scriptPath} (${rebuiltApp} -> ${targetApp})`)

  isQuittingForHandoff = true
  setTimeout(() => app.quit(), 600)

  return { ok: true, handedOff: true, rebuiltApp, targetApp }
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'))
  } catch {
    return null
  }
}

// Bootstrap-complete marker helpers. The marker is written ONCE by the
// first-launch bootstrap runner (Phase 1D) after install.ps1 stages succeed
// AND the user has finished initial configuration. On every subsequent boot
// we check `isBootstrapComplete()` and skip the bootstrap flow entirely if
// the marker is present and current-schema.
//
// Marker schema (version 1):
//   {
//     schemaVersion: 1,
//     pinnedCommit: "<40-char SHA>",       // what install.ps1 was driven against
//     pinnedBranch: "<branch name>" | null,
//     completedAt:  "<ISO 8601>",
//     desktopVersion: "<app.getVersion()>"  // for forensics
//   }
function readBootstrapMarker() {
  return readJson(BOOTSTRAP_COMPLETE_MARKER)
}

// Marker-independent: is the canonical install at ACTIVE_HERMES_ROOT actually
// runnable right now? A complete CLI install (`install.sh --include-desktop`)
// or a DMG launch over a prior CLI install satisfies this WITHOUT the desktop
// ever having written the bootstrap marker -- so we must be able to recognise
// "already installed" off the filesystem alone, not just the marker.
function isActiveRuntimeUsable() {
  const venvPython = getVenvPython(VENV_ROOT)

  return (
    isHermesSourceRoot(ACTIVE_HERMES_ROOT) &&
    fileExists(venvPython) &&
    canImportHermesCli(venvPython, {
      env: {
        PYTHONPATH: [ACTIVE_HERMES_ROOT, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter)
      }
    })
  )
}

function isBootstrapComplete() {
  const marker = readBootstrapMarker()

  if (!marker || typeof marker !== 'object') {
    return false
  }

  if (marker.schemaVersion !== BOOTSTRAP_MARKER_SCHEMA_VERSION) {
    return false
  }

  if (typeof marker.pinnedCommit !== 'string' || marker.pinnedCommit.length < 7) {
    return false
  }

  // We DELIBERATELY do NOT verify that the checkout is currently at the
  // pinned commit -- users update via the in-app update path or `hermes
  // update`, which moves HEAD legitimately. The marker just attests "we
  // ran the bootstrap successfully at least once." We DO additionally require
  // a runnable venv: an interrupted or split-home install can leave the marker
  // + checkout without a venv, and trusting that spawns a dead backend
  // ("gateway offline") instead of re-running bootstrap to repair it.
  return isActiveRuntimeUsable()
}

function writeBootstrapMarker(payload) {
  fs.mkdirSync(path.dirname(BOOTSTRAP_COMPLETE_MARKER), { recursive: true })

  const merged = {
    schemaVersion: BOOTSTRAP_MARKER_SCHEMA_VERSION,
    pinnedCommit: payload.pinnedCommit || null,
    pinnedBranch: payload.pinnedBranch || null,
    completedAt: new Date().toISOString(),
    desktopVersion: app.getVersion()
  }

  writeFileAtomic(BOOTSTRAP_COMPLETE_MARKER, JSON.stringify(merged, null, 2) + '\n', 'utf8')

  return merged
}

function resolveWebDist() {
  const override = process.env.HERMES_DESKTOP_WEB_DIST

  if (override && directoryExists(path.resolve(override))) {
    return path.resolve(override)
  }

  const unpackedDist = path.join(unpackedPathFor(APP_ROOT), 'dist')

  if (directoryExists(unpackedDist)) {
    return unpackedDist
  }

  // Final fallback: APP_ROOT/dist. When packaged with asar:true this lives
  // INSIDE app.asar — not a servable filesystem directory — so the embedded
  // dashboard backend 404s on static routes (see #41327, #39472). The durable
  // fix is unpacking dist/ (PR #41411 adds dist/** to asarUnpack so the tier-2
  // unpackedDist above resolves). If we still land here while packaged, log it
  // so the cause isn't silent.
  const fallback = path.join(APP_ROOT, 'dist')

  if (IS_PACKAGED && /app\.asar(?=$|[\\/])/.test(fallback) && !directoryExists(fallback)) {
    rememberLog(
      `[web-dist] dashboard frontend dir resolved to an asar-internal path that ` +
        `is not a real directory: ${fallback}. Static routes will 404. ` +
        `Ensure dist/** is unpacked (asarUnpack) or set HERMES_DESKTOP_WEB_DIST.`
    )
  }

  return fallback
}

function resolveRendererIndex() {
  const candidates = [path.join(APP_ROOT, 'dist', 'index.html'), path.join(resolveWebDist(), 'index.html')]
  const found = candidates.find(fileExists)

  if (found) {
    return found
  }

  // Nothing on disk. A packaged build with no renderer bundle blank-pages with
  // a bare ERR_FILE_NOT_FOUND and no clue why (see #39484). Surface the cause
  // and the fix before Electron loads the missing file.
  rememberLog(
    `[renderer] index.html not found — the desktop app was packaged without a ` +
      `renderer bundle. Tried: ${candidates.join(', ')}. ` +
      `Rebuild with: hermes desktop --force-build`
  )

  return candidates[0]
}

// True when `dir` lives inside the packaged app bundle / install tree.
// Packaged Electron's process.cwd() (and npm's INIT_CWD when dev tooling
// leaked into a release build) often resolve here — e.g. win-unpacked on
// Windows — which is exactly where PR #37536 item 16 said we must NOT run.
function isPackagedInstallPath(dir) {
  return isPackagedInstallPathUnderRoots(dir, {
    isPackaged: IS_PACKAGED,
    installRoots: [
      APP_ROOT,
      path.dirname(process.execPath),
      resolveRemovableAppPath(process.execPath, process.platform, process.env)
    ]
  })
}

function resolveHermesCwd() {
  // In a packaged build, `process.cwd()` resolves to the install root (e.g.
  // `…/win-unpacked` on Windows or `/Applications/Hermes.app/Contents/...`
  // on macOS). Sessions spawned there leave files inside the app bundle
  // and bewilder users when "where did my files go?" is the install dir.
  // The user-configurable default project directory wins over everything,
  // followed by env hints (only honored when packaged if they point at a
  // real directory), then the home dir.
  const candidates = [
    readDefaultProjectDir(),
    process.env.HERMES_DESKTOP_CWD,
    IS_PACKAGED ? null : process.env.INIT_CWD,
    IS_PACKAGED ? null : process.cwd(),
    !IS_PACKAGED ? SOURCE_REPO_ROOT : null,
    app.getPath('home')
  ]

  for (const candidate of candidates) {
    if (!candidate) {
      continue
    }

    const resolved = path.resolve(String(candidate))

    if (isPackagedInstallPath(resolved)) {
      continue
    }

    if (directoryExists(resolved)) {
      return resolved
    }
  }

  return app.getPath('home')
}

function sanitizeWorkspaceCwd(cwd) {
  const trimmed = typeof cwd === 'string' ? cwd.trim() : ''

  if (!trimmed || isPackagedInstallPath(trimmed)) {
    return { cwd: resolveHermesCwd(), sanitized: Boolean(trimmed) }
  }

  try {
    const resolved = path.resolve(trimmed)

    if (directoryExists(resolved)) {
      return { cwd: resolved, sanitized: false }
    }
  } catch {
    // Fall through to the resolved default.
  }

  return { cwd: resolveHermesCwd(), sanitized: Boolean(trimmed) }
}

// Persisted "Default project directory" — surfaced as a setting in the
// renderer (see app/settings/sessions-settings.tsx). Stored as JSON in
// userData so it survives self-updates without bleeding into the new
// install. `null` means "no preference, fall back to the usual chain".
const DEFAULT_PROJECT_DIR_CONFIG_FILENAME = 'project-dir.json'

function defaultProjectDirConfigPath() {
  return path.join(app.getPath('userData'), DEFAULT_PROJECT_DIR_CONFIG_FILENAME)
}

function readDefaultProjectDir() {
  try {
    const raw = fs.readFileSync(defaultProjectDirConfigPath(), 'utf8')
    const parsed = JSON.parse(raw)

    if (parsed && typeof parsed.dir === 'string' && parsed.dir.trim()) {
      const resolved = path.resolve(parsed.dir)

      if (directoryExists(resolved)) {
        return resolved
      }
    }
  } catch {
    // Missing / unreadable / malformed → fall through to the rest of the
    // candidate chain.
  }

  return null
}

function writeDefaultProjectDir(dir) {
  const target = defaultProjectDirConfigPath()
  const payload = dir ? JSON.stringify({ dir: path.resolve(dir) }, null, 2) : JSON.stringify({}, null, 2)

  try {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, payload, 'utf8')
  } catch (error) {
    rememberLog(`[settings] write default project dir failed: ${error.message}`)
  }
}

function createPythonBackend(root, label, backendArgs, options: any = {}) {
  const python = findPythonForRoot(root)

  if (!python) {
    return null
  }

  const venvRoot = path.join(root, 'venv')
  const venvPython = getVenvPython(venvRoot)
  const command = IS_WINDOWS && fileExists(venvPython) ? venvPython : python

  return {
    kind: 'python',
    label,
    command,
    args: ['-m', 'hermes_cli.main', ...backendArgs],
    env: buildDesktopBackendEnv({
      hermesHome: HERMES_HOME,
      pythonPathEntries: [root, ...getVenvSitePackagesEntries(venvRoot)],
      venvRoot
    }),
    root,
    bootstrap: Boolean(options.bootstrap),
    shell: false
  }
}

// createActiveBackend — build a backend pointing at ACTIVE_HERMES_ROOT, the
// canonical install location shared with the CLI installer. The venv at
// VENV_ROOT may not exist yet on first run; bootstrap=true tells
// ensureRuntime() to create / refresh it before launch.
function createActiveBackend(backendArgs) {
  const venvPython = getVenvPython(VENV_ROOT)
  const command = fileExists(venvPython) ? venvPython : findSystemPython()

  return {
    kind: 'python',
    label: `Hermes at ${ACTIVE_HERMES_ROOT}`,
    command,
    args: ['-m', 'hermes_cli.main', ...backendArgs],
    env: buildDesktopBackendEnv({
      hermesHome: HERMES_HOME,
      pythonPathEntries: [ACTIVE_HERMES_ROOT, ...getVenvSitePackagesEntries(VENV_ROOT)],
      venvRoot: VENV_ROOT
    }),
    root: ACTIVE_HERMES_ROOT,
    bootstrap: true,
    shell: false
  }
}

function resolveHermesBackend(backendArgs) {
  // 1. Explicit override -- HERMES_DESKTOP_HERMES_ROOT points at a developer
  //    checkout. Honour it as-is (no bootstrap; the user is driving).
  const overrideRoot = process.env.HERMES_DESKTOP_HERMES_ROOT && path.resolve(process.env.HERMES_DESKTOP_HERMES_ROOT)

  if (overrideRoot && isHermesSourceRoot(overrideRoot)) {
    const backend = createPythonBackend(overrideRoot, `Hermes source at ${overrideRoot}`, backendArgs)

    if (backend) {
      return backend
    }
  }

  // 2. Development source -- when running `npm run dev` from a checkout, the
  //    cloned repo at SOURCE_REPO_ROOT takes precedence over ACTIVE and any
  //    installed `hermes` on PATH so local Python edits are actually exercised.
  //    (In dev with no checkout, SOURCE_REPO_ROOT won't pass isHermesSourceRoot.)
  if (!IS_PACKAGED && isHermesSourceRoot(SOURCE_REPO_ROOT)) {
    const backend = createPythonBackend(SOURCE_REPO_ROOT, `Hermes source at ${SOURCE_REPO_ROOT}`, backendArgs)

    if (backend) {
      return backend
    }
  }

  // 3. Bootstrap-complete ACTIVE_HERMES_ROOT -- the canonical install at
  //    %LOCALAPPDATA%\hermes\hermes-agent (Windows) or ~/.hermes/hermes-agent.
  //    The bootstrap marker means install.ps1 stages finished and the user
  //    completed initial configuration; we trust the install and go straight
  //    to spawning hermes. Updates flow through the in-app update path
  //    (applyUpdates -> git pull) or `hermes update` from the CLI.
  if (isBootstrapComplete()) {
    return createActiveBackend(backendArgs)
  }

  // 4. Existing `hermes` on PATH -- installed via install.ps1 / install.sh from
  //    a previous tool-only setup, or pip-installed system-wide. Use it but
  //    do NOT write a bootstrap marker; the user did this themselves and we
  //    don't want to take ownership of an install we didn't perform.
  //    HERMES_DESKTOP_IGNORE_EXISTING=1 forces the bootstrap path for testing.
  if (process.env.HERMES_DESKTOP_IGNORE_EXISTING !== '1') {
    let hermesCommand = null
    const hermesOverride = process.env.HERMES_DESKTOP_HERMES

    if (hermesOverride) {
      const resolvedOverride = findOnPath(hermesOverride)

      if (resolvedOverride) {
        hermesCommand = resolvedOverride
      } else if (!isWindowsBinaryPathInWsl(hermesOverride, { isWsl: IS_WSL })) {
        hermesCommand = hermesOverride
      } else {
        rememberLog(`Ignoring Windows Hermes override under WSL: ${hermesOverride}`)
      }
    } else {
      hermesCommand = findOnPath('hermes')
    }

    if (hermesCommand) {
      if (looksLikeDesktopAppBinary(hermesCommand)) {
        rememberLog(`Ignoring desktop app executable on PATH while resolving Hermes CLI: ${hermesCommand}`)
        hermesCommand = null
      }
    }

    if (hermesCommand) {
      const unwrapped = unwrapWindowsVenvHermesCommand(hermesCommand, backendArgs)

      if (unwrapped) {
        return unwrapped
      }

      // Smoke-test the candidate before trusting it. A `hermes` shim
      // left behind by a half-uninstalled pip install (or a venv
      // entry-point pointing at a deleted interpreter) still resolves
      // via findOnPath but explodes on spawn -- the user then sees a
      // dead backend instead of the first-launch installer. The cheap
      // `--version` probe (see backend-probes.ts) catches that case
      // and lets the resolver fall through to step 6 / bootstrap.
      const shellForProbe = isCommandScript(hermesCommand)

      if (verifyHermesCli(hermesCommand, { shell: shellForProbe })) {
        return (
          unwrapWindowsVenvHermesCommand(hermesCommand, backendArgs) || {
            label: `existing Hermes CLI at ${hermesCommand}`,
            command: hermesCommand,
            args: backendArgs,
            bootstrap: false,
            env: {},
            kind: 'command',
            shell: shellForProbe
          }
        )
      }

      rememberLog(
        `Ignoring existing Hermes CLI at ${hermesCommand}: --version probe failed; falling through to bootstrap.`
      )
    }
  }

  // 5. Last-ditch: pip-installed hermes_cli module via system Python.
  //    Same rationale as #4 -- the user installed this; we use it but don't
  //    take ownership.
  const python = findSystemPython()

  if (python) {
    // Same smoke-test rationale as step 4: a system Python in the
    // SUPPORTED_VERSIONS range can be registered (PEP 514) without
    // having hermes_cli installed -- common on dev boxes that have
    // a python.org install from prior unrelated work. Returning that
    // backend hands the spawn step a guaranteed ModuleNotFoundError.
    // Verify the import works before trusting the candidate; on
    // failure, fall through to step 6 so the bootstrap runner pulls
    // a uv-managed 3.11 into %LOCALAPPDATA%\hermes\hermes-agent\venv.
    if (canImportHermesCli(python)) {
      return {
        kind: 'python',
        label: `installed hermes_cli module via ${python}`,
        command: python,
        args: ['-m', 'hermes_cli.main', ...backendArgs],
        bootstrap: false,
        env: {},
        shell: false
      }
    }

    rememberLog(`Ignoring system Python ${python}: hermes_cli is not importable; falling through to bootstrap.`)
  }

  // 6. Nothing usable yet -- signal the bootstrap runner that we need to
  //    clone+install. Phase 1D's bootstrap-runner consumes this sentinel
  //    and drives install.ps1 stages with a progress UI. Until 1D lands,
  //    callers see the sentinel and surface it as a user-facing error
  //    explaining what's missing.
  //
  //    We deliberately do NOT throw here -- throwing inside
  //    resolveHermesBackend was the old "no payload" path and forced the
  //    user into a dead end. With the bootstrap protocol, "no install yet"
  //    is a recoverable state the GUI can drive through.
  return {
    kind: 'bootstrap-needed',
    label: 'Hermes Agent not installed yet; bootstrap required',
    command: null,
    args: backendArgs,
    bootstrap: true,
    env: {},
    shell: false,
    // Hints for the bootstrap runner / UI layer:
    activeRoot: ACTIVE_HERMES_ROOT,
    installStamp: INSTALL_STAMP, // may be null in dev
    isPackaged: IS_PACKAGED,
    platform: process.platform
  }
}

async function ensureRuntime(backend) {
  if (!backend.bootstrap) {
    await advanceBootProgress('runtime.external', `Using ${backend.label}`, 32)

    return backend
  }

  // backend.kind === 'bootstrap-needed' means resolveHermesBackend couldn't
  // find anything to spawn. Hand off to the bootstrap runner which drives the
  // platform installer, writes the bootstrap-complete marker on success, then
  // we re-resolve to get the now-installed backend.
  //
  // Phase 1D status: bootstrap runs but events go to desktop.log only
  // (renderer window isn't created until later in startBackend). Phase 1E
  // will rewire startup to spawn the window first and route bootstrap events
  // to a renderer-side install overlay.
  if (backend.kind === 'bootstrap-needed') {
    rememberLog('[bootstrap] no Hermes install found; starting first-launch bootstrap')

    if (await handOffWindowsBootstrapRecovery('bootstrap-needed')) {
      const handoffError: Error & { isBootstrapFailure?: boolean; bootstrapHandedOff?: boolean } = new Error(
        'Hermes recovery was handed off to Hermes Setup. The desktop will restart when recovery completes.'
      )

      handoffError.isBootstrapFailure = true
      handoffError.bootstrapHandedOff = true
      bootstrapFailure = handoffError
      throw handoffError
    }

    // Eagerly flip the bootstrap UI state to 'active' so the renderer
    // shows the install overlay BEFORE the runner finishes fetching the
    // manifest (which on slow networks can take tens of seconds and would
    // otherwise leave the user staring at the generic 'Preparing' splash).
    // We emit a synthetic manifest with an empty stages list -- the real
    // manifest event will overwrite it once install.ps1 -Manifest returns.
    try {
      broadcastBootstrapEvent({
        type: 'manifest',
        stages: [],
        protocolVersion: null
      })
    } catch {
      void 0
    }

    bootstrapAbortController = new AbortController()

    const bootstrapResult = await runBootstrap({
      installStamp: backend.installStamp,
      activeRoot: backend.activeRoot,
      sourceRepoRoot: SOURCE_REPO_ROOT,
      hermesHome: HERMES_HOME,
      logRoot: path.join(HERMES_HOME, 'logs'),
      abortSignal: bootstrapAbortController.signal,
      onEvent: ev => {
        // Tee every bootstrap event to (a) the desktop log for forensics
        // and (b) the renderer for live progress UI. Either may be absent;
        // tolerate both gracefully so a renderer crash doesn't stall the
        // bootstrap and a log-write failure doesn't suppress the UI signal.
        try {
          rememberLog(`[bootstrap] ${JSON.stringify(ev)}`)
        } catch {
          void 0
        }

        try {
          broadcastBootstrapEvent(ev)
        } catch {
          void 0
        }
      },
      writeMarker: writeBootstrapMarker
    })

    bootstrapAbortController = null

    if (bootstrapResult.cancelled) {
      const cancelledError = new Error('Hermes install was cancelled.') as any
      cancelledError.isBootstrapFailure = true
      cancelledError.bootstrapCancelled = true
      bootstrapFailure = cancelledError
      throw cancelledError
    }

    if (!bootstrapResult.ok) {
      const bootstrapError = new Error(
        `Hermes bootstrap failed${bootstrapResult.failedStage ? ` at stage '${bootstrapResult.failedStage}'` : ''}: ` +
          `${bootstrapResult.error || 'unknown error'}. ` +
          `Check ${path.join(HERMES_HOME, 'logs', 'desktop.log')} for the full transcript.`
      ) as any

      bootstrapError.isBootstrapFailure = true
      bootstrapError.failedStage = bootstrapResult.failedStage || null
      // Latch the failure so subsequent startHermes() calls return this
      // same error without re-running install.ps1.  Cleared by the
      // hermes:bootstrap:reset IPC (renderer's "Reload and retry").
      bootstrapFailure = bootstrapError
      throw bootstrapError
    }

    rememberLog('[bootstrap] bootstrap complete; marker written. Re-resolving backend.')

    // Re-resolve now that the install exists. The new resolution lands in
    // step 3 (bootstrap-complete marker) and we recurse to wire venvPython.
    return ensureRuntime(resolveHermesBackend(backend.args))
  }

  // bootstrap=true with a real backend (createActiveBackend path) means we
  // have a checkout and need to ensure the venv-derived Python command is
  // wired into the backend before launch. Same code path the old factory
  // sync flow exited through, minus all the factory/pip/marker machinery
  // (install.ps1 owns those concerns now and the bootstrap-complete marker
  // attests they ran successfully).
  if (!isHermesSourceRoot(ACTIVE_HERMES_ROOT)) {
    throw new Error(
      `Hermes install at ${ACTIVE_HERMES_ROOT} is missing or incomplete. ` +
        'Reinstall via the desktop installer or scripts/install.ps1.'
    )
  }

  // On Windows, preflight Git Bash. Hermes' terminal tool calls bash.exe
  // directly (tools/environments/local.py); without it the agent can't run
  // terminal commands. install.ps1's Stage-Git puts PortableGit at
  // %LOCALAPPDATA%\hermes\git\, which findGitBash() picks up, so for any
  // user who completed the bootstrap this is a no-op. For users who got
  // here via an external `hermes` on PATH, this c