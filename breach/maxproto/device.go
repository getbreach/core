package maxproto

import randmath "math/rand/v2"

// DeviceInfo is the subset of the handshake userAgent that is safe to spoof:
// purely cosmetic device fields. The fingerprint-critical fields (appVersion,
// buildNumber, arch, deviceType, pushDeviceType) are NOT here — they are pinned
// to the build whose APK digests the anti-spoof fingerprint is derived from, so
// no combination of DeviceInfo can ever make the fingerprint contradict the
// announced version. Any field left empty keeps the default.
type DeviceInfo struct {
	DeviceName   string `json:"deviceName"`
	OsVersion    string `json:"osVersion"`
	Screen       string `json:"screen"`
	Timezone     string `json:"timezone"`
	Locale       string `json:"locale"`
	DeviceLocale string `json:"deviceLocale"`
}

// UserAgentFor builds a handshake userAgent from the default (which carries the
// locked appVersion/buildNumber/arch that match the fingerprint digests) with
// the spoofable device fields overlaid. Empty fields keep the default.
func UserAgentFor(d DeviceInfo) UserAgent {
	ua := DefaultUserAgent() // appVersion / buildNumber / arch / deviceType / pushType locked
	if d.DeviceName != "" {
		ua.DeviceName = d.DeviceName
	}
	if d.OsVersion != "" {
		ua.OsVersion = d.OsVersion
	}
	if d.Screen != "" {
		ua.Screen = d.Screen
	}
	if d.Timezone != "" {
		ua.Timezone = d.Timezone
	}
	if d.Locale != "" {
		ua.Locale = d.Locale
	}
	if d.DeviceLocale != "" {
		ua.DeviceLocale = d.DeviceLocale
	}
	return ua
}

// devicePool is a small set of real, RU-common Android phones used to pick a
// RANDOM default device when the caller does not specify one — so that "no
// device given" does not mean "every install reports the same phone" (a shared
// fingerprint). Only cosmetic fields vary; the fingerprint-critical
// appVersion/buildNumber/arch stay locked (see UserAgentFor).
var devicePool = []DeviceInfo{
	{DeviceName: "Xiaomi 23127PN0CG", OsVersion: "Android 14", Screen: "440dpi 440dpi 1220x2712"},
	{DeviceName: "samsung SM-S918B", OsVersion: "Android 14", Screen: "480dpi 480dpi 1440x3088"},
	{DeviceName: "samsung SM-S928B", OsVersion: "Android 14", Screen: "480dpi 480dpi 1440x3120"},
	{DeviceName: "samsung SM-A536B", OsVersion: "Android 13", Screen: "450dpi 450dpi 1080x2340"},
	{DeviceName: "samsung SM-A346B", OsVersion: "Android 14", Screen: "400dpi 400dpi 1080x2340"},
	{DeviceName: "Google Pixel 7", OsVersion: "Android 14", Screen: "420dpi 420dpi 1080x2400"},
	{DeviceName: "Redmi Note 12 Pro", OsVersion: "Android 13", Screen: "395dpi 395dpi 1080x2400"},
	{DeviceName: "Redmi Note 11", OsVersion: "Android 13", Screen: "400dpi 400dpi 1080x2400"},
	{DeviceName: "realme RMX3771", OsVersion: "Android 14", Screen: "480dpi 480dpi 1264x2780"},
	{DeviceName: "vivo V2312", OsVersion: "Android 14", Screen: "388dpi 388dpi 1080x2400"},
	{DeviceName: "CPH2451", OsVersion: "Android 14", Screen: "525dpi 525dpi 1440x3216"},
}

// RandomDevice returns a random device from the pool.
func RandomDevice() DeviceInfo {
	return devicePool[randmath.IntN(len(devicePool))]
}

// RandomDeviceUserAgent is UserAgentFor(RandomDevice()) — a plausible, varied
// default device with the version locked. Use it when the caller gives no device
// on a FRESH login, so installs don't all look identical.
func RandomDeviceUserAgent() UserAgent {
	return UserAgentFor(RandomDevice())
}
