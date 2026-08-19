// explore: probe a silent mint path 76 -> 166 (create a group conference, then
// join by its link) to get TURN creds WITHOUT ringing a friend (opcode 78).
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"breach/maxproto"
)

func main() {
	cfgPath := flag.String("config", "config.json", "MAX config")
	flag.Parse()
	cfg, err := maxproto.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	c, err := maxproto.Dial(cfg.Host, cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Request(6, map[string]any{
		"mt_instanceid": cfg.InstanceID, "userAgent": ua(cfg),
		"clientSessionId": cfg.ClientSessionID, "deviceId": cfg.DeviceID,
	}); err != nil {
		log.Fatalf("sessionInit: %v", err)
	}
	if _, err := c.Request(19, map[string]any{
		"token": cfg.Token, "interactive": false,
		"exp": map[string]any{"chatsCountGroups": []byte{0x0b, 0x32}}, "presenceSync": 0,
	}); err != nil {
		log.Fatalf("login: %v", err)
	}
	fmt.Println("logged in")

	ip := internalParams(cfg)

	// opcode 76: create a group conference (no callees, no chat) -> joinLink
	pkt, err := c.Request(76, map[string]any{
		"conversationId": uuidV4(), "internalParams": ip, "isVideo": false,
	})
	if err != nil {
		log.Fatalf("opcode 76: %v", err)
	}
	r76, _ := pkt.Payload.(map[string]any)
	fmt.Printf("76 resp keys: %v\n", keys(r76))
	link, _ := r76["joinLink"].(string)
	convo, _ := r76["conversationId"].(string)
	fmt.Printf("joinLink=%q conversationId=%q\n", link, convo)
	if icp, ok := r76["internalCallerParams"].(string); ok {
		fmt.Printf("76 ALREADY has internalCallerParams: %.80s...\n", icp)
	}
	if link == "" {
		log.Fatal("no joinLink from 76")
	}

	// opcode 166: join by link -> internalParams (TURN creds)
	pkt2, err := c.Request(166, map[string]any{
		"joinLink": link, "internalParams": ip, "isVideo": false,
	})
	if err != nil {
		log.Fatalf("opcode 166 (joinByLink): %v", err)
	}
	r166, _ := pkt2.Payload.(map[string]any)
	fmt.Printf("166 resp keys: %v\n", keys(r166))
	raw, _ := r166["internalParams"].(string)
	if raw == "" {
		raw, _ = r166["internalCallerParams"].(string)
	}
	if raw == "" {
		fmt.Printf("166 full resp: %v\n", r166)
		log.Fatal("no internalParams from 166")
	}
	var icp map[string]any
	json.Unmarshal([]byte(raw), &icp)
	turn, _ := icp["turn"].(map[string]any)
	fmt.Println("=== SILENT MINT RESULT (76->166) ===")
	fmt.Printf("turn urls: %v\n", turn["urls"])
	fmt.Printf("turn username: %v\n", turn["username"])
	fmt.Printf("turn credential: %v\n", turn["credential"])
	fmt.Printf("endpoint: %.60s\n", icp["endpoint"])
}

func ua(cfg *maxproto.Config) map[string]any {
	u := cfg.UserAgent
	return map[string]any{
		"deviceType": u.DeviceType, "appVersion": u.AppVersion, "osVersion": u.OsVersion,
		"timezone": u.Timezone, "screen": u.Screen, "pushDeviceType": u.PushType,
		"arch": u.Arch, "locale": u.Locale, "buildNumber": u.BuildNumber,
		"deviceName": u.DeviceName, "deviceLocale": u.DeviceLocale,
	}
}

func internalParams(cfg *maxproto.Config) string {
	b, _ := json.Marshal(map[string]any{
		"platform": "ANDROID", "sdkVersion": cfg.SdkVersion, "clientAppKey": cfg.ClientAppKey,
		"deviceId": cfg.DeviceID, "protocolVersion": 5, "onlyAdminCanRecord": false,
		"waitForAdmin": false, "capabilities": cfg.Capabilities,
	})
	return string(b)
}

func uuidV4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func keys(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}
