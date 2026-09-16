package main

// msgs holds every user-facing string of the setup wizard. Fields ending in a
// format verb (%s/%d/%v/%w) are format strings; the call sites document which.
// Two instances below (ruMsgs, enMsgs) are selected by the language menu.
type msgs struct {
	banner        string // plain
	overwrite     string // %s = path
	provTitle     string
	provMax       string
	provWB        string
	modeTitle     string
	modeWG        string
	modeSocks     string
	server        string
	socksAddr     string
	socksToken    string
	socksPin      string
	socksUser     string
	socksPass     string
	wgListen      string
	streams       string
	mints         string
	maxPhone      string
	maxLoginErr   string // used as "%s: %w"
	wbSignIn      string // %s = session path
	wbChat        string
	wbCallee      string
	wbChatOK      string // %s chat, %s peer
	wbWarnOpen    string // %v err
	wbWarnResolve string // %s chat, %v err
	written       string // %s = path
	futureRuns    string // %s = flag suffix
	startNow      string
	yes           string
	no            string
	required      string
	positiveNum   string
	menuHelp      string
}

var ruMsgs = msgs{
	banner:        "Настройка breach-client — Enter принимает значение в скобках [по умолчанию].",
	overwrite:     "внимание: %s уже существует и будет перезаписан.",
	provTitle:     "Провайдер — откуда берутся TURN-креды:",
	provMax:       "MAX  (вход по SMS)",
	provWB:        "WB   (вход через WB ID, callback в браузере)",
	modeTitle:     "Режим выхода — как трафик покидает машину:",
	modeWG:        "WireGuard / UDP-рот  (сверху свой WG/Hysteria; нужен root)",
	modeSocks:     "SOCKS5  (breach отдаёт локальный SOCKS5; выход дозванивается сам; без root)",
	server:        "адрес breach-server (ip:port выхода)",
	socksAddr:     "локальный адрес SOCKS5",
	socksToken:    "пароль этого клиента на выходе",
	socksPin:      "pin сертификата выхода (sha256, из /etc/breach/qtun-pin)",
	socksUser:     "необязательный логин для локального SOCKS5 (пусто = без логина)",
	socksPass:     "пароль для этого логина SOCKS5",
	wgListen:      "локальный UDP, куда шлёт внутренний туннель (рот)",
	streams:       "TURN-аллокаций на один минт (streams)",
	mints:         "сколько кредов минтить (mints)",
	maxPhone:      "MAX: номер телефона для входа (+7...)",
	maxLoginErr:   "вход MAX",
	wbSignIn:      "WB: вход (сессия сохранится в %s)",
	wbChat:        "личный WB-чат для минта как 'chats/<id>' (пусто — ввести userID собеседника)",
	wbCallee:      "userID собеседника для звонка",
	wbChatOK:      "ок: %s звонит собеседнику %s",
	wbWarnOpen:    "внимание: не удалось открыть WB-сессию для проверки чата: %v",
	wbWarnResolve: "внимание: не удалось разрешить %s в собеседника (групповой чат не подойдёт): %v",
	written:       "конфиг записан в %s",
	futureRuns:    "дальше просто запускай: breach-client%s",
	startNow:      "Запустить туннель сейчас?",
	yes:           "Да",
	no:            "Нет",
	required:      "(обязательно)",
	positiveNum:   "(введите положительное число)",
	menuHelp:      "↑/↓ выбор · Enter подтвердить · Ctrl-C отмена",
}

var enMsgs = msgs{
	banner:        "breach-client setup — press Enter to accept the [default] in brackets.",
	overwrite:     "note: %s already exists and will be overwritten.",
	provTitle:     "Provider — where TURN credentials come from:",
	provMax:       "MAX  (log in by SMS)",
	provWB:        "WB   (log in with WB ID, browser callback)",
	modeTitle:     "Exit mode — how traffic leaves your machine:",
	modeWG:        "WireGuard / UDP mouth  (run your own WG/Hysteria over it; needs root)",
	modeSocks:     "SOCKS5  (breach serves a local SOCKS5; the exit dials out; no root)",
	server:        "breach-server address (ip:port of the exit)",
	socksAddr:     "local SOCKS5 listen address",
	socksToken:    "this client's password on the exit",
	socksPin:      "exit's cert pin (sha256, from /etc/breach/qtun-pin)",
	socksUser:     "optional username for the local SOCKS5 listener (blank = none)",
	socksPass:     "password for that SOCKS5 username",
	wgListen:      "local UDP the inner tunnel targets (the mouth)",
	streams:       "TURN allocations per minted credential (streams)",
	mints:         "credentials to mint (mints)",
	maxPhone:      "MAX: phone number to log in (+7...)",
	maxLoginErr:   "MAX login",
	wbSignIn:      "WB: signing in (session saved to %s)",
	wbChat:        "WB personal chat to mint from as 'chats/<id>' (blank to enter a peer userID instead)",
	wbCallee:      "peer userID to call",
	wbChatOK:      "ok: %s calls peer %s",
	wbWarnOpen:    "warning: could not open WB session to check the chat: %v",
	wbWarnResolve: "warning: could not resolve %s to a peer (a group chat won't work): %v",
	written:       "config written to %s",
	futureRuns:    "future runs: just run breach-client%s",
	startNow:      "Start the tunnel now?",
	yes:           "Yes",
	no:            "No",
	required:      "(required)",
	positiveNum:   "(enter a positive number)",
	menuHelp:      "↑/↓ move · Enter select · Ctrl-C cancel",
}
