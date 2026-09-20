package dashboard

import "fmt"

type poolEditor struct {
	mints, streams, accounts int
	error                    string
}

func (e *poolEditor) key(key byte) {
	switch key {
	case '-', '_':
		e.mints = max(1, e.mints-1)
	case '+', '=':
		e.mints = min(16, e.mints+1)
	case '[':
		e.streams = max(1, e.streams-1)
	case ']':
		e.streams = min(16, e.streams+1)
	}
	e.error = ""
}
func (c *canvas) poolEditor(e *poolEditor) {
	w, h := len(c.rows[0]), len(c.rows)
	pw := min(w, 66)
	ph := 12
	x, y := (w-pw)/2, max(0, (h-ph)/2)
	for row := 0; row < ph; row++ {
		c.text(x, y+row, pw, fmt.Sprintf("%*s", pw, ""), plain)
	}
	c.panel(x, y, pw, ph, "TURN POOL · LIVE SETTINGS")
	c.text(x+2, y+2, pw-4, fmt.Sprintf("Mints / account    %2d       - / +", e.mints), bright)
	c.text(x+2, y+3, pw-4, fmt.Sprintf("Streams / mint     %2d       [ / ]", e.streams), bright)
	c.text(x+2, y+5, pw-4, fmt.Sprintf("Target  %d accounts × %d × %d = %d allocations", e.accounts, e.mints, e.streams, e.accounts*e.mints*e.streams), accent)
	c.text(x+2, y+7, pw-4, "Existing pool keeps serving while changes apply.", muted)
	c.text(x+2, y+8, pw-4, "More mints may request new provider credentials.", muted)
	if e.error != "" {
		c.text(x+2, y+9, pw-4, safeText(e.error), bad)
	}
	c.text(x+2, y+10, pw-4, "Enter apply  ·  Esc cancel  ·  q quit", good)
}
