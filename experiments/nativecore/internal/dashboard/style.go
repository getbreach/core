package dashboard

import "strings"

// Only our own single-cell glyphs reach the canvas. External text is sanitized
// before layout; ANSI is emitted afterwards so clipping cannot split escapes.
type ink uint8

const (
	plain ink = iota
	muted
	border
	accent
	good
	warn
	bad
	bright
	violet
)

var colors = [...]string{"", "38;5;245", "38;5;240", "38;5;81", "38;5;114", "38;5;221", "38;5;203", "1", "38;5;141"}

type cell struct {
	char rune
	ink  ink
}
type canvas struct {
	rows  [][]cell
	color bool
}

func newCanvas(w, h int, color bool) *canvas {
	c := &canvas{rows: make([][]cell, h), color: color}
	for y := range c.rows {
		c.rows[y] = make([]cell, w)
		for x := range c.rows[y] {
			c.rows[y][x].char = ' '
		}
	}
	return c
}
func (c *canvas) text(x, y, limit int, text string, color ink) {
	if y < 0 || y >= len(c.rows) {
		return
	}
	chars := []rune(text)
	limit = max(0, min(limit, len(c.rows[y])-x))
	if len(chars) > limit {
		chars = chars[:limit]
		if limit > 0 {
			chars[limit-1] = '…'
		}
	}
	for i, r := range chars {
		if x+i >= 0 {
			c.rows[y][x+i] = cell{r, color}
		}
	}
}
func (c *canvas) panel(x, y, w, h int, title string) {
	c.text(x, y, w, "╭"+strings.Repeat("─", w-2)+"╮", border)
	for row := 1; row < h-1; row++ {
		c.text(x, y+row, 1, "│", border)
		c.text(x+w-1, y+row, 1, "│", border)
	}
	c.text(x, y+h-1, w, "╰"+strings.Repeat("─", w-2)+"╯", border)
	c.text(x+2, y, w-4, " "+title+" ", accent)
}
func (c *canvas) lines() []string {
	lines := make([]string, len(c.rows))
	for y, row := range c.rows {
		var b strings.Builder
		current := plain
		for _, v := range row {
			if c.color && current != v.ink {
				b.WriteString("\x1b[0m")
				if v.ink != plain {
					b.WriteString("\x1b[" + colors[v.ink] + "m")
				}
				current = v.ink
			}
			b.WriteRune(v.char)
		}
		if c.color && current != plain {
			b.WriteString("\x1b[0m")
		}
		lines[y] = b.String()
	}
	return lines
}
