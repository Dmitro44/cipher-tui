package main

import (
	"fmt"
	"os"

	"go-cipher/internal/cipher"
	"go-cipher/internal/ui"
	"go-cipher/internal/ui/cipherpane"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	gost := cipher.NewGost()
	m := ui.NewModel(
		ui.Tab{Title: gost.Name(), Pane: cipherpane.NewCipherPane(gost)},
	)

	if _, err := tea.NewProgram(
		m,
		tea.WithAltScreen(),
	).Run(); err != nil {
		fmt.Printf("error: %s", err)
		os.Exit(1)
	}
}
