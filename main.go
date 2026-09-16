package main

import (
	"fmt"
	"os"

	"go-cipher/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if _, err := tea.NewProgram(
		ui.NewModel(),
		tea.WithAltScreen(),
	).Run(); err != nil {
		fmt.Printf("error: %s", err)
		os.Exit(1)
	}
}
