package ui

import (
	"encoding/hex"
	"os"
	"strings"
	"time"

	"go-cipher/internal/crypto/gost"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func (m model) Init() tea.Cmd {
	return m.Filepicker.Init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

		layout := NewLayout(msg.Width, msg.Height)

		m.Input.SetWidth(layout.TextareaInputWidth)
		m.Input.SetHeight(layout.TextareaInputHeight)
		m.Output.SetWidth(layout.TextareaOutputWidth)
		m.Output.SetHeight(layout.TextareaOutputHeight)
		m.Filepicker.SetHeight(layout.FilepickerHeight)
		m.SaveFilename.Width = 34

	case statusMsg:
		m.Status = ""
		return m, nil

	case tea.KeyMsg:
		// Save Popup Logic
		if m.ShowSavePopup {
			switch msg.String() {
			case "esc":
				m.ShowSavePopup = false
				m.SaveFilename.Blur()
				return m, nil
			case "enter":
				filename := m.SaveFilename.Value()
				if filename == "" {
					filename = "output.txt"
				}

				err := os.WriteFile(filename, []byte(m.Output.Value()), 0o644)
				if err != nil {
					m.Status = "Error: " + err.Error()
				} else {
					m.Status = "Saved to: " + filename
				}

				m.ShowSavePopup = false
				m.SaveFilename.Blur()

				return m, tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
					return statusMsg("")
				})
			default:
				var cmd tea.Cmd
				m.SaveFilename, cmd = m.SaveFilename.Update(msg)
				return m, cmd
			}
		}

		// Global Bindings
		switch {
		case key.Matches(msg, m.Keymap.quit):
			if m.shouldClearKey(msg) {
				// let the focusable-element switch below handle it
				break
			}
			m.Input.Blur()
			m.Output.Blur()
			m.Key.Blur()
			return m, tea.Quit
		case key.Matches(msg, m.Keymap.next):
			m.Focus = (m.Focus + 1) % FocusCount
			m.skipInactive(1)
			m.updateFocus()
			return m, m.Filepicker.Init()
		case key.Matches(msg, m.Keymap.prev):
			m.Focus = (m.Focus - 1 + FocusCount) % FocusCount
			m.skipInactive(-1)
			m.updateFocus()
			return m, m.Filepicker.Init()
		}

		// Filepicker specific
		if m.InputMode == File && m.Focus == FocusFilepicker {
			if !m.FileConfirmed {
				var cmd tea.Cmd
				m.Filepicker, cmd = m.Filepicker.Update(msg)
				if didSelect, path := m.Filepicker.DidSelectFile(msg); didSelect {
					m.SelectedFile = path
					m.FileConfirmed = true
				}
				return m, cmd
			}
			if msg.String() == "backspace" {
				m.FileConfirmed = false
				m.SelectedFile = ""
				return m, m.Filepicker.Init()
			}
			return m, nil
		}

		// Other focusable elements
		switch {
		case key.Matches(msg, m.Keymap.copy):
			m.Input.SetValue(m.Output.Value())
			m.Output.SetValue("")
			m.InputMode = ManualInput
			m.Focus = FocusInput
			m.updateFocus()
			return m, nil
		case key.Matches(msg, m.Keymap.clearInput):
			m.Input.SetValue("")
			m.Focus = FocusInput
			m.updateFocus()
			return m, nil
		case m.shouldClearKey(msg):
			m.Key.SetValue("")
			return m, nil
		case m.Focus == FocusInputMode && msg.String() == "enter":
			m.InputMode = (m.InputMode + 1) % 2
			m.FileConfirmed = false
			m.SelectedFile = ""
			m.updateFocus()
			return m, m.Filepicker.Init()
		case m.Focus == FocusMethod && msg.String() == "enter":
			m.Method = (m.Method + 1) % 4
			m.skipInactive(1)
			m.updateFocus()
			return m, nil
		case m.Focus == FocusMode && msg.String() == "enter":
			m.Mode = (m.Mode + 1) % 2
			return m, nil
		case m.Focus == FocusBtn && msg.String() == "enter":
			m.Output.SetValue("")
			var res, iv, mac []byte
			decrypt := (m.Mode == Decrypt)

			var inputSource []byte
			if m.InputMode == File {
				if m.SelectedFile == "" {
					m.Output.SetValue("No file selected")
					return m, nil
				}
				content, err := os.ReadFile(m.SelectedFile)
				if err != nil {
					m.Output.SetValue("Error reading file: " + err.Error())
					return m, nil
				}
				inputSource, err = hex.DecodeString(string(content))
				if err != nil {
					m.Output.SetValue("Cannot decode bytes from file")
					return m, nil
				}
			} else {
				inputSource = []byte(strings.TrimSpace(m.Input.Value()))
			}

			if decrypt && m.InputMode == ManualInput {
				decoded, err := hex.DecodeString(strings.TrimSpace(m.Input.Value()))
				if err != nil {
					m.Output.SetValue("Ciphertext must be hex (copy output from encrypt)")
					return m, nil
				}
				inputSource = decoded
			}

			if len(inputSource) < 8 {
				m.Output.SetValue("Input should be longer than 8 bytes")
				return m, nil
			}

			key, err := hex.DecodeString(strings.TrimSpace(m.Key.Value()))
			if err != nil {
				panic("cannot decode key")
			}
			switch m.Method {
			case Simple:
				if decrypt {
					res = gost.ECBDecrypt(inputSource, key)
				} else {
					res = gost.ECBEncrypt(inputSource, key)
				}
			case Gamma:
				if decrypt {
					iv := inputSource[:8]
					res = gost.GostGammaDecrypt(inputSource[8:], key, iv)
				} else {
					res, iv = gost.GostGammaEncrypt(inputSource, key)
				}
			case GammaWithFeedback:
				if decrypt {
					iv := inputSource[:8]
					res = gost.GammaWithFeedbackDecrypt(inputSource[8:], key, iv)
				} else {
					res, iv = gost.GammaWithFeedbackEncrypt(inputSource, key)
				}
			case GammaWithMAC:
				if decrypt {
					iv := inputSource[:8]
					// WARN: only for 32 bit hardcoded mac
					mac := inputSource[8:12]
					res = gost.GammaDecryptWithMAC(inputSource[12:], key, iv, mac)
				} else {
					res, iv, mac = gost.GammaEncryptWithMAC(inputSource, key)
				}
			}

			m.Output.SetValue(renderResult(m.Method, decrypt, res, iv, mac))
			return m, nil
		case m.Focus == FocusSaveBtn && msg.String() == "enter":
			m.ShowSavePopup = true
			m.SaveFilename.SetValue("")
			m.SaveFilename.Focus()
			return m, nil
		}
	}

	var cmd tea.Cmd

	if m.Focus == FocusInput {
		m.Input, cmd = m.Input.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.Focus == FocusFilepicker {
		m.Filepicker, cmd = m.Filepicker.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.Focus == FocusKey {
		m.Key, cmd = m.Key.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	layout := NewLayout(m.Width, m.Height)

	inputModeLabel := labelStyle.Render("INPUT MODE")
	inputModeValue := "File"
	if m.InputMode == ManualInput {
		inputModeValue = "Manual input"
	}
	if m.Focus == FocusInputMode {
		inputModeValue = selectedStyle.Render(inputModeValue) + " (Enter)"
	}

	methodLabel := labelStyle.Render("METHOD")
	var methodValue string
	switch m.Method {
	case Simple:
		methodValue = "Simple replacement"
	case Gamma:
		methodValue = "Gamma"
	case GammaWithFeedback:
		methodValue = "Gamma with feedback"
	case GammaWithMAC:
		methodValue = "Gamma with MAC"
	}

	if m.Focus == FocusMethod {
		methodValue = selectedStyle.Render(methodValue) + " (Enter)"
	}

	modeLabel := labelStyle.Render("MODE")
	var modeValue string
	switch m.Mode {
	case Encrypt:
		modeValue = "Encrypt"
	case Decrypt:
		modeValue = "Decrypt"
	}

	if m.Focus == FocusMode {
		modeValue = selectedStyle.Render(modeValue) + " (Enter)"
	}

	keyLabel := labelStyle.Render("KEY")

	runBtnLabel := "RUN"
	if m.Focus == FocusBtn {
		runBtnLabel = buttonStyle.Render(runBtnLabel)
	}

	label := "SAVE TO FILE"
	if m.Focus == FocusSaveBtn {
		label = saveBtnStyle.Render(label)
	}
	saveBtnLabel := label

	innerWidth := LeftPanelWidth - 2
	// Hardwrap keeps "> " attached to the key; word-wrap would push it to its own line.
	keyWrapped := ansi.Hardwrap(m.Key.View(), innerWidth, true)

	leftContent := lipgloss.JoinVertical(
		lipgloss.Left,
		inputModeLabel,
		inputModeValue,
		"",
		methodLabel,
		methodValue,
		"",
		modeLabel,
		modeValue,
		"",
		keyLabel,
		keyWrapped,
		"",
		"",
		runBtnLabel,
		saveBtnLabel,
	)

	wrappedContent := lipgloss.NewStyle().Width(innerWidth).Render(leftContent)

	innerHeight := layout.LeftPanelHeight
	if wrappedHeight := lipgloss.Height(wrappedContent); wrappedHeight < innerHeight {
		wrappedContent = lipgloss.PlaceVertical(innerHeight, lipgloss.Top, wrappedContent)
	}

	leftPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1).
		Render(wrappedContent)

	inputPanelStyle := lipgloss.NewStyle().
		Height(layout.TopPanelHeight).
		Width(layout.RightPanelWidth).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1)

	outputPanelStyle := lipgloss.NewStyle().
		Height(layout.BottomPanelHeight).
		Width(layout.RightPanelWidth).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1)

	inputTitle := "INPUT"
	inputContent := m.Input.View()

	if m.InputMode == File {
		if m.FileConfirmed {
			inputTitle = "FILE SELECTED"

			style := selectedStyle
			if m.Focus != FocusFilepicker {
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
			}

			selectedLine := style.Render("Selected: " + m.SelectedFile)
			hintLine := lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true).
				Render("Press Backspace to change file")
			inputContent = lipgloss.JoinVertical(lipgloss.Left, selectedLine, "", hintLine)
		} else {
			inputTitle = "FILE PICKER"
			inputContent = m.Filepicker.View()
		}
	}

	inputPanel := inputPanelStyle.Render(lipgloss.PlaceVertical(layout.TopPanelHeight, lipgloss.Top, labelStyle.Render(inputTitle)+"\n"+inputContent))

	outputView := m.Output.View()
	if m.Status != "" {
		outputView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86")).
			Bold(true).
			Render(m.Status)
	}

	outputPanel := outputPanelStyle.Render(lipgloss.PlaceVertical(layout.BottomPanelHeight, lipgloss.Top, labelStyle.Render("OUTPUT")+"\n"+outputView))

	rightPanel := lipgloss.JoinVertical(0, inputPanel, outputPanel)

	baseView := lipgloss.JoinHorizontal(0, leftPanel, rightPanel)

	if m.ShowSavePopup {
		popupContent := lipgloss.JoinVertical(
			lipgloss.Left,
			labelStyle.Render("SAVE OUTPUT TO FILE"),
			"",
			"Filename:",
			m.SaveFilename.View(),
			"",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true).
				Render("Enter to save  •  Esc to cancel"),
		)
		popup := popupStyle.Render(popupContent)
		return lipgloss.Place(
			m.Width, m.Height,
			lipgloss.Center, lipgloss.Center,
			popup,
			lipgloss.WithWhitespaceChars(" "),
			lipgloss.WithWhitespaceForeground(lipgloss.Color("237")),
		)
	}

	return baseView
}

func (m *model) skipInactive(dir int) {
	for {
		inactive := false
		if m.InputMode == ManualInput && m.Focus == FocusFilepicker {
			inactive = true
		}
		if m.InputMode == File && m.Focus == FocusInput {
			inactive = true
		}

		if !inactive {
			break
		}
		m.Focus = (m.Focus + dir + FocusCount) % FocusCount
	}
}

func (m *model) updateFocus() {
	m.Input.Blur()
	m.Key.Blur()
	m.SaveFilename.Blur()

	switch m.Focus {
	case FocusInput:
		m.Input.Focus()
	case FocusKey:
		m.Key.Focus()
	}

	if m.InputMode == File {
		m.Input.Blur()
	}
}

func (m model) shouldClearKey(msg tea.KeyMsg) bool {
	return m.Focus == FocusKey && key.Matches(msg, m.Keymap.clearKey) && m.Key.Value() != ""
}

func renderResult(method Method, decrypt bool, res, iv, mac []byte) string {
	if decrypt {
		return string(res)
	}

	switch method {
	case Gamma, GammaWithFeedback:
		return hex.EncodeToString(iv) + hex.EncodeToString(res)
	case GammaWithMAC:
		return hex.EncodeToString(iv) + hex.EncodeToString(mac) + hex.EncodeToString(res)
	default:
		return hex.EncodeToString(res)
	}
}
