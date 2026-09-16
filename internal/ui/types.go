package ui

import (
	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
)

type (
	Method    int
	Mode      int
	InputMode int
)

const (
	ManualInput InputMode = iota
	File
)

const (
	Simple Method = iota
	Gamma
	GammaWithFeedback
	GammaWithMAC
)

const (
	Encrypt Mode = iota
	Decrypt
)

const (
	FocusInputMode int = iota
	FocusFilepicker
	FocusMethod
	FocusMode
	FocusKey
	FocusInput
	FocusBtn
	FocusSaveBtn
	FocusCount
)

type model struct {
	Filepicker    filepicker.Model
	SelectedFile  string
	FileConfirmed bool
	InputMode     InputMode
	Method        Method
	Mode          Mode
	Status        string
	Focus         int
	Width         int
	Height        int
	Key           textinput.Model
	Input         textarea.Model
	Output        textarea.Model
	SaveFilename  textinput.Model
	ShowSavePopup bool
	Keymap        keymap
}

type keymap = struct {
	next, prev, quit, copy, clearInput, clearKey key.Binding
}

type statusMsg string
