package cipherpane

const (
	// Panel dimensions
	LeftPanelWidth = 30
	PanelMargin    = 3

	// Layout offsets
	RightPanelWidthOffset = 4
	ContentHeightOffset   = 8
	LeftPanelHeightOffset = 4
	InternalWidthOffset   = 2
	InternalHeightOffset  = 3
)

type Layout struct {
	WindowWidth  int
	WindowHeight int

	// Left panel
	LeftPanelHeight int

	// Right panels
	RightPanelWidth   int
	TopPanelHeight    int
	BottomPanelHeight int

	// Internal component dimensions
	TextareaInputWidth   int
	TextareaInputHeight  int
	TextareaOutputWidth  int
	TextareaOutputHeight int
	FilepickerHeight     int
}

func NewLayout(width, height int) Layout {
	l := Layout{
		WindowWidth:  width,
		WindowHeight: height,
	}

	// Calculate panel dimensions
	totalH := height - PanelMargin
	l.RightPanelWidth = width - LeftPanelWidth - RightPanelWidthOffset // Matches existing calculation: msg.Width - leftWidth - 8

	// Split vertical space for right panels
	contentHeight := totalH - ContentHeightOffset
	// Split space equally between top and bottom panels.
	// Bottom panel takes the remainder if height is odd.
	l.TopPanelHeight = contentHeight / 2
	l.BottomPanelHeight = contentHeight/2 + contentHeight%2

	l.LeftPanelHeight = totalH - LeftPanelHeightOffset // Matches existing calculation: totalH - 4

	// Internal dimensions (subtract borders + padding + label line)
	l.TextareaInputWidth = l.RightPanelWidth - InternalWidthOffset
	l.TextareaInputHeight = l.TopPanelHeight - InternalHeightOffset

	l.TextareaOutputWidth = l.RightPanelWidth - InternalWidthOffset
	l.TextareaOutputHeight = l.BottomPanelHeight - InternalHeightOffset

	l.FilepickerHeight = l.TopPanelHeight - InternalHeightOffset

	return l
}
