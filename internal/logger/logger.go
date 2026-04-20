package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
)

// Attribute keys recognised by the handler and rendered in the fixed columns.
const (
	KeyModule  = "module"
	KeyTarget  = "target"
	KeyNetbios = "netbios"
	KeyPort    = "port"
)

// Custom log levels that map onto the printer's symbol set.
const (
	// LevelSuccess prints a green [*] symbol (sits between Info and Warn).
	LevelSuccess = slog.Level(2)
)

// formatters mirrors the defaults used by printer.DefaultPrinterConfig.
var (
	firstColFmt = color.New(color.FgBlue, color.Bold).SprintfFunc()
	outputFmt   = color.New(color.FgHiYellow).SprintfFunc()
	successFmt  = color.New(color.FgGreen, color.Bold).SprintfFunc()
	failureFmt  = color.New(color.FgRed, color.Bold).SprintfFunc()
	successSym  = "[*]"
	failureSym  = "[-]"
)

// Handler is a slog.Handler that produces the same tabular output as Printer.
type Handler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr // pre-set attrs from WithAttrs calls
}

func (h *Handler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(merged, h.attrs)
	copy(merged[len(h.attrs):], attrs)
	return &Handler{w: h.w, mu: h.mu, attrs: merged}
}

func (h *Handler) WithGroup(_ string) slog.Handler { return h }

func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	// Collect all attrs (pre-set + record-level).
	all := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	all = append(all, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		all = append(all, a)
		return true
	})

	// Extract fixed-column values.
	var module, target, netbios string
	var port int
	var extra []slog.Attr
	for _, a := range all {
		switch a.Key {
		case KeyModule:
			module = a.Value.String()
		case KeyTarget:
			target = a.Value.String()
		case KeyNetbios:
			netbios = a.Value.String()
		case KeyPort:
			port = int(a.Value.Int64())
		default:
			extra = append(extra, a)
		}
	}
	if netbios == "" {
		netbios = "?????"
	}

	// Build fixed prefix columns.
	var row strings.Builder
	row.WriteString(firstColFmt("%-8s", module))
	row.WriteString(fmt.Sprintf("%-16s", target))
	row.WriteString(fmt.Sprintf("%-5d", port))
	row.WriteString(fmt.Sprintf("%-20s", netbios))

	// Build message, appending any extra key=value attrs.
	msg := r.Message
	for _, a := range extra {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value)
	}
	msg = strings.ReplaceAll(strings.ReplaceAll(msg, "\n", ""), "\r", "")
	msgField := fmt.Sprintf("%-40s", msg)
	if len(msg) > 37 {
		msgField += fmt.Sprintf("%-3s", "")
	}

	// Choose symbol and colourise message based on level.
	var symbol, txt string
	switch {
	case r.Level >= slog.LevelError:
		symbol = failureFmt("%s ", failureSym)
		txt = msgField
	case r.Level >= LevelSuccess:
		symbol = successFmt("%s ", successSym)
		txt = msgField
	case r.Level >= slog.LevelInfo:
		symbol = color.BlueString("%s ", successSym)
		txt = msgField
	default:
		// Debug / plain
		symbol = ""
		txt = outputFmt(msgField)
	}

	h.mu.Lock()
	_, err := fmt.Fprintf(h.w, "%s%s%s\n", row.String(), symbol, txt)
	h.mu.Unlock()
	return err
}

// ---------------------------------------------------------------------------
// Global logger
// ---------------------------------------------------------------------------

var (
	globalMu     sync.Mutex
	globalLogger *slog.Logger
)

// Init initialises the global logger with the given writer.
// Safe to call multiple times; subsequent calls replace the logger.
func Init(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	h := &Handler{w: w, mu: &sync.Mutex{}}
	l := slog.New(h)
	globalMu.Lock()
	globalLogger = l
	globalMu.Unlock()
	slog.SetDefault(l)
}

// Default returns the global logger, initialising it with os.Stdout if needed.
func Default() *slog.Logger {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalLogger == nil {
		h := &Handler{w: os.Stdout, mu: &sync.Mutex{}}
		globalLogger = slog.New(h)
		slog.SetDefault(globalLogger)
	}
	return globalLogger
}

// New returns a child logger pre-loaded with the module/target/netbios/port
// context columns, mirroring printer.NewPrinter.
func New(module, target, netbios string, port int) *slog.Logger {
	if netbios == "" {
		netbios = "?????"
	}
	return Default().With(
		KeyModule, module,
		KeyTarget, target,
		KeyNetbios, netbios,
		KeyPort, port,
	)
}
