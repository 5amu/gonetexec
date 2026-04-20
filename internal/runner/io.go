package runner

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"golang.org/x/text/encoding/unicode"
)

const DefaultMaxConcurrent = 60

func ExtractLinesFromFileOrString(s string) (o []string) {
	var err error
	if o, err = readLines(s); err != nil {
		o = []string{s}
	}
	return o
}

func WriteLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func GeneratePassword(n int) string {
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?_")
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func StringToUTF16(s string) string {
	pwd := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	out, _ := pwd.NewEncoder().String(s)
	return out
}
