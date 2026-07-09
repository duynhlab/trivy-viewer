package logging

import "testing"

func TestInitDoesNotPanic(t *testing.T) {
	for _, format := range []string{"json", "pretty", "other"} {
		for _, level := range []string{"debug", "info", "warn", "error", "bogus"} {
			Init(format, level)
		}
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]int{"debug": -4, "info": 0, "warn": 4, "error": 8, "x": 0}
	for in, want := range cases {
		if got := int(parseLevel(in)); got != want {
			t.Errorf("parseLevel(%q) = %d, want %d", in, got, want)
		}
	}
}
