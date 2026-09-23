// SPDX-FileCopyrightText: Copyright The Moby Authors
// SPDX-License-Identifier: Apache-2.0

package apparmor

import (
	"testing"
)

func TestQuoteProfileName(t *testing.T) {
	tests := []struct {
		doc   string
		value string
		want  string
	}{
		{
			doc:  "empty",
			want: "",
		},
		{
			doc:   "simple",
			value: "default-profile",
			want:  `"default-profile"`,
		},
		{
			doc:   "spaces",
			value: "with spaces",
			want:  `"with spaces"`,
		},
		{
			doc:   "double quote",
			value: `foo"bar`,
			want:  `"foo\"bar"`,
		},
		{
			doc:   "backslash",
			value: `foo\bar`,
			want:  `"foo\\bar"`,
		},
		{
			doc:   "escape sequence",
			value: `foo\nbar`,
			want:  `"foo\\nbar"`,
		},
		{
			doc:   "AARE wildcard",
			value: `foo*bar?baz`,
			want:  `"foo\*bar\?baz"`,
		},
		{
			doc:   "AARE character class",
			value: `foo[bar]`,
			want:  `"foo\[bar\]"`,
		},
		{
			doc:   "AARE alternation",
			value: `foo{bar,baz}`,
			want:  `"foo\{bar\,baz\}"`,
		},
		{
			doc:   "AARE anchor",
			value: `foo^bar`,
			want:  `"foo\^bar"`,
		},
		{
			doc:   "invalid UTF-8 with special character",
			value: "foo\xff*bar",
			want:  "\"foo\xff\\*bar\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.doc, func(t *testing.T) {
			if got := quoteProfileName(tc.value); got != tc.want {
				t.Errorf("quoteProfileName(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
