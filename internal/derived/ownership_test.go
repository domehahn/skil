package derived

import "testing"

func TestMarkdownOwnershipPreservesExecutableFenceAndOffsets(t *testing.T) {
	data := []byte("Explain os.system in prose.\n```python\nos.system(cmd)\n```\n")
	spans, complete := ClassifySyntaxOwnership("SKILL.md", data, 10)
	if !complete || len(spans) != 2 {
		t.Fatalf("unexpected ownership: complete=%v spans=%#v", complete, spans)
	}
	if spans[0].Owner != OwnerMarkdownProse || spans[1].Owner != OwnerMarkdownCode {
		t.Fatalf("ownership flattened: %#v", spans)
	}
	if string(data[spans[1].Start:spans[1].End]) != "```python\nos.system(cmd)\n```\n" {
		t.Fatal("source mapping changed")
	}
}

func TestUnclosedFenceMakesOwnershipIncomplete(t *testing.T) {
	_, complete := ClassifySyntaxOwnership("README.md", []byte("```shell\nrm file\n"), 10)
	if complete {
		t.Fatal("unclosed executable region reported complete")
	}
}
