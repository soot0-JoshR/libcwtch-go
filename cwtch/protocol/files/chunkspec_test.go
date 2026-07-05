package files

import "testing"

func TestChunkSpec(t *testing.T) {

	var testCases = map[string]ChunkSpec{
		"0":           CreateChunkSpec([]bool{false}),
		"0:10":        CreateChunkSpec([]bool{false, false, false, false, false, false, false, false, false, false, false}),
		"0:1,3:5,7:9": CreateChunkSpec([]bool{false, false, true, false, false, false, true, false, false, false, true}),
		"":            CreateChunkSpec([]bool{true, true, true, true, true, true, true, true, true, true, true}),
		"2,5,8,10":    CreateChunkSpec([]bool{true, true, false, true, true, false, true, true, false, true, false}),
		//
		"0,2:10": CreateChunkSpec([]bool{false, true, false, false, false, false, false, false, false, false, false}),
		"0:8,10": CreateChunkSpec([]bool{false, false, false, false, false, false, false, false, false, true, false}),
		"1:9":    CreateChunkSpec([]bool{true, false, false, false, false, false, false, false, false, false, true}),
	}

	for k, v := range testCases {
		if k != v.Serialize() {
			t.Fatalf("got %v but expected %v", v.Serialize(), k)
		}
		t.Logf("%v == %v", k, v.Serialize())
	}

	for k, v := range testCases {
		if cs, err := Deserialize(k); err != nil {
			t.Fatalf("error deserialized key: %v %v", k, err)
		} else {
			if v.Serialize() != cs.Serialize() {
				t.Fatalf("got %v but expected %v", v.Serialize(), cs.Serialize())
			}
			t.Logf("%v == %v", cs.Serialize(), v.Serialize())
		}
	}

}
