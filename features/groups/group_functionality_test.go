package groups

import "testing"

func TestGroupFunctionality_ValidPrefix(t *testing.T) {
	gf, _ := ExperimentGate(map[string]bool{groupExperiment: true})
	if gf.ValidPrefix("torv3blahblahblah") == false {
		t.Fatalf("torv3 should be a valid prefix")
	}
	if gf.ValidPrefix("tofubundle:32432423||3242342") == false {
		t.Fatalf("tofubundle should be a valid prefix")
	}
	if gf.ValidPrefix("server:23541233t") == false {
		t.Fatalf("server should be a valid prefix")
	}
	if gf.ValidPrefix("alice!24234") == true {
		t.Fatalf("alice should be an invalid predix")
	}
}

func TestGroupFunctionality_IsEnabled(t *testing.T) {

	_, err := ExperimentGate(map[string]bool{})

	if err == nil {
		t.Fatalf("group functionality should be disabled")
	}

	_, err = ExperimentGate(map[string]bool{groupExperiment: true})

	if err != nil {
		t.Fatalf("group functionality should be enabled")
	}

	_, err = ExperimentGate(map[string]bool{groupExperiment: false})
	if err == nil {
		t.Fatalf("group functionality should be disabled")
	}
}
