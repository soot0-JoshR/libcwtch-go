package groups

import "testing"

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
