package peer

import (
	"cwtch.im/cwtch/event"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	"testing"
)

func TestShouldPreserveHistoryOnStegmsLoad(t *testing.T) {
	historyKey := attr.LocalScope.ConstructScopedZonedPath(
		attr.ProfileZone.ConstructZonedPath(event.SaveHistoryKey),
	).ToString()
	groupKey := attr.LocalScope.ConstructScopedZonedPath(
		attr.LegacyGroupZone.ConstructZonedPath(constants.GroupID),
	).ToString()

	tests := []struct {
		name         string
		conversation *model.Conversation
		want         bool
	}{
		{
			name:         "missing policy migrates",
			conversation: &model.Conversation{Attributes: model.Attributes{}},
			want:         true,
		},
		{
			name: "default delete migrates",
			conversation: &model.Conversation{Attributes: model.Attributes{
				historyKey: event.DeleteHistoryDefault,
			}},
			want: true,
		},
		{
			name: "existing save remains saved",
			conversation: &model.Conversation{Attributes: model.Attributes{
				historyKey: event.SaveHistoryConfirmed,
			}},
			want: true,
		},
		{
			name: "explicit delete remains authoritative",
			conversation: &model.Conversation{Attributes: model.Attributes{
				historyKey: event.DeleteHistoryConfirmed,
			}},
			want: false,
		},
		{
			name: "legacy group is unchanged",
			conversation: &model.Conversation{Attributes: model.Attributes{
				groupKey: "group-id",
			}},
			want: false,
		},
		{
			name:         "nil conversation is ignored",
			conversation: nil,
			want:         false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldPreserveHistoryOnStegmsLoad(test.conversation); got != test.want {
				t.Fatalf("shouldPreserveHistoryOnStegmsLoad() = %v, want %v", got, test.want)
			}
		})
	}
}
