package utils

import "cwtch.im/cwtch/event"

// An event to set the logging level dynamically from the UI
const (
	SetLoggingLevel = event.Type("SetLoggingLevel")
)

// Logging Levels as Event Fields. Note: Unlike most event we don't cae about
// the *value* of the field, only the presence. If more than one of these fields is
// present in a single SetLoggingLevel event then the highest logging level is used. INFO < WARN < ERROR < DEBUG
const (
	Warn  = event.Field("Warn")
	Error = event.Field("Error")
	Debug = event.Field("Debug")
	Info  = event.Field("Info")
)
