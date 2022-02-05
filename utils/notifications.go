package utils

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
)

func determineNotification(ci *model.Conversation) constants.NotificationType {
	settings := ReadGlobalSettings()

	switch settings.NotificationPolicy {
	case NotificationPolicyNone:
		return constants.NotificationNone
	case NotificationPolicyOptOut:
		if ci != nil {
			if optOut, exists := ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.NotificationOptOut); exists && optOut == "true" {
				return constants.NotificationNone
			}
		}
		if settings.NotificationContent == "NotificationContent.ContactInfo" {
			return constants.NotificationConversation
		}
		return constants.NotificationEvent
	case NotificationPolicyOptIn:
		if ci != nil {
			if optIn, exists := ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.NotificationOptIn); exists && optIn == "true" {
				if settings.NotificationContent == "NotificationContent.ContactInfo" {
					return constants.NotificationConversation
				}
				return constants.NotificationEvent
			}
		}
		return constants.NotificationNone
	}
	return constants.NotificationNone
}
