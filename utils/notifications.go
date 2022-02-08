package utils

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"git.openprivacy.ca/cwtch.im/libcwtch-go/constants"
)

func determineNotification(ci *model.Conversation) constants.NotificationType {
	settings := ReadGlobalSettings()
	switch settings.NotificationPolicy {
	case NotificationPolicyMute:
		return constants.NotificationNone
	case NotificationPolicyOptIn:
		if ci != nil {
			if policy, exists := ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.ConversationNotificationPolicy); exists {
				switch policy {
				case constants.ConversationNotificationPolicyDefault:
					return constants.NotificationNone
				case constants.ConversationNotificationPolicyNever:
					return constants.NotificationNone
				case constants.ConversationNotificationPolicyOptIn:
					return notificationContentToNotificationType(settings.NotificationContent)
				}
			}
		}
		return constants.NotificationNone
	case NotificationPolicyDefaultAll:
		if ci != nil {
			if policy, exists := ci.GetAttribute(attr.LocalScope, attr.ProfileZone, constants.ConversationNotificationPolicy); exists {
				switch policy {
				case constants.ConversationNotificationPolicyNever:
					return constants.NotificationNone
				case constants.ConversationNotificationPolicyDefault:
					fallthrough
				case constants.ConversationNotificationPolicyOptIn:
					return notificationContentToNotificationType(settings.NotificationContent)
				}
			}
		}
		return notificationContentToNotificationType(settings.NotificationContent)
	}
	return constants.NotificationNone
}

func notificationContentToNotificationType(notificationContent string) constants.NotificationType {
	if notificationContent == "NotificationContent.ContactInfo" {
		return constants.NotificationConversation
	}
	return constants.NotificationEvent
}
