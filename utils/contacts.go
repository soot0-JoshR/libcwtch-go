package utils

import "cwtch.im/cwtch/model"

type Contact struct {
	Name               string                  `json:"name"`
	Onion              string                  `json:"onion"`
	Status             string                  `json:"status"`
	Picture            string                  `json:"picture"`
	DefaultPicture     string                  `json:"defaultPicture"`
	Accepted           bool                    `json:"accepted"`
	AccessControlList  model.AccessControlList `json:"accessControlList"`
	Blocked            bool                    `json:"blocked"`
	SaveHistory        string                  `json:"saveConversationHistory"`
	Messages           int                     `json:"numMessages"`
	Unread             int                     `json:"numUnread"`
	LastMessage        string                  `json:"lastMsgTime"`
	IsGroup            bool                    `json:"isGroup"`
	GroupServer        string                  `json:"groupServer"`
	IsArchived         bool                    `json:"isArchived"`
	Identifier         int                     `json:"identifier"`
	NotificationPolicy string                  `json:"notificationPolicy"`
}
