/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 * Copyright 2020-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package omci

import (
	me "github.com/opencord/omci-lib-go/v2/generated"
)

// MessageType is the OMCI Message Type combined with the AR/AK flags as appropriate.
type MessageType byte

const (
	CreateRequestType                      = MessageType(byte(me.Create) | me.AR)
	CreateResponseType                     = MessageType(byte(me.Create) | me.AK)
	DeleteRequestType                      = MessageType(byte(me.Delete) | me.AR)
	DeleteResponseType                     = MessageType(byte(me.Delete) | me.AK)
	SetRequestType                         = MessageType(byte(me.Set) | me.AR)
	SetResponseType                        = MessageType(byte(me.Set) | me.AK)
	GetRequestType                         = MessageType(byte(me.Get) | me.AR)
	GetResponseType                        = MessageType(byte(me.Get) | me.AK)
	GetAllAlarmsRequestType                = MessageType(byte(me.GetAllAlarms) | me.AR)
	GetAllAlarmsResponseType               = MessageType(byte(me.GetAllAlarms) | me.AK)
	GetAllAlarmsNextRequestType            = MessageType(byte(me.GetAllAlarmsNext) | me.AR)
	GetAllAlarmsNextResponseType           = MessageType(byte(me.GetAllAlarmsNext) | me.AK)
	MibUploadRequestType                   = MessageType(byte(me.MibUpload) | me.AR)
	MibUploadResponseType                  = MessageType(byte(me.MibUpload) | me.AK)
	MibUploadNextRequestType               = MessageType(byte(me.MibUploadNext) | me.AR)
	MibUploadNextResponseType              = MessageType(byte(me.MibUploadNext) | me.AK)
	MibResetRequestType                    = MessageType(byte(me.MibReset) | me.AR)
	MibResetResponseType                   = MessageType(byte(me.MibReset) | me.AK)
	TestRequestType                        = MessageType(byte(me.Test) | me.AR)
	TestResponseType                       = MessageType(byte(me.Test) | me.AK)
	StartSoftwareDownloadRequestType       = MessageType(byte(me.StartSoftwareDownload) | me.AR)
	StartSoftwareDownloadResponseType      = MessageType(byte(me.StartSoftwareDownload) | me.AK)
	DownloadSectionRequestType             = MessageType(me.DownloadSection) // me.AR is optional
	DownloadSectionRequestWithResponseType = MessageType(byte(me.DownloadSection) | me.AR)
	DownloadSectionResponseType            = MessageType(byte(me.DownloadSection) | me.AK)
	EndSoftwareDownloadRequestType         = MessageType(byte(me.EndSoftwareDownload) | me.AR)
	EndSoftwareDownloadResponseType        = MessageType(byte(me.EndSoftwareDownload) | me.AK)
	ActivateSoftwareRequestType            = MessageType(byte(me.ActivateSoftware) | me.AR)
	ActivateSoftwareResponseType           = MessageType(byte(me.ActivateSoftware) | me.AK)
	CommitSoftwareRequestType              = MessageType(byte(me.CommitSoftware) | me.AR)
	CommitSoftwareResponseType             = MessageType(byte(me.CommitSoftware) | me.AK)
	SynchronizeTimeRequestType             = MessageType(byte(me.SynchronizeTime) | me.AR)
	SynchronizeTimeResponseType            = MessageType(byte(me.SynchronizeTime) | me.AK)
	RebootRequestType                      = MessageType(byte(me.Reboot) | me.AR)
	RebootResponseType                     = MessageType(byte(me.Reboot) | me.AK)
	GetNextRequestType                     = MessageType(byte(me.GetNext) | me.AR)
	GetNextResponseType                    = MessageType(byte(me.GetNext) | me.AK)
	GetCurrentDataRequestType              = MessageType(byte(me.GetCurrentData) | me.AR)
	GetCurrentDataResponseType             = MessageType(byte(me.GetCurrentData) | me.AK)
	SetTableRequestType                    = MessageType(byte(me.SetTable) | me.AR)
	SetTableResponseType                   = MessageType(byte(me.SetTable) | me.AK)

	// Autonomous ONU messages

	AlarmNotificationType    = MessageType(me.AlarmNotification)
	AttributeValueChangeType = MessageType(me.AttributeValueChange)
	TestResultType           = MessageType(me.TestResult)

	// Support mapping of extended format types (use MSB reserved bit)

	ExtendedTypeDecodeOffset = MessageType(byte(0x80))
)

func (mt MessageType) String() string {
	switch mt {
	default:
		return "Unknown"

	case CreateRequestType:
		return "Create Request"
	case CreateResponseType:
		return "Create Response"
	case DeleteRequestType:
		return "Delete Request"
	case DeleteResponseType:
		return "Delete Response"
	case SetRequestType:
		return "Set Request"
	case SetResponseType:
		return "Set Response"
	case GetRequestType:
		return "Get Request"
	case GetResponseType:
		return "Get Response"
	case GetAllAlarmsRequestType:
		return "Get All Alarms Request"
	case GetAllAlarmsResponseType:
		return "Get All Alarms Response"
	case GetAllAlarmsNextRequestType:
		return "Get All Alarms Next Request"
	case GetAllAlarmsNextResponseType:
		return "Get All Alarms Next Response"
	case MibUploadRequestType:
		return "MIB Upload Request"
	case MibUploadResponseType:
		return "MIB Upload Response"
	case MibUploadNextRequestType:
		return "MIB Upload Next Request"
	case MibUploadNextResponseType:
		return "MIB Upload Next Response"
	case MibResetRequestType:
		return "MIB Reset Request"
	case MibResetResponseType:
		return "MIB Reset Response"
	case TestRequestType:
		return "Test Request"
	case TestResponseType:
		return "Test Response"
	case StartSoftwareDownloadRequestType:
		return "Start Software Download Request"
	case StartSoftwareDownloadResponseType:
		return "Start Software Download Response"
	case DownloadSectionRequestType, DownloadSectionRequestWithResponseType:
		return "Download Section Request"
	case DownloadSectionResponseType:
		return "Download Section Response"
	case EndSoftwareDownloadRequestType:
		return "End Software Download Request"
	case EndSoftwareDownloadResponseType:
		return "End Software Download Response"
	case ActivateSoftwareRequestType:
		return "Activate Software Request"
	case ActivateSoftwareResponseType:
		return "Activate Software Response"
	case CommitSoftwareRequestType:
		return "Commit Software Request"
	case CommitSoftwareResponseType:
		return "Commit Software Response"
	case SynchronizeTimeRequestType:
		return "Synchronize Time Request"
	case SynchronizeTimeResponseType:
		return "Synchronize Time Response"
	case RebootRequestType:
		return "Reboot Request"
	case RebootResponseType:
		return "Reboot Response"
	case GetNextRequestType:
		return "Get Next Request"
	case GetNextResponseType:
		return "Get Next Response"
	case GetCurrentDataRequestType:
		return "Get Current Data Request"
	case GetCurrentDataResponseType:
		return "Get Current Data Response"
	case SetTableRequestType:
		return "Set Table Request"
	case SetTableResponseType:
		return "Set Table Response"
	case AlarmNotificationType:
		return "Alarm Notification"
	case AttributeValueChangeType:
		return "Attribute Value Change"
	case TestResultType:
		return "Test Result"
	}
}
