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
	"errors"
	"github.com/google/gopacket"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

var nextLayerMapping map[MessageType]gopacket.LayerType

var (
	LayerTypeCreateRequest                gopacket.LayerType
	LayerTypeDeleteRequest                gopacket.LayerType
	LayerTypeSetRequest                   gopacket.LayerType
	LayerTypeGetRequest                   gopacket.LayerType
	LayerTypeGetAllAlarmsRequest          gopacket.LayerType
	LayerTypeGetAllAlarmsNextRequest      gopacket.LayerType
	LayerTypeMibUploadRequest             gopacket.LayerType
	LayerTypeMibUploadNextRequest         gopacket.LayerType
	LayerTypeMibResetRequest              gopacket.LayerType
	LayerTypeTestRequest                  gopacket.LayerType
	LayerTypeStartSoftwareDownloadRequest gopacket.LayerType
	LayerTypeDownloadSectionRequest       gopacket.LayerType
	LayerTypeDownloadSectionLastRequest   gopacket.LayerType
	LayerTypeEndSoftwareDownloadRequest   gopacket.LayerType
	LayerTypeActivateSoftwareRequest      gopacket.LayerType
	LayerTypeCommitSoftwareRequest        gopacket.LayerType
	LayerTypeSynchronizeTimeRequest       gopacket.LayerType
	LayerTypeRebootRequest                gopacket.LayerType
	LayerTypeGetNextRequest               gopacket.LayerType
	LayerTypeGetCurrentDataRequest        gopacket.LayerType
	LayerTypeSetTableRequest              gopacket.LayerType

	LayerTypeCreateRequestExtended                gopacket.LayerType
	LayerTypeDeleteRequestExtended                gopacket.LayerType
	LayerTypeSetRequestExtended                   gopacket.LayerType
	LayerTypeMibUploadRequestExtended             gopacket.LayerType
	LayerTypeMibUploadNextRequestExtended         gopacket.LayerType
	LayerTypeMibResetRequestExtended              gopacket.LayerType
	LayerTypeGetRequestExtended                   gopacket.LayerType
	LayerTypeGetNextRequestExtended               gopacket.LayerType
	LayerTypeStartSoftwareDownloadRequestExtended gopacket.LayerType
	LayerTypeDownloadSectionRequestExtended       gopacket.LayerType
	LayerTypeDownloadSectionLastRequestExtended   gopacket.LayerType
	LayerTypeEndSoftwareDownloadRequestExtended   gopacket.LayerType
	LayerTypeActivateSoftwareRequestExtended      gopacket.LayerType
	LayerTypeCommitSoftwareRequestExtended        gopacket.LayerType
	LayerTypeSynchronizeTimeRequestExtended       gopacket.LayerType
	LayerTypeRebootRequestExtended                gopacket.LayerType
	LayerTypeGetCurrentDataRequestExtended        gopacket.LayerType
	LayerTypeSetTableRequestExtended              gopacket.LayerType
	LayerTypeGetAllAlarmsRequestExtended          gopacket.LayerType
	LayerTypeGetAllAlarmsNextRequestExtended      gopacket.LayerType
)
var (
	LayerTypeCreateResponse                gopacket.LayerType
	LayerTypeDeleteResponse                gopacket.LayerType
	LayerTypeSetResponse                   gopacket.LayerType
	LayerTypeGetResponse                   gopacket.LayerType
	LayerTypeGetAllAlarmsResponse          gopacket.LayerType
	LayerTypeGetAllAlarmsNextResponse      gopacket.LayerType
	LayerTypeMibUploadResponse             gopacket.LayerType
	LayerTypeMibUploadNextResponse         gopacket.LayerType
	LayerTypeMibResetResponse              gopacket.LayerType
	LayerTypeAlarmNotification             gopacket.LayerType
	LayerTypeAttributeValueChange          gopacket.LayerType
	LayerTypeTestResponse                  gopacket.LayerType
	LayerTypeStartSoftwareDownloadResponse gopacket.LayerType
	LayerTypeDownloadSectionResponse       gopacket.LayerType
	LayerTypeEndSoftwareDownloadResponse   gopacket.LayerType
	LayerTypeActivateSoftwareResponse      gopacket.LayerType
	LayerTypeCommitSoftwareResponse        gopacket.LayerType
	LayerTypeSynchronizeTimeResponse       gopacket.LayerType
	LayerTypeRebootResponse                gopacket.LayerType
	LayerTypeGetNextResponse               gopacket.LayerType
	LayerTypeTestResult                    gopacket.LayerType
	LayerTypeGetCurrentDataResponse        gopacket.LayerType
	LayerTypeSetTableResponse              gopacket.LayerType

	LayerTypeCreateResponseExtended                gopacket.LayerType
	LayerTypeDeleteResponseExtended                gopacket.LayerType
	LayerTypeSetResponseExtended                   gopacket.LayerType
	LayerTypeMibUploadResponseExtended             gopacket.LayerType
	LayerTypeMibUploadNextResponseExtended         gopacket.LayerType
	LayerTypeMibResetResponseExtended              gopacket.LayerType
	LayerTypeGetResponseExtended                   gopacket.LayerType
	LayerTypeGetNextResponseExtended               gopacket.LayerType
	LayerTypeStartSoftwareDownloadResponseExtended gopacket.LayerType
	LayerTypeDownloadSectionResponseExtended       gopacket.LayerType
	LayerTypeEndSoftwareDownloadResponseExtended   gopacket.LayerType
	LayerTypeActivateSoftwareResponseExtended      gopacket.LayerType
	LayerTypeCommitSoftwareResponseExtended        gopacket.LayerType
	LayerTypeAlarmNotificationExtended             gopacket.LayerType
	LayerTypeAttributeValueChangeExtended          gopacket.LayerType
	LayerTypeTestResultExtended                    gopacket.LayerType
	LayerTypeSynchronizeTimeResponseExtended       gopacket.LayerType
	LayerTypeRebootResponseExtended                gopacket.LayerType
	LayerTypeGetCurrentDataResponseExtended        gopacket.LayerType
	LayerTypeSetTableResponseExtended              gopacket.LayerType
	LayerTypeGetAllAlarmsResponseExtended          gopacket.LayerType
	LayerTypeGetAllAlarmsNextResponseExtended      gopacket.LayerType
)
var (
	LayerTypeUnknownAttributes gopacket.LayerType
)

func mkReqLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(me.AR)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkRespLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(me.AK)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func init() {
	// Create layers for message_type & action
	LayerTypeCreateRequest = mkReqLayer(me.Create, "CreateRequest", decodeCreateRequest)
	LayerTypeDeleteRequest = mkReqLayer(me.Delete, "DeleteRequest", decodeDeleteRequest)
	LayerTypeSetRequest = mkReqLayer(me.Set, "SetRequest", decodeSetRequest)
	LayerTypeGetRequest = mkReqLayer(me.Get, "GetRequest", decodeGetRequest)
	LayerTypeGetAllAlarmsRequest = mkReqLayer(me.GetAllAlarms, "GetAllAlarmsRequest", decodeGetAllAlarmsRequest)
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextRequest", decodeGetAllAlarmsNextRequest)
	LayerTypeMibUploadRequest = mkReqLayer(me.MibUpload, "MibUploadRequest", decodeMibUploadRequest)
	LayerTypeMibUploadNextRequest = mkReqLayer(me.MibUploadNext, "MibUploadNextRequest", decodeMibUploadNextRequest)
	LayerTypeMibResetRequest = mkReqLayer(me.MibReset, "MibResetRequest", decodeMibResetRequest)
	LayerTypeTestRequest = mkReqLayer(me.Test, "TestRequest", decodeTestRequest)
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(me.StartSoftwareDownload, "StartSoftwareDownloadRequest", decodeStartSoftwareDownloadRequest)

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	LayerTypeDownloadSectionRequest = mkLayer(me.DownloadSection, "DownloadSectionRequest", decodeDownloadSectionRequest)
	LayerTypeDownloadSectionLastRequest = mkReqLayer(me.DownloadSection, "DownloadLastSectionRequest", decodeDownloadSectionRequest)
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(me.EndSoftwareDownload, "EndSoftwareDownloadRequest", decodeEndSoftwareDownloadRequest)
	LayerTypeActivateSoftwareRequest = mkReqLayer(me.ActivateSoftware, "ActivateSoftwareRequest", decodeActivateSoftwareRequest)
	LayerTypeCommitSoftwareRequest = mkReqLayer(me.CommitSoftware, "CommitSoftwareRequest", decodeCommitSoftwareRequest)
	LayerTypeSynchronizeTimeRequest = mkReqLayer(me.SynchronizeTime, "SynchronizeTimeRequest", decodeSynchronizeTimeRequest)
	LayerTypeRebootRequest = mkReqLayer(me.Reboot, "RebootRequest", decodeRebootRequest)
	LayerTypeGetNextRequest = mkReqLayer(me.GetNext, "GetNextRequest", decodeGetNextRequest)
	LayerTypeGetCurrentDataRequest = mkReqLayer(me.GetCurrentData, "GetCurrentDataRequest", decodeGetCurrentDataRequest)
	LayerTypeSetTableRequest = mkReqLayer(me.SetTable, "SetTableRequest", decodeSetTableRequest)

	LayerTypeCreateResponse = mkRespLayer(me.Create, "CreateResponse", decodeCreateResponse)
	LayerTypeDeleteResponse = mkRespLayer(me.Delete, "DeleteResponse", decodeDeleteResponse)
	LayerTypeSetResponse = mkRespLayer(me.Set, "SetResponse", decodeSetResponse)
	LayerTypeGetResponse = mkRespLayer(me.Get, "GetResponse", decodeGetResponse)
	LayerTypeGetAllAlarmsResponse = mkRespLayer(me.GetAllAlarms, "GetAllAlarmsResponse", decodeGetAllAlarmsResponse)
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextResponse", decodeGetAllAlarmsNextResponse)
	LayerTypeMibUploadResponse = mkRespLayer(me.MibUpload, "MibUploadResponse", decodeMibUploadResponse)
	LayerTypeMibUploadNextResponse = mkRespLayer(me.MibUploadNext, "MibUploadNextResponse", decodeMibUploadNextResponse)
	LayerTypeMibResetResponse = mkRespLayer(me.MibReset, "MibResetResponse", decodeMibResetResponse)
	LayerTypeAlarmNotification = mkLayer(me.AlarmNotification, "AlarmNotification", decodeAlarmNotification)
	LayerTypeAttributeValueChange = mkLayer(me.AttributeValueChange, "AttributeValueChange", decodeAttributeValueChange)
	LayerTypeTestResponse = mkRespLayer(me.Test, "TestResponse", decodeTestResponse)
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(me.StartSoftwareDownload, "StartSoftwareDownloadResponse", decodeStartSoftwareDownloadResponse)
	LayerTypeDownloadSectionResponse = mkRespLayer(me.DownloadSection, "DownloadSectionResponse", decodeDownloadSectionResponse)
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(me.EndSoftwareDownload, "EndSoftwareDownloadResponse", decodeEndSoftwareDownloadResponse)
	LayerTypeActivateSoftwareResponse = mkRespLayer(me.ActivateSoftware, "ActivateSoftwareResponse", decodeActivateSoftwareResponse)
	LayerTypeCommitSoftwareResponse = mkRespLayer(me.CommitSoftware, "CommitSoftwareResponse", decodeCommitSoftwareResponse)
	LayerTypeSynchronizeTimeResponse = mkRespLayer(me.SynchronizeTime, "SynchronizeTimeResponse", decodeSynchronizeTimeResponse)
	LayerTypeRebootResponse = mkRespLayer(me.Reboot, "RebootResponse", decodeRebootResponse)
	LayerTypeGetNextResponse = mkRespLayer(me.GetNext, "GetNextResponse", decodeGetNextResponse)
	LayerTypeTestResult = mkRespLayer(me.TestResult, "TestResult", decodeTestResult)
	LayerTypeGetCurrentDataResponse = mkRespLayer(me.GetCurrentData, "GetCurrentDataResponse", decodeGetCurrentDataResponse)
	LayerTypeSetTableResponse = mkRespLayer(me.SetTable, "SetTableResponse", decodeSetTableResponse)

	// Extended message set support

	LayerTypeCreateRequestExtended = mkReqLayer(me.Create|me.ExtendedOffset, "CreateRequest-Ext", decodeCreateRequestExtended)
	LayerTypeDeleteRequestExtended = mkReqLayer(me.Delete|me.ExtendedOffset, "DeleteRequest-Ext", decodeDeleteRequestExtended)
	LayerTypeSetRequestExtended = mkReqLayer(me.Set|me.ExtendedOffset, "SetRequest-Ext", decodeSetRequestExtended)
	LayerTypeGetRequestExtended = mkReqLayer(me.Get|me.ExtendedOffset, "GetRequest-Ext", decodeGetRequestExtended)
	LayerTypeGetNextRequestExtended = mkReqLayer(me.GetNext|me.ExtendedOffset, "GetNextRequest-Ext", decodeGetNextRequestExtended)
	LayerTypeMibUploadRequestExtended = mkReqLayer(me.MibUpload|me.ExtendedOffset, "MibUploadRequest-Ext", decodeMibUploadRequestExtended)
	LayerTypeMibUploadNextRequestExtended = mkReqLayer(me.MibUploadNext|me.ExtendedOffset, "MibUploadNextRequest-Ext", decodeMibUploadNextRequestExtended)
	LayerTypeMibResetRequestExtended = mkReqLayer(me.MibReset|me.ExtendedOffset, "MibResetRequest-Ext", decodeMibResetRequestExtended)
	LayerTypeStartSoftwareDownloadRequestExtended = mkReqLayer(me.StartSoftwareDownload|me.ExtendedOffset, "StartSoftwareDownloadRequest-Ext", decodeStartSoftwareDownloadRequestExtended)
	LayerTypeDownloadSectionRequestExtended = mkLayer(me.DownloadSection|me.ExtendedOffset, "DownloadSectionRequest-Ext", decodeDownloadSectionRequestExtended)
	LayerTypeDownloadSectionLastRequestExtended = mkReqLayer(me.DownloadSection|me.ExtendedOffset, "DownloadLastSectionRequest-Ext", decodeDownloadSectionRequestExtended)
	LayerTypeEndSoftwareDownloadRequestExtended = mkReqLayer(me.EndSoftwareDownload|me.ExtendedOffset, "EndSoftwareDownloadRequest-Ext", decodeEndSoftwareDownloadRequestExtended)
	LayerTypeActivateSoftwareRequestExtended = mkReqLayer(me.ActivateSoftware|me.ExtendedOffset, "ActivateSoftwareRequest-Ext", decodeActivateSoftwareRequestExtended)
	LayerTypeCommitSoftwareRequestExtended = mkReqLayer(me.CommitSoftware|me.ExtendedOffset, "CommitSoftwareRequest-Ext", decodeCommitSoftwareRequestExtended)
	LayerTypeSynchronizeTimeRequestExtended = mkReqLayer(me.SynchronizeTime|me.ExtendedOffset, "SynchronizeTimeRequest-Ext", decodeSynchronizeTimeRequestExtended)
	LayerTypeRebootRequestExtended = mkReqLayer(me.Reboot|me.ExtendedOffset, "RebootRequest-Ext", decodeRebootRequestExtended)
	LayerTypeGetCurrentDataRequestExtended = mkReqLayer(me.GetCurrentData|me.ExtendedOffset, "GetCurrentDataRequest-Ext", decodeGetCurrentDataRequestExtended)
	LayerTypeSetTableRequestExtended = mkReqLayer(me.SetTable|me.ExtendedOffset, "SetTableRequest-Ext", decodeSetTableRequestExtended)
	LayerTypeGetAllAlarmsRequestExtended = mkReqLayer(me.GetAllAlarms|me.ExtendedOffset, "GetAllAlarmsRequest-Ext", decodeGetAllAlarmsRequestExtended)
	LayerTypeGetAllAlarmsNextRequestExtended = mkReqLayer(me.GetAllAlarmsNext|me.ExtendedOffset, "GetAllAlarmsNextRequest-Ext", decodeGetAllAlarmsNextRequestExtended)

	LayerTypeCreateResponseExtended = mkRespLayer(me.Create|me.ExtendedOffset, "CreateResponse-Ext", decodeCreateResponseExtended)
	LayerTypeDeleteResponseExtended = mkRespLayer(me.Delete|me.ExtendedOffset, "DeleteResponse-Ext", decodeDeleteResponseExtended)
	LayerTypeSetResponseExtended = mkRespLayer(me.Set|me.ExtendedOffset, "SetResponse-Ext", decodeSetResponseExtended)
	LayerTypeGetResponseExtended = mkRespLayer(me.Get|me.ExtendedOffset, "GetResponse-Ext", decodeGetResponseExtended)
	LayerTypeGetNextResponseExtended = mkRespLayer(me.GetNext|me.ExtendedOffset, "GetNextResponse-Ext", decodeGetNextResponseExtended)
	LayerTypeMibUploadResponseExtended = mkRespLayer(me.MibUpload|me.ExtendedOffset, "MibUploadResponse-Ext", decodeMibUploadResponseExtended)
	LayerTypeMibUploadNextResponseExtended = mkRespLayer(me.MibUploadNext|me.ExtendedOffset, "MibUploadNextResponse-Ext", decodeMibUploadNextResponseExtended)
	LayerTypeMibResetResponseExtended = mkRespLayer(me.MibReset|me.ExtendedOffset, "MibResetResponse-Ext", decodeMibResetResponseExtended)
	LayerTypeStartSoftwareDownloadResponseExtended = mkRespLayer(me.StartSoftwareDownload|me.ExtendedOffset, "StartSoftwareDownloadResponse-Ext", decodeStartSoftwareDownloadResponseExtended)
	LayerTypeDownloadSectionResponseExtended = mkRespLayer(me.DownloadSection|me.ExtendedOffset, "DownloadSectionResponse-Ext", decodeDownloadSectionResponseExtended)
	LayerTypeEndSoftwareDownloadResponseExtended = mkRespLayer(me.EndSoftwareDownload|me.ExtendedOffset, "EndSoftwareDownloadResponse-Ext", decodeEndSoftwareDownloadResponseExtended)
	LayerTypeActivateSoftwareResponseExtended = mkRespLayer(me.ActivateSoftware|me.ExtendedOffset, "ActivateSoftwareResponse-Ext", decodeActivateSoftwareResponseExtended)
	LayerTypeCommitSoftwareResponseExtended = mkRespLayer(me.CommitSoftware|me.ExtendedOffset, "CommitSoftwareResponse-Ext", decodeCommitSoftwareResponseExtended)
	LayerTypeSynchronizeTimeResponseExtended = mkRespLayer(me.SynchronizeTime|me.ExtendedOffset, "SynchronizeTimeResponse-Ext", decodeSynchronizeTimeResponseExtended)
	LayerTypeRebootResponseExtended = mkRespLayer(me.Reboot|me.ExtendedOffset, "RebootResponse-Ext", decodeRebootResponseExtended)
	LayerTypeGetCurrentDataResponseExtended = mkRespLayer(me.GetCurrentData|me.ExtendedOffset, "GetCurrentDataResponse-Ext", decodeGetCurrentDataResponseExtended)
	LayerTypeSetTableResponseExtended = mkRespLayer(me.SetTable|me.ExtendedOffset, "SetTableResponse-Ext", decodeSetTableResponseExtended)
	LayerTypeGetAllAlarmsResponseExtended = mkRespLayer(me.GetAllAlarms|me.ExtendedOffset, "GetAllAlarmsResponse-Ext", decodeGetAllAlarmsResponseExtended)
	LayerTypeGetAllAlarmsNextResponseExtended = mkRespLayer(me.GetAllAlarmsNext|me.ExtendedOffset, "GetAllAlarmsNextResponse-Ext", decodeGetAllAlarmsNextResponseExtended)

	LayerTypeAlarmNotificationExtended = mkLayer(me.AlarmNotification|me.ExtendedOffset, "AlarmNotification-Ext", decodeAlarmNotificationExtended)
	LayerTypeAttributeValueChangeExtended = mkLayer(me.AttributeValueChange|me.ExtendedOffset, "AttributeValueChange-Ext", decodeAttributeValueChangeExtended)
	LayerTypeTestResultExtended = mkLayer(me.TestResult|me.ExtendedOffset, "TestResult-Ext", decodeTestResultExtended)

	// Map message_type and action to layer
	nextLayerMapping = make(map[MessageType]gopacket.LayerType)

	nextLayerMapping[CreateRequestType] = LayerTypeCreateRequest
	nextLayerMapping[DeleteRequestType] = LayerTypeDeleteRequest
	nextLayerMapping[SetRequestType] = LayerTypeSetRequest
	nextLayerMapping[GetRequestType] = LayerTypeGetRequest
	nextLayerMapping[GetAllAlarmsRequestType] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[GetAllAlarmsNextRequestType] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[MibUploadRequestType] = LayerTypeMibUploadRequest
	nextLayerMapping[MibUploadNextRequestType] = LayerTypeMibUploadNextRequest
	nextLayerMapping[MibResetRequestType] = LayerTypeMibResetRequest
	nextLayerMapping[TestRequestType] = LayerTypeTestRequest
	nextLayerMapping[StartSoftwareDownloadRequestType] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[DownloadSectionRequestType] = LayerTypeDownloadSectionRequest
	nextLayerMapping[DownloadSectionRequestWithResponseType] = LayerTypeDownloadSectionLastRequest
	nextLayerMapping[EndSoftwareDownloadRequestType] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[ActivateSoftwareRequestType] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[CommitSoftwareRequestType] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[SynchronizeTimeRequestType] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[RebootRequestType] = LayerTypeRebootRequest
	nextLayerMapping[GetNextRequestType] = LayerTypeGetNextRequest
	nextLayerMapping[GetCurrentDataRequestType] = LayerTypeGetCurrentDataRequest

	nextLayerMapping[CreateResponseType] = LayerTypeCreateResponse
	nextLayerMapping[DeleteResponseType] = LayerTypeDeleteResponse
	nextLayerMapping[SetResponseType] = LayerTypeSetResponse
	nextLayerMapping[GetResponseType] = LayerTypeGetResponse
	nextLayerMapping[GetAllAlarmsResponseType] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[GetAllAlarmsNextResponseType] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[MibUploadResponseType] = LayerTypeMibUploadResponse
	nextLayerMapping[MibUploadNextResponseType] = LayerTypeMibUploadNextResponse
	nextLayerMapping[MibResetResponseType] = LayerTypeMibResetResponse
	nextLayerMapping[TestResponseType] = LayerTypeTestResponse
	nextLayerMapping[StartSoftwareDownloadResponseType] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[DownloadSectionResponseType] = LayerTypeDownloadSectionResponse
	nextLayerMapping[EndSoftwareDownloadResponseType] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[ActivateSoftwareResponseType] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[CommitSoftwareResponseType] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[SynchronizeTimeResponseType] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[RebootResponseType] = LayerTypeRebootResponse
	nextLayerMapping[GetNextResponseType] = LayerTypeGetNextResponse
	nextLayerMapping[GetCurrentDataResponseType] = LayerTypeGetCurrentDataResponse

	nextLayerMapping[AttributeValueChangeType] = LayerTypeAttributeValueChange
	nextLayerMapping[AlarmNotificationType] = LayerTypeAlarmNotification
	nextLayerMapping[TestResultType] = LayerTypeTestResult

	nextLayerMapping[SetTableRequestType] = LayerTypeSetTableRequest
	nextLayerMapping[SetTableResponseType] = LayerTypeSetTableResponse

	// Extended message support
	nextLayerMapping[CreateRequestType+ExtendedTypeDecodeOffset] = LayerTypeCreateRequestExtended
	nextLayerMapping[CreateResponseType+ExtendedTypeDecodeOffset] = LayerTypeCreateResponseExtended
	nextLayerMapping[DeleteResponseType+ExtendedTypeDecodeOffset] = LayerTypeDeleteResponseExtended
	nextLayerMapping[DeleteRequestType+ExtendedTypeDecodeOffset] = LayerTypeDeleteRequestExtended
	nextLayerMapping[SetRequestType+ExtendedTypeDecodeOffset] = LayerTypeSetRequestExtended
	nextLayerMapping[SetResponseType+ExtendedTypeDecodeOffset] = LayerTypeSetResponseExtended
	nextLayerMapping[GetRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetRequestExtended
	nextLayerMapping[GetResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetResponseExtended
	nextLayerMapping[GetNextRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetNextRequestExtended
	nextLayerMapping[GetNextResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetNextResponseExtended

	nextLayerMapping[MibUploadRequestType+ExtendedTypeDecodeOffset] = LayerTypeMibUploadRequestExtended
	nextLayerMapping[MibUploadResponseType+ExtendedTypeDecodeOffset] = LayerTypeMibUploadResponseExtended
	nextLayerMapping[MibUploadNextRequestType+ExtendedTypeDecodeOffset] = LayerTypeMibUploadNextRequestExtended
	nextLayerMapping[MibUploadNextResponseType+ExtendedTypeDecodeOffset] = LayerTypeMibUploadNextResponseExtended

	nextLayerMapping[MibResetRequestType+ExtendedTypeDecodeOffset] = LayerTypeMibResetRequestExtended
	nextLayerMapping[MibResetResponseType+ExtendedTypeDecodeOffset] = LayerTypeMibResetResponseExtended
	nextLayerMapping[SynchronizeTimeRequestType+ExtendedTypeDecodeOffset] = LayerTypeSynchronizeTimeRequestExtended
	nextLayerMapping[SynchronizeTimeResponseType+ExtendedTypeDecodeOffset] = LayerTypeSynchronizeTimeResponseExtended
	nextLayerMapping[RebootRequestType+ExtendedTypeDecodeOffset] = LayerTypeRebootRequestExtended
	nextLayerMapping[RebootResponseType+ExtendedTypeDecodeOffset] = LayerTypeRebootResponseExtended
	nextLayerMapping[GetCurrentDataRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetCurrentDataRequestExtended
	nextLayerMapping[GetCurrentDataResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetCurrentDataResponseExtended

	nextLayerMapping[SetTableRequestType+ExtendedTypeDecodeOffset] = LayerTypeSetTableRequestExtended
	nextLayerMapping[SetTableResponseType+ExtendedTypeDecodeOffset] = LayerTypeSetTableResponseExtended

	nextLayerMapping[GetAllAlarmsRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetAllAlarmsRequestExtended
	nextLayerMapping[GetAllAlarmsNextRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetAllAlarmsNextRequestExtended
	nextLayerMapping[GetAllAlarmsResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetAllAlarmsResponseExtended
	nextLayerMapping[GetAllAlarmsNextResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetAllAlarmsNextResponseExtended

	nextLayerMapping[StartSoftwareDownloadRequestType+ExtendedTypeDecodeOffset] = LayerTypeStartSoftwareDownloadRequestExtended
	nextLayerMapping[StartSoftwareDownloadResponseType+ExtendedTypeDecodeOffset] = LayerTypeStartSoftwareDownloadResponseExtended
	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	nextLayerMapping[DownloadSectionRequestType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionRequestExtended
	nextLayerMapping[DownloadSectionRequestWithResponseType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionLastRequestExtended
	nextLayerMapping[DownloadSectionResponseType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionResponseExtended

	nextLayerMapping[EndSoftwareDownloadRequestType+ExtendedTypeDecodeOffset] = LayerTypeEndSoftwareDownloadRequestExtended
	nextLayerMapping[EndSoftwareDownloadResponseType+ExtendedTypeDecodeOffset] = LayerTypeEndSoftwareDownloadResponseExtended

	nextLayerMapping[ActivateSoftwareRequestType+ExtendedTypeDecodeOffset] = LayerTypeActivateSoftwareRequestExtended
	nextLayerMapping[ActivateSoftwareResponseType+ExtendedTypeDecodeOffset] = LayerTypeActivateSoftwareResponseExtended

	nextLayerMapping[CommitSoftwareRequestType+ExtendedTypeDecodeOffset] = LayerTypeCommitSoftwareRequestExtended
	nextLayerMapping[CommitSoftwareResponseType+ExtendedTypeDecodeOffset] = LayerTypeCommitSoftwareResponseExtended

	nextLayerMapping[AlarmNotificationType+ExtendedTypeDecodeOffset] = LayerTypeAlarmNotificationExtended
	nextLayerMapping[AttributeValueChangeType+ExtendedTypeDecodeOffset] = LayerTypeAttributeValueChangeExtended
	nextLayerMapping[TestResultType+ExtendedTypeDecodeOffset] = LayerTypeTestResultExtended

	////////////////////////////////////////////////////////////////////////
	// The following are custom layers used during relaxed decode.  They are defined
	// as layers but will be appended to decoded packets as an error layer.  The DecodeFunc
	// is actually never called and does not have to be added to the nextLayerMapping
	var decode gopacket.DecodeFunc

	decode = decodeUnknownAttributes
	LayerTypeUnknownAttributes = gopacket.RegisterLayerType(2000,
		gopacket.LayerTypeMetadata{Name: "Unknown Attributes", Decoder: decode})
}

func MsgTypeToNextLayer(mt MessageType, isExtended bool) (gopacket.LayerType, error) {
	if isExtended {
		mt |= ExtendedTypeDecodeOffset
	}
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown/unsupported message type")
}
