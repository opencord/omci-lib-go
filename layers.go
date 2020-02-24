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
	me "github.com/opencord/omci-lib-go/generated"
	"github.com/google/gopacket"
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
	LayerTypeCreateRequest = mkReqLayer(me.Create, "CreateRequest", gopacket.DecodeFunc(decodeCreateRequest))
	LayerTypeDeleteRequest = mkReqLayer(me.Delete, "DeleteRequest", gopacket.DecodeFunc(decodeDeleteRequest))
	LayerTypeSetRequest = mkReqLayer(me.Set, "SetRequest", gopacket.DecodeFunc(decodeSetRequest))
	LayerTypeGetRequest = mkReqLayer(me.Get, "GetRequest", gopacket.DecodeFunc(decodeGetRequest))
	LayerTypeGetAllAlarmsRequest = mkReqLayer(me.GetAllAlarms, "GetAllAlarmsRequest", gopacket.DecodeFunc(decodeGetAllAlarmsRequest))
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextRequest", gopacket.DecodeFunc(decodeGetAllAlarmsNextRequest))
	LayerTypeMibUploadRequest = mkReqLayer(me.MibUpload, "MibUploadRequest", gopacket.DecodeFunc(decodeMibUploadRequest))
	LayerTypeMibUploadNextRequest = mkReqLayer(me.MibUploadNext, "MibUploadNextRequest", gopacket.DecodeFunc(decodeMibUploadNextRequest))
	LayerTypeMibResetRequest = mkReqLayer(me.MibReset, "MibResetRequest", gopacket.DecodeFunc(decodeMibResetRequest))
	LayerTypeTestRequest = mkReqLayer(me.Test, "TestRequest", gopacket.DecodeFunc(decodeTestRequest))
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(me.StartSoftwareDownload, "StartSoftwareDownloadRequest", gopacket.DecodeFunc(decodeStartSoftwareDownloadRequest))

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	LayerTypeDownloadSectionRequest = mkLayer(me.DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeDownloadSectionLastRequest = mkReqLayer(me.DownloadSection, "DownloadLastSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(me.EndSoftwareDownload, "EndSoftwareDownloadRequest", gopacket.DecodeFunc(decodeEndSoftwareDownloadRequest))
	LayerTypeActivateSoftwareRequest = mkReqLayer(me.ActivateSoftware, "ActivateSoftwareRequest", gopacket.DecodeFunc(decodeActivateSoftwareRequest))
	LayerTypeCommitSoftwareRequest = mkReqLayer(me.CommitSoftware, "CommitSoftwareRequest", gopacket.DecodeFunc(decodeCommitSoftwareRequest))
	LayerTypeSynchronizeTimeRequest = mkReqLayer(me.SynchronizeTime, "SynchronizeTimeRequest", gopacket.DecodeFunc(decodeSynchronizeTimeRequest))
	LayerTypeRebootRequest = mkReqLayer(me.Reboot, "RebootRequest", gopacket.DecodeFunc(decodeRebootRequest))
	LayerTypeGetNextRequest = mkReqLayer(me.GetNext, "GetNextRequest", gopacket.DecodeFunc(decodeGetNextRequest))
	LayerTypeGetCurrentDataRequest = mkReqLayer(me.GetCurrentData, "GetCurrentDataRequest", gopacket.DecodeFunc(decodeGetCurrentDataRequest))
	LayerTypeSetTableRequest = mkReqLayer(me.SetTable, "SetTableRequest", gopacket.DecodeFunc(decodeSetTableRequest))

	LayerTypeCreateResponse = mkRespLayer(me.Create, "CreateResponse", gopacket.DecodeFunc(decodeCreateResponse))
	LayerTypeDeleteResponse = mkRespLayer(me.Delete, "DeleteResponse", gopacket.DecodeFunc(decodeDeleteResponse))
	LayerTypeSetResponse = mkRespLayer(me.Set, "SetResponse", gopacket.DecodeFunc(decodeSetResponse))
	LayerTypeGetResponse = mkRespLayer(me.Get, "GetResponse", gopacket.DecodeFunc(decodeGetResponse))
	LayerTypeGetAllAlarmsResponse = mkRespLayer(me.GetAllAlarms, "GetAllAlarmsResponse", gopacket.DecodeFunc(decodeGetAllAlarmsResponse))
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextResponse", gopacket.DecodeFunc(decodeGetAllAlarmsNextResponse))
	LayerTypeMibUploadResponse = mkRespLayer(me.MibUpload, "MibUploadResponse", gopacket.DecodeFunc(decodeMibUploadResponse))
	LayerTypeMibUploadNextResponse = mkRespLayer(me.MibUploadNext, "MibUploadNextResponse", gopacket.DecodeFunc(decodeMibUploadNextResponse))
	LayerTypeMibResetResponse = mkRespLayer(me.MibReset, "MibResetResponse", gopacket.DecodeFunc(decodeMibResetResponse))
	LayerTypeAlarmNotification = mkLayer(me.AlarmNotification, "AlarmNotification", gopacket.DecodeFunc(decodeAlarmNotification))
	LayerTypeAttributeValueChange = mkLayer(me.AttributeValueChange, "AttributeValueChange", gopacket.DecodeFunc(decodeAttributeValueChange))
	LayerTypeTestResponse = mkRespLayer(me.Test, "TestResponse", gopacket.DecodeFunc(decodeTestResponse))
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(me.StartSoftwareDownload, "StartSoftwareDownloadResponse", gopacket.DecodeFunc(decodeStartSoftwareDownloadResponse))
	LayerTypeDownloadSectionResponse = mkRespLayer(me.DownloadSection, "DownloadSectionResponse", gopacket.DecodeFunc(decodeDownloadSectionResponse))
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(me.EndSoftwareDownload, "EndSoftwareDownloadResponse", gopacket.DecodeFunc(decodeEndSoftwareDownloadResponse))
	LayerTypeActivateSoftwareResponse = mkRespLayer(me.ActivateSoftware, "ActivateSoftwareResponse", gopacket.DecodeFunc(decodeActivateSoftwareResponse))
	LayerTypeCommitSoftwareResponse = mkRespLayer(me.CommitSoftware, "CommitSoftwareResponse", gopacket.DecodeFunc(decodeCommitSoftwareResponse))
	LayerTypeSynchronizeTimeResponse = mkRespLayer(me.SynchronizeTime, "SynchronizeTimeResponse", gopacket.DecodeFunc(decodeSynchronizeTimeResponse))
	LayerTypeRebootResponse = mkRespLayer(me.Reboot, "RebootResponse", gopacket.DecodeFunc(decodeRebootResponse))
	LayerTypeGetNextResponse = mkRespLayer(me.GetNext, "GetNextResponse", gopacket.DecodeFunc(decodeGetNextResponse))
	LayerTypeTestResult = mkRespLayer(me.TestResult, "TestResult", gopacket.DecodeFunc(decodeTestResult))
	LayerTypeGetCurrentDataResponse = mkRespLayer(me.GetCurrentData, "GetCurrentDataResponse", gopacket.DecodeFunc(decodeGetCurrentDataResponse))
	LayerTypeSetTableResponse = mkRespLayer(me.SetTable, "SetTableResponse", gopacket.DecodeFunc(decodeSetTableResponse))

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
	nextLayerMapping[EndSoftwareDownloadRequestType] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[ActivateSoftwareRequestType] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[CommitSoftwareRequestType] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[SynchronizeTimeRequestType] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[RebootRequestType] = LayerTypeRebootRequest
	nextLayerMapping[GetNextRequestType] = LayerTypeGetNextRequest
	nextLayerMapping[GetCurrentDataRequestType] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[SetTableRequestType] = LayerTypeSetTableRequest

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
	nextLayerMapping[SetTableResponseType] = LayerTypeSetTableResponse

	nextLayerMapping[AttributeValueChangeType] = LayerTypeAttributeValueChange
	nextLayerMapping[AlarmNotificationType] = LayerTypeAlarmNotification
	nextLayerMapping[TestResultType] = LayerTypeTestResult
}

func MsgTypeToNextLayer(mt MessageType) (gopacket.LayerType, error) {
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown message type")
}
