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
package meframe_test

import (
	mapset "github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/opencord/omci-lib-go/v2/meframe"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var messageTypeTestFuncs map[MessageType]func(*testing.T, *me.ManagedEntity, DeviceIdent)

var allMessageTypes = [...]MessageType{
	CreateRequestType,
	CreateResponseType,
	DeleteRequestType,
	DeleteResponseType,
	SetRequestType,
	SetResponseType,
	GetRequestType,
	GetResponseType,
	GetAllAlarmsRequestType,
	GetAllAlarmsResponseType,
	GetAllAlarmsNextRequestType,
	GetAllAlarmsNextResponseType,
	MibUploadRequestType,
	MibUploadResponseType,
	MibUploadNextRequestType,
	MibUploadNextResponseType,
	MibResetRequestType,
	MibResetResponseType,
	TestRequestType,
	TestResponseType,
	StartSoftwareDownloadRequestType,
	StartSoftwareDownloadResponseType,
	DownloadSectionRequestType,
	DownloadSectionResponseType,
	EndSoftwareDownloadRequestType,
	EndSoftwareDownloadResponseType,
	ActivateSoftwareRequestType,
	ActivateSoftwareResponseType,
	CommitSoftwareRequestType,
	CommitSoftwareResponseType,
	SynchronizeTimeRequestType,
	SynchronizeTimeResponseType,
	RebootRequestType,
	RebootResponseType,
	GetNextRequestType,
	GetNextResponseType,
	GetCurrentDataRequestType,
	GetCurrentDataResponseType,
	SetTableRequestType,
	SetTableResponseType,
	// Autonomous ONU messages
	AlarmNotificationType,
	AttributeValueChangeType,
	TestResultType,
}

var allExtendedMessageTypes = [...]MessageType{
	GetRequestType,
	GetResponseType,
}

func init() {
	messageTypeTestFuncs = make(map[MessageType]func(*testing.T, *me.ManagedEntity, DeviceIdent), 0)

	messageTypeTestFuncs[CreateRequestType] = testCreateRequestTypeMeFrame
	messageTypeTestFuncs[CreateResponseType] = testCreateResponseTypeMeFrame
	messageTypeTestFuncs[DeleteRequestType] = testDeleteRequestTypeMeFrame
	messageTypeTestFuncs[DeleteResponseType] = testDeleteResponseTypeMeFrame
	messageTypeTestFuncs[SetRequestType] = testSetRequestTypeMeFrame
	messageTypeTestFuncs[SetResponseType] = testSetResponseTypeMeFrame
	messageTypeTestFuncs[GetRequestType] = testGetRequestTypeMeFrame
	messageTypeTestFuncs[GetResponseType] = testGetResponseTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsRequestType] = testGetAllAlarmsRequestTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsResponseType] = testGetAllAlarmsResponseTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsNextRequestType] = testGetAllAlarmsNextRequestTypeMeFrame
	messageTypeTestFuncs[GetAllAlarmsNextResponseType] = testGetAllAlarmsNextResponseTypeMeFrame
	messageTypeTestFuncs[MibUploadRequestType] = testMibUploadRequestTypeMeFrame
	messageTypeTestFuncs[MibUploadResponseType] = testMibUploadResponseTypeMeFrame
	messageTypeTestFuncs[MibUploadNextRequestType] = testMibUploadNextRequestTypeMeFrame
	messageTypeTestFuncs[MibUploadNextResponseType] = testMibUploadNextResponseTypeMeFrame
	messageTypeTestFuncs[MibResetRequestType] = testMibResetRequestTypeMeFrame
	messageTypeTestFuncs[MibResetResponseType] = testMibResetResponseTypeMeFrame
	messageTypeTestFuncs[TestRequestType] = testTestRequestTypeMeFrame
	messageTypeTestFuncs[TestResponseType] = testTestResponseTypeMeFrame

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)4
	messageTypeTestFuncs[StartSoftwareDownloadRequestType] = testStartSoftwareDownloadRequestTypeMeFrame
	messageTypeTestFuncs[StartSoftwareDownloadResponseType] = testStartSoftwareDownloadResponseTypeMeFrame
	messageTypeTestFuncs[DownloadSectionRequestType] = testDownloadSectionRequestTypeMeFrame
	messageTypeTestFuncs[DownloadSectionResponseType] = testDownloadSectionResponseTypeMeFrame
	messageTypeTestFuncs[EndSoftwareDownloadRequestType] = testEndSoftwareDownloadRequestTypeMeFrame
	messageTypeTestFuncs[EndSoftwareDownloadResponseType] = testEndSoftwareDownloadResponseTypeMeFrame
	messageTypeTestFuncs[ActivateSoftwareRequestType] = testActivateSoftwareRequestTypeMeFrame
	messageTypeTestFuncs[ActivateSoftwareResponseType] = testActivateSoftwareResponseTypeMeFrame
	messageTypeTestFuncs[CommitSoftwareRequestType] = testCommitSoftwareRequestTypeMeFrame
	messageTypeTestFuncs[CommitSoftwareResponseType] = testCommitSoftwareResponseTypeMeFrame
	messageTypeTestFuncs[SynchronizeTimeRequestType] = testSynchronizeTimeRequestTypeMeFrame
	messageTypeTestFuncs[SynchronizeTimeResponseType] = testSynchronizeTimeResponseTypeMeFrame
	messageTypeTestFuncs[RebootRequestType] = testRebootRequestTypeMeFrame
	messageTypeTestFuncs[RebootResponseType] = testRebootResponseTypeMeFrame
	messageTypeTestFuncs[GetNextRequestType] = testGetNextRequestTypeMeFrame
	messageTypeTestFuncs[GetNextResponseType] = testGetNextResponseTypeMeFrame
	messageTypeTestFuncs[GetCurrentDataRequestType] = testGetCurrentDataRequestTypeMeFrame
	messageTypeTestFuncs[GetCurrentDataResponseType] = testGetCurrentDataResponseTypeMeFrame
	messageTypeTestFuncs[SetTableRequestType] = testSetTableRequestTypeMeFrame
	messageTypeTestFuncs[SetTableResponseType] = testSetTableResponseTypeMeFrame
	messageTypeTestFuncs[AlarmNotificationType] = testAlarmNotificationTypeMeFrame
	messageTypeTestFuncs[AttributeValueChangeType] = testAttributeValueChangeTypeMeFrame
	messageTypeTestFuncs[TestResultType] = testTestResultTypeMeFrame

	// Supported Extended message set types here
	messageTypeTestFuncs[GetRequestType+ExtendedTypeDecodeOffset] = testGetRequestTypeMeFrame
	messageTypeTestFuncs[GetResponseType+ExtendedTypeDecodeOffset] = testGetResponseTypeMeFrame

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	messageTypeTestFuncs[DownloadSectionRequestType+ExtendedTypeDecodeOffset] = testDownloadSectionRequestTypeMeFrame
	// TODO: messageTypeTestFuncs[DownloadSectionRequestWithResponseType+ExtendedTypeDecodeOffset] = testDownloadSectionLastRequestTypeMeFrame
	messageTypeTestFuncs[DownloadSectionResponseType+ExtendedTypeDecodeOffset] = testDownloadSectionResponseTypeMeFrame

	messageTypeTestFuncs[AlarmNotificationType+ExtendedTypeDecodeOffset] = testAlarmNotificationTypeMeFrame
	messageTypeTestFuncs[AttributeValueChangeType+ExtendedTypeDecodeOffset] = testAttributeValueChangeTypeMeFrame
	messageTypeTestFuncs[TestResultType+ExtendedTypeDecodeOffset] = testTestResultTypeMeFrame
}

func getMEsThatSupportAMessageType(messageType MessageType) []*me.ManagedEntity {
	msgType := me.MsgType(byte(messageType) & me.MsgTypeMask)

	entities := make([]*me.ManagedEntity, 0)
	for _, classID := range me.GetSupportedClassIDs() {
		if managedEntity, err := me.LoadManagedEntityDefinition(classID); err.StatusCode() == me.Success {
			supportedTypes := managedEntity.GetManagedEntityDefinition().GetMessageTypes()
			if supportedTypes.Contains(msgType) {
				entities = append(entities, managedEntity)
			}
		}
	}
	return entities
}

func TestFrameFormatNotYetSupported(t *testing.T) {
	// We do not yet support a few message types for the extended frame formats.
	// As we do, add appropriate tests and change this to one that is not supported
	// Until all are supported

	params := me.ParamData{
		Attributes: me.AttributeValueMap{"MibDataSync": 0},
	}
	managedEntity, omciErr := me.NewOnuData(params)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), me.Success)

	buffer, err := meframe.GenFrame(managedEntity, SetRequestType, meframe.FrameFormat(ExtendedIdent), meframe.TransactionID(1))
	assert.Nil(t, buffer)
	assert.NotNil(t, err)
}

// TODO: Add more specific get next response tests as we have had issues

func TestGetNextResponseOneFrameOnly(t *testing.T) {
	// OMCI ME GetRequest for MsgTypes often needs only a single frame and
	// it is a table of one octet values.  Make sure we decode it correctly

	response1 := []uint8{
		0, 250, 58, 10, 1, 31, 0, 0, 0, 64, 0,
		4, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 40,
	}
	// getNextSize is the size returned by the original Get request. Normally you would
	// do many OMCI requests and append all the results (while decreasing size), but
	// this is all in on packet.
	//
	// Do the buffer loop anyway
	getNextSize := 23
	remaining := getNextSize

	dataBuffer := make([]byte, 0)
	packets := []gopacket.Packet{
		gopacket.NewPacket(response1, LayerTypeOMCI, gopacket.NoCopy),
	}
	for _, packet := range packets {
		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		omciObj, omciOk := omciLayer.(*OMCI)
		assert.True(t, omciOk)
		assert.NotNil(t, omciObj)
		assert.Equal(t, uint16(250), omciObj.TransactionID)
		assert.Equal(t, GetNextResponseType, omciObj.MessageType)
		assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)
		assert.Equal(t, uint32(0), omciObj.MIC)
		assert.Equal(t, uint16(40), omciObj.Length)

		msgLayer := packet.Layer(LayerTypeGetNextResponse)
		msgObj, msgOk := msgLayer.(*GetNextResponse)
		assert.True(t, msgOk)
		assert.NotNil(t, msgObj)
		assert.Equal(t, me.Success, msgObj.Result)
		assert.Equal(t, uint16(0x4000), msgObj.AttributeMask)
		assert.Equal(t, 2, len(msgObj.Attributes))

		for attrName, value := range msgObj.Attributes {
			// Skip Entity ID attribute always stored in attribute list
			if attrName == "ManagedEntityId" {
				assert.Equal(t, uint16(0), value.(uint16))
				continue
			}
			assert.Equal(t, "MessageTypeTable", attrName)
			tmpBuffer, ok := value.([]byte)
			assert.True(t, ok)

			validOctets := len(tmpBuffer)
			assert.NotZero(t, validOctets)
			if validOctets > remaining {
				validOctets = remaining
			}
			remaining -= validOctets
			dataBuffer = append(dataBuffer, tmpBuffer[:validOctets]...)

			assert.True(t, remaining >= 0)
			if remaining == 0 {
				break
			}
		}
	}
	bufSize := len(dataBuffer)
	assert.Equal(t, getNextSize, bufSize)
}

func aTestFailingGetNextResponseTypeMeFrame(t *testing.T) {
	//params := me.ParamData{
	//	EntityID:   0,
	//	Attributes: me.AttributeValueMap{
	//		"Rmep5DatabaseTable": []uint8{
	//			0,1,2,3,4,5,6,7,8,9,
	//			10,11,12,13,14,15,16,17,18,19,
	//			20,21,22,23,24,25,26,27,28,29,
	//			30,
	//		},
	//	},
	//}
	//meInstance, err := me.NewDot1AgMepCcmDatabase(params)
	//bitmask := uint16(2048)
	//assert.NotNil(t, meInstance)
	//assert.Nil(t, err)
	//
	//tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	//
	//frame, omciErr := meframe.GenFrame(meInstance, GetNextResponseType, meframe.TransactionID(tid), meframe.Result(me.Success),
	//	AttributeMask(bitmask))
	//assert.NotNil(t, frame)
	//assert.NotZero(t, len(frame))
	//assert.Nil(t, omciErr)
	//
	/////////////////////////////////////////////////////////////////////
	//// Now decode and compare
	//cid := meInstance.GetClassID()
	//assert.NotEqual(t, cid, 0)
	//packet := gopacket.NewPacket(frame,  LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer( LayerTypeOMCI)
	//assert.NotNil(t, omciLayer)
	//
	//omciObj, omciOk := omciLayer.(* OMCI)
	//assert.NotNil(t, omciObj)
	//assert.True(t, omciOk)
	//assert.Equal(t, tid, omciObj.TransactionID)
	//assert.Equal(t, GetNextResponseType, omciObj.MessageType)
	//assert.Equal(t, BaselineIdent, omciObj.DeviceIdentifier)
	//
	//msgLayer := packet.Layer(LayerTypeGetNextResponse)
	//assert.NotNil(t, msgLayer)
	//
	//msgObj, msgOk := msgLayer.(*GetNextResponse)
	//assert.NotNil(t, msgObj)
	//assert.True(t, msgOk)
	//
	//assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	//assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	//assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)

}

func TestAllMessageTypes(t *testing.T) {
	// Loop over all message types
	for _, messageType := range allMessageTypes {
		//typeTested := false
		if testRoutine, ok := messageTypeTestFuncs[messageType]; ok {
			// Loop over all Managed Entities that support that type
			for _, managedEntity := range getMEsThatSupportAMessageType(messageType) {
				// Call the test routine
				testRoutine(t, managedEntity, BaselineIdent)
				//typeTested = true
			}
		}
		// Verify at least one test ran for this message type
		// TODO: Enable once all tests are working -> assert.True(t, typeTested)
	}
	// Now for the extended message set message types we support
	for _, messageType := range allExtendedMessageTypes {
		trueMessageType := messageType - ExtendedTypeDecodeOffset

		if testRoutine, ok := messageTypeTestFuncs[messageType]; ok {
			// Loop over all Managed Entities that support that type
			for _, managedEntity := range getMEsThatSupportAMessageType(trueMessageType) {
				// Call the test routine
				testRoutine(t, managedEntity, ExtendedIdent)
				//typeTested = true
			}
		}
		// Verify at least one test ran for this message type
		// TODO: Enable once all tests are working -> assert.True(t, typeTested)
	}
}

//func TestAllThatSupportAlarms(t *testing.T) {  TODO: Future
//	// Loop over all Managed Entities and test those with Attributes that support
//
//	for _, managedEntity := range getMEsThatSupportAMessageType(messageType) {
//		// Call the test routine
//		testRoutine(t, managedEntity)
//		//typeTested = true
//	}
//}

func getAttributeNameSet(attributes me.AttributeValueMap) mapset.Set {
	// TODO: For Classes with attribute masks that can set/get/... more than just
	//       a single attribute, test a set/get of just a single attribute to verify
	//       all encoding/decoding methods are working as expected.
	names := mapset.NewSet()
	for name := range attributes {
		names.Add(name)
	}
	return names
}

func pickAValue(attrDef me.AttributeDefinition) interface{} {
	constraint := attrDef.Constraint
	defaultVal := attrDef.DefValue
	size := attrDef.GetSize()
	_, isOctetString := defaultVal.([]byte)

	if attrDef.IsTableAttribute() || isOctetString {
		// Table attributes treated as a string of octets.  If size is zero, it is
		// most likely an attribute with variable size. Pick a random size that will
		// fit into a simple frame (1-33 octets)
		if size == 0 {
			size = rand.Intn(32) + 1
		}
		value := make([]byte, size)
		for octet := 0; octet < size; octet++ {
			value[octet] = byte(octet & 0xff)
		}
		return value
	}
	switch size {
	case 1:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint8); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint8)

	case 2:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint16); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint16)

	case 4:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint32); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint32)

	case 8:
		// Try the default + 1 as a value. Since some defaults are zero
		// and we want example frames without zeros in them.
		if value, ok := defaultVal.(uint64); ok {
			if constraint == nil {
				return value + 1
			}
			if err := constraint(value + 1); err == nil {
				return value + 1
			}
		}
		return defaultVal.(uint64)

	default:
		size := attrDef.GetSize()
		value := make([]uint8, size)
		for index := 0; index < size; index++ {
			value[index] = uint8(index & 0xFF)
		}
		return value
	}
}
