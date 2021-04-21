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
package omci_test

import (
	mapset "github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go"
	me "github.com/opencord/omci-lib-go/generated"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var messageTypeTestFuncs map[MessageType]func(*testing.T, *me.ManagedEntity, DeviceIdent)

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

	buffer, err := GenFrame(managedEntity, SetRequestType, FrameFormat(ExtendedIdent), TransactionID(1))
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
	//frame, omciErr := GenFrame(meInstance, GetNextResponseType, TransactionID(tid), Result(me.Success),
	//	AttributeMask(bitmask))
	//assert.NotNil(t, frame)
	//assert.NotZero(t, len(frame))
	//assert.Nil(t, omciErr)
	//
	/////////////////////////////////////////////////////////////////////
	//// Now decode and compare
	//cid := meInstance.GetClassID()
	//assert.NotEqual(t, cid, 0)
	//packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, omciLayer)
	//
	//omciObj, omciOk := omciLayer.(*OMCI)
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
	for name, _ := range attributes {
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

func testCreateRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	for _, attrDef := range managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.SetByCreate) {
			params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
		}
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	frame, omciErr := GenFrame(meInstance, CreateRequestType, TransactionID(tid), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, CreateRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*CreateRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeValueMap(), msgObj.Attributes)
}

func testCreateResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var mask uint16
	for _, attrDef := range managedEntity.GetAttributeDefinitions() {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.SetByCreate) {
			// Random 20% chance this parameter was bad
			if rand.Int31n(5) == 0 {
				mask |= attrDef.Mask
			}
		}
	}
	frame, omciErr := GenFrame(meInstance, CreateResponseType,
		TransactionID(tid), Result(result), AttributeExecutionMask(mask), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, CreateResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*CreateResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)

	if result == me.ParameterError {
		assert.Equal(t, mask, msgObj.AttributeExecutionMask)
	} else {
		assert.Zero(t, msgObj.AttributeExecutionMask)
	}
}

func testDeleteRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, DeleteRequestType, TransactionID(tid), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testDeleteResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	frame, omciErr := GenFrame(meInstance, DeleteResponseType, TransactionID(tid), Result(result),
		FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
}

func testSetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	attrDefs := managedEntity.GetAttributeDefinitions()
	tableAttrFound := false
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.IsTableAttribute() {
			tableAttrFound = true
			continue // TODO: Skip table attributes for now
		} else if attrDef.GetAccess().Contains(me.Write) {
			params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
		}
	}
	if tableAttrFound && len(params.Attributes) == 0 {
		// The only set attribute may have been a table and we do not have
		// a test for that right now.
		return
	}
	assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, SetRequestType, TransactionID(tid),
		AttributeMask(bitmask), FrameFormat(messageSet))
	// some frames cannot fit all the attributes
	if omciErr != nil {
		if _, ok := omciErr.(*me.MessageTruncatedError); ok {
			return
		}
	}
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SetRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeValueMap(), msgObj.Attributes)
}

func testSetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(10))  // [0, 9] Not all types will be tested

	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var unsupportedMask uint16
	var failedMask uint16
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.Write) {
			// Random 10% chance this parameter unsupported and
			// 10% it failed
			switch rand.Int31n(5) {
			case 0:
				unsupportedMask |= attrDef.Mask
			case 1:
				failedMask |= attrDef.Mask
			}
		}
	}
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	frame, omciErr := GenFrame(meInstance, SetResponseType,
		TransactionID(tid), Result(result),
		AttributeMask(bitmask), FrameFormat(messageSet),
		AttributeExecutionMask(failedMask),
		UnsupportedAttributeMask(unsupportedMask))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SetResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)

	if result == me.AttributeFailure {
		assert.Equal(t, failedMask, msgObj.FailedAttributeMask)
		assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)
	} else {
		assert.Zero(t, msgObj.FailedAttributeMask)
		assert.Zero(t, msgObj.UnsupportedAttributeMask)
	}
}

func testGetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.GetAccess().Contains(me.Read) {
			// Allow 'nil' as parameter value for GetRequests since we only need names
			params.Attributes[attrDef.GetName()] = nil
		}
	}
	assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, GetRequestType, TransactionID(tid),
		AttributeMask(bitmask), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)
}

func testGetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap),
	}
	// Add loop to test all valid result codes for this message type
	validResultCodes := []me.Results{
		me.Success,
		me.ProcessingError,
		me.NotSupported,
		me.ParameterError,
		me.UnknownEntity,
		me.UnknownInstance,
		me.DeviceBusy,
		me.AttributeFailure,
	}
	for _, result := range validResultCodes {
		tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

		// If success Results selected, set FailIfTruncated 50% of time to test
		// overflow detection and failures periodically.  This is primarily for
		// baseline message set for those MEs that may have lots of attribute space
		// needed.  If extended message set, always fail if truncated since we should
		// be able to stuff as much as we want (at least for now in these unit tests)
		failIfTruncated := false
		if result == me.Success && (rand.Int31n(2) == 1 || messageSet == ExtendedIdent) {
			failIfTruncated = true
		}
		// Always pass a failure mask, but should only get encoded if result == ParameterError
		var unsupportedMask uint16
		var failedMask uint16
		attrDefs := managedEntity.GetAttributeDefinitions()
		for _, attrDef := range attrDefs {
			if attrDef.Index == 0 {
				continue // Skip entity ID, already specified

			} else if attrDef.GetAccess().Contains(me.Read) {
				// Random 5% chance this parameter unsupported and
				// 5% it failed
				switch rand.Int31n(20) {
				default:
					// TODO: Table attributes not yet supported.  For Table Attributes, figure out a
					//       good way to unit test this and see if that can be extended to a more
					//       general operation that provides the 'get-next' frames to the caller who
					//		 wishes to serialize a table attribute.
					if !attrDef.IsTableAttribute() {
						params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
					}
				case 0:
					unsupportedMask |= attrDef.Mask
				case 1:
					failedMask |= attrDef.Mask
				}
			}
		}
		bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
		assert.Nil(t, attrErr)

		// Create the managed instance
		meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)

		frame, omciErr := GenFrame(meInstance, GetResponseType,
			TransactionID(tid), Result(result),
			AttributeMask(bitmask), FrameFormat(messageSet),
			AttributeExecutionMask(failedMask),
			UnsupportedAttributeMask(unsupportedMask),
			FailIfTruncated(failIfTruncated))

		// TODO: Need to test if err is MessageTruncatedError. Sometimes reported as
		//       a proessing error
		if omciErr != nil {
			if _, ok := omciErr.(*me.MessageTruncatedError); ok {
				return
			}
		}
		assert.NotNil(t, frame)
		assert.NotZero(t, len(frame))
		assert.NotNil(t, err)
		assert.Equal(t, err.StatusCode(), me.Success)

		///////////////////////////////////////////////////////////////////
		// Now decode and compare
		packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		omciObj, omciOk := omciLayer.(*OMCI)
		assert.NotNil(t, omciObj)
		assert.True(t, omciOk)
		assert.Equal(t, tid, omciObj.TransactionID)
		assert.Equal(t, GetResponseType, omciObj.MessageType)
		assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

		msgLayer := packet.Layer(LayerTypeGetResponse)
		// If requested Result was Success and FailIfTruncated is true, then we may
		// fail (get nil layer) if too many attributes to fit in a frame
		if result == me.Success && msgLayer == nil {
			return // was expected
		}
		assert.NotNil(t, msgLayer)

		msgObj, msgOk := msgLayer.(*GetResponse)
		assert.NotNil(t, msgObj)
		assert.True(t, msgOk)

		assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
		assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)

		switch msgObj.Result {
		default:
			assert.Equal(t, result, msgObj.Result)
			assert.Zero(t, msgObj.FailedAttributeMask)
			assert.Zero(t, msgObj.UnsupportedAttributeMask)

		case me.Success:
			assert.Equal(t, result, msgObj.Result)
			assert.Zero(t, msgObj.FailedAttributeMask)
			assert.Zero(t, msgObj.UnsupportedAttributeMask)
			assert.Equal(t, meInstance.GetAttributeValueMap(), msgObj.Attributes)

		case me.AttributeFailure:
			// Should have been Success or AttributeFailure to start with
			assert.True(t, result == me.Success || result == me.AttributeFailure)
			if result == me.AttributeFailure {
				assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)
			}
			// Returned may have more bits set in failed mask and less attributes
			// since failIfTruncated is false and we may add more fail attributes
			// since they do not fit. May also set only lower value (lower bits)
			// if it turns out that the upper bits are already pre-assigned to the
			// failure bits.
			//
			// Make sure any successful attributes were requested
			meMap := meInstance.GetAttributeValueMap()
			for name := range msgObj.Attributes {
				getValue, ok := meMap[name]
				assert.True(t, ok)
				assert.NotNil(t, getValue)
			}
		}
	}
}

func testGetAllAlarmsRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	mode := uint8(rand.Int31n(2))          // [0, 1]

	frame, omciErr := GenFrame(meInstance, GetAllAlarmsRequestType, TransactionID(tid),
		RetrievalMode(mode), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, mode, msgObj.AlarmRetrievalMode)
}

func testGetAllAlarmsResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1)  // [1, 0xFFFF]
	numOfCommands := uint16(rand.Int31n(5)) // [0, 5)

	frame, omciErr := GenFrame(meInstance, GetAllAlarmsResponseType, TransactionID(tid),
		SequenceNumberCountOrSize(numOfCommands), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, numOfCommands, msgObj.NumberOfCommands)
}

func testGetAllAlarmsNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]
	sequenceNumber := uint16(rand.Int31n(5)) // [0, 5)

	frame, omciErr := GenFrame(meInstance, GetAllAlarmsNextRequestType, TransactionID(tid),
		SequenceNumberCountOrSize(sequenceNumber), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsNextRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, sequenceNumber, msgObj.CommandSequenceNumber)
}

func testGetAllAlarmsNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	alarmInfo := AlarmOptions{
		AlarmClassID:  123, // TODO: Real class here?
		AlarmInstance: 456,
		AlarmBitmap:   make([]byte, 28),
	}
	// TODO: Allow a 1 to 28 octet array to be used and zero fill any remainder...
	for octet := 0; octet < 28; octet++ {
		alarmInfo.AlarmBitmap[octet] = uint8(rand.Intn(256))
	}
	frame, omciErr := GenFrame(meInstance, GetAllAlarmsNextResponseType, TransactionID(tid),
		Alarm(alarmInfo), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetAllAlarmsNextResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetAllAlarmsNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, alarmInfo.AlarmClassID, msgObj.AlarmEntityClass)
	assert.Equal(t, alarmInfo.AlarmInstance, msgObj.AlarmEntityInstance)
	for octet := 0; octet < len(alarmInfo.AlarmBitmap); octet++ {
		assert.Equal(t, alarmInfo.AlarmBitmap[octet], msgObj.AlarmBitMap[octet])
	}
}

func testMibUploadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, MibUploadRequestType, TransactionID(tid), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1)  // [1, 0xFFFF]
	numOfCommands := uint16(rand.Int31n(5)) // [0, 5)

	frame, omciErr := GenFrame(meInstance, MibUploadResponseType, TransactionID(tid),
		SequenceNumberCountOrSize(numOfCommands), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, numOfCommands, msgObj.NumberOfCommands)
}

func testMibUploadNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	seqNumber := uint16(rand.Int31n(0xFFFF)) // [0, 0xFFFE]
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]

	var frame []byte
	frame, omciErr := GenFrame(meInstance, MibUploadNextRequestType, TransactionID(tid),
		SequenceNumberCountOrSize(seqNumber), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadNextRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, seqNumber, msgObj.CommandSequenceNumber)
	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	// TODO: Since only baseline messages supported, send only one ME
	uploadMe := meInstance

	frame, omciErr := GenFrame(meInstance, MibUploadNextResponseType, TransactionID(tid),
		Payload(uploadMe), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, uploadMe.GetClassID(), msgObj.ReportedME.GetClassID())
	assert.Equal(t, uploadMe.GetEntityID(), msgObj.ReportedME.GetEntityID())
}

func testMibResetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, MibResetRequestType, TransactionID(tid), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibResetRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibResetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibResetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testMibResetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	frame, omciErr := GenFrame(meInstance, MibResetResponseType, TransactionID(tid),
		Result(result), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, MibResetResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibResetResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibResetResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
}

func testTestRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testTestResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testStartSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	instance := uint16(0) // ONU-G
	image := uint16(1)
	params := me.ParamData{
		EntityID: uint16((instance << 8) + image),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	options := SoftwareOptions{
		WindowSize:   uint8(rand.Int31n(255)),                  // [0, 255]
		ImageSize:    uint32(rand.Int31n(0x100000) + 0x100000), // [1 Meg, 2M-1]
		CircuitPacks: []uint16{0},                              // [1 Meg, 2M-1]
	}
	frame, omciErr := GenFrame(meInstance, StartSoftwareDownloadRequestType,
		TransactionID(tid), Software(options), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, StartSoftwareDownloadRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*StartSoftwareDownloadRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, options.ImageSize, msgObj.ImageSize)
	assert.Equal(t, len(options.CircuitPacks), int(msgObj.NumberOfCircuitPacks))

	for index, circuitPack := range options.CircuitPacks {
		assert.Equal(t, circuitPack, msgObj.CircuitPacks[index])
	}
}

func testStartSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testDownloadSectionRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testDownloadSectionResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testEndSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testEndSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testActivateSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testActivateSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testCommitSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testCommitSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testSynchronizeTimeRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	tm := time.Now().UTC()
	tmUnix := tm.Unix()

	frame, omciErr := GenFrame(meInstance, SynchronizeTimeRequestType, TransactionID(tid),
		Payload(tmUnix), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SynchronizeTimeRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SynchronizeTimeRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)

	assert.Equal(t, uint16(tm.Year()), msgObj.Year)
	assert.Equal(t, uint8(tm.Month()), msgObj.Month)
	assert.Equal(t, uint8(tm.Day()), msgObj.Day)
	assert.Equal(t, uint8(tm.Hour()), msgObj.Hour)
	assert.Equal(t, uint8(tm.Minute()), msgObj.Minute)
	assert.Equal(t, uint8(tm.Second()), msgObj.Second)
}

func testSynchronizeTimeResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested
	successResult := uint8(rand.Int31n(2)) // [0, 1]

	var frame []byte
	frame, omciErr := GenFrame(meInstance, SynchronizeTimeResponseType, TransactionID(tid),
		Result(result), SuccessResult(successResult), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, SynchronizeTimeResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SynchronizeTimeResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
	if result == me.Success {
		assert.Equal(t, successResult, msgObj.SuccessResults)
	} else {
		assert.Zero(t, msgObj.SuccessResults)
	}
}

func testRebootRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	condition := uint8(rand.Int31n(3))     // [0, 3]

	frame, omciErr := GenFrame(meInstance, RebootRequestType, TransactionID(tid),
		RebootCondition(condition), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, RebootRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeRebootRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*RebootRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, condition, msgObj.RebootCondition)
}

func testRebootResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	frame, omciErr := GenFrame(meInstance, RebootResponseType, TransactionID(tid),
		Result(result), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, RebootResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeRebootResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*RebootResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
}

func testGetNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	// TODO: Loop over all table attributes for this class ID
	// Find first attribute that is a table definition
	// TODO: Test request of more than 1 attribute. G.988 specifies that a status
	//       code of (3) should be returned.  Raise error during encode instead of
	//       waiting for compliant ONU.  May want to have an 'ignore' to allow it.
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.IsTableAttribute() {
			// TODO: Tables without a size are not supported. At least needs to be one octet
			if attrDef.Size == 0 {
				continue
			}
			// Allow 'nil' as parameter value for GetNextRequests since we only need names
			params.Attributes[attrDef.GetName()] = nil
			break
		}
	}
	if len(params.Attributes) == 0 {
		return
	}
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	seqNumber := uint16(rand.Int31n(0xFFFF)) // [0, 0xFFFE]
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, GetNextRequestType, TransactionID(tid),
		SequenceNumberCountOrSize(seqNumber), AttributeMask(bitmask), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetNextRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)
	assert.Equal(t, seqNumber, msgObj.SequenceNumber)
}

func testGetNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	// TODO: Loop over result types (here and other responses with results)
	result := me.Success // me.Results(rand.Int31n(7))  // [0, 6]
	bitmask := uint16(0)
	attrDefs := managedEntity.GetAttributeDefinitions()

	// TODO: Loop over all table attributes for this class ID
	if result == me.Success {
		// Find first attribute that is a table definition
		// TODO: Test request of more than 1 attribute. G.988 specifies that a status
		//       code of (3) should be returned.  Raise error during encode instead of
		//       waiting for compliant ONU.  May want to have an 'ignore' to allow it.
		for _, attrDef := range attrDefs {
			if attrDef.Index == 0 {
				continue // Skip entity ID, already specified
			} else if attrDef.IsTableAttribute() {
				if len(params.Attributes) == 0 {
					// Need a parameter that is a table attribute
					return
				}
				params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
				break
			}
		}
		if len(params.Attributes) == 0 {
			return
		}
		assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
		var attrErr error
		bitmask, attrErr = me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
		assert.Nil(t, attrErr)
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := GenFrame(meInstance, GetNextResponseType, TransactionID(tid), Result(result),
		AttributeMask(bitmask), FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	cid := meInstance.GetClassID()
	assert.NotEqual(t, cid, 0)
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetNextResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)

	switch msgObj.Result {
	default:
		assert.Equal(t, result, msgObj.Result)

	case me.Success:
		assert.Equal(t, result, msgObj.Result)
		// The attributes should be equal but for variable length table attribute (size = 0 in structure)
		// we will have the frame padding returned as well.
		for attrName, value := range meInstance.GetAttributeValueMap() {
			attr, err := me.GetAttributeDefinitionByName(attrDefs, attrName)
			assert.Nil(t, err)
			assert.NotNil(t, attr)
			assert.Equal(t, attrName, attr.GetName())
			if attr.IsTableAttribute() {
				instValue := value.([]byte)
				msgValue := msgObj.Attributes[attrName].([]byte)
				assert.True(t, len(instValue) <= len(msgValue))
				assert.Equal(t, msgValue[:len(instValue)], instValue)
			} else {
				assert.Equal(t, value, msgObj.Attributes[attrName])
			}
		}
	}
}

func testGetCurrentDataRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testGetCurrentDataResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testSetTableRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testSetTableResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testAlarmNotificationTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testAttributeValueChangeTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testTestResultTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}
