/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package omci_test

import (
	"encoding/base64"
	"fmt"
	. "github.com/cboling/omci"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var allMsgTypes = [...]me.MsgType{
	me.Create,
	me.Delete,
	me.Set,
	me.Get,
	me.GetAllAlarms,
	me.GetAllAlarmsNext,
	me.MibUpload,
	me.MibUploadNext,
	me.MibReset,
	me.AlarmNotification,
	me.AttributeValueChange,
	me.Test,
	me.StartSoftwareDownload,
	me.DownloadSection,
	me.EndSoftwareDownload,
	me.ActivateSoftware,
	me.CommitSoftware,
	me.SynchronizeTime,
	me.Reboot,
	me.GetNext,
	me.TestResult,
	me.GetCurrentData,
	me.SetTable}

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

var allResults = [...]me.Results{
	me.Success,
	me.ProcessingError,
	me.NotSupported,
	me.ParameterError,
	me.UnknownEntity,
	me.UnknownInstance,
	me.DeviceBusy,
	me.InstanceExists}

// TestMsgTypeStrings tests that base message types can be printed
func TestMsgTypeStrings(t *testing.T) {
	for _, msg := range allMsgTypes {
		strMsg := msg.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
	unknown := me.MsgType(0xFF)
	strMsg := unknown.String()
	assert.NotEqual(t, len(strMsg), 0)
}

// TestMessageTypeStrings tests that request/response/notification
// message types can be printed
func TestMessageTypeStrings(t *testing.T) {
	for _, msg := range allMessageTypes {
		strMsg := msg.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
	unknown := MessageType(0xFF)
	strMsg := unknown.String()
	assert.NotEqual(t, len(strMsg), 0)
}

func TestResultsStrings(t *testing.T) {
	for _, code := range allResults {
		strMsg := code.String()
		assert.NotEqual(t, len(strMsg), 0)
	}
}

// TestOmciDecode will test for proper error checking of things that
// are invalid at the OMCI decode layer
func TestOmciDecode(t *testing.T) {
	// TID = 0 on autonomous ONU notifications only.  Get packet back but ErrorLayer()
	// returns non-nil
	tidZeroOnNonNotification := "0000440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(tidZeroOnNonNotification)
	assert.NoError(t, err)
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Only Baseline and Extended Message types allowed
	invalidMessageType := "000C440F010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err = stringToPacket(invalidMessageType)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Bad baseline message length
	badBaselineMsgLength := "000C440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000029"

	data, err = stringToPacket(badBaselineMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Bad extended message length
	badExtendedMsgLength := "000C440B010C010000290400800003010000" +
		"00000000000000000000000000000000" +
		"00000000000000000000"

	data, err = stringToPacket(badExtendedMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())

	// Huge extended message length
	hugeExtendedMsgLength := "000C440B010C010007BD0400800003010000" +
		"00000000000000000000000000000000" +
		"00000000000000000000"

	data, err = stringToPacket(hugeExtendedMsgLength)
	assert.NoError(t, err)
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.NotNil(t, packet.ErrorLayer())
}

// TestOmciSerialization will test for proper error checking of things that
// are invalid at the OMCI layer
func TestOmciSerialization(t *testing.T) {
	goodMessage := "000C440A010C0100040080000301000000000000000000000000000000000000000000000000000000000028"

	omciLayerDefaults := &OMCI{
		TransactionID: 0x0c,
		MessageType:   CreateRequestType,
		// DeviceIdentifier: BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,				// Optional, defaults to 40 octets
	}
	omciLayerFixed := &OMCI{
		TransactionID:    0x0c,
		MessageType:      CreateRequestType,
		DeviceIdentifier: BaselineIdent,
		Length:           0x28,
	}
	request := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GemPortNetworkCtpClassID,
			EntityInstance: uint16(0x100),
		},
		Attributes: me.AttributeValueMap{
			"PortId":                              0x400,
			"TContPointer":                        0x8000,
			"Direction":                           3,
			"TrafficManagementPointerForUpstream": 0x100,
			"TrafficDescriptorProfilePointerForUpstream":   0,
			"PriorityQueuePointerForDownStream":            0,
			"TrafficDescriptorProfilePointerForDownstream": 0,
			"EncryptionKeyRing":                            0,
		},
	}
	// Test serialization back to former string (using defaults in the message parts)
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayerDefaults, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)

	// Test serialization back to former string (using explicit values in the message parts)
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciLayerFixed, request)
	assert.NoError(t, err)

	outgoingPacket = buffer.Bytes()
	reconstituted = packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCreateRequestDecode(t *testing.T) {
	goodMessage := "000C440A010C01000400800003010000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0xc))
	assert.Equal(t, omciMsg.MessageType, CreateRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.Equal(t, request.EntityClass, me.GemPortNetworkCtpClassID)
	assert.Equal(t, request.EntityInstance, uint16(0x100))

	attributes := request.Attributes
	assert.NotNil(t, attributes)

	// As this is a create request, gather up all set-by-create attributes
	// make sure we got them all, and nothing else
	meDefinition, omciErr := me.LoadManagedEntityDefinition(request.EntityClass)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), me.Success)

	attrDefs := meDefinition.GetAttributeDefinitions()

	sbcMask := getSbcMask(meDefinition)
	for index := uint(1); index < uint(len(attrDefs)); index++ {
		attrName := attrDefs[index].GetName()

		if sbcMask&uint16(1<<(uint)(16-index)) != 0 {
			_, ok3 := attributes[attrName]
			assert.True(t, ok3)
		} else {
			_, ok3 := attributes[attrName]
			assert.False(t, ok3)
		}
		//fmt.Printf("Name: %v, Value: %v\n", attrName, attributes[attrName])
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, omciMsg, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCreateRequestSerialize(t *testing.T) {
	goodMessage := "000C440A010C0100040080000301000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0c,
		MessageType:   CreateRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CreateRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GemPortNetworkCtpClassID,
			EntityInstance: uint16(0x100),
		},
		Attributes: me.AttributeValueMap{
			"PortId":                              0x400,
			"TContPointer":                        0x8000,
			"Direction":                           3,
			"TrafficManagementPointerForUpstream": 0x100,
			"TrafficDescriptorProfilePointerForUpstream":   0,
			"PriorityQueuePointerForDownStream":            0,
			"TrafficDescriptorProfilePointerForDownstream": 0,
			"EncryptionKeyRing":                            0,
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCreateResponseDecode(t *testing.T) {
	goodMessage := "0157240a01100001000000000000000000000000000000000000000000000000000000000000000000000028a9ccbeb9"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0157))
	assert.Equal(t, omciMsg.MessageType, CreateResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeCreateResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CreateResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCreateResponseSerialize(t *testing.T) {
	goodMessage := "0157240a01100001000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0157,
		MessageType:   CreateResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CreateResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: uint16(1),
		},
		Result:                 me.Success,
		AttributeExecutionMask: uint16(0),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDeleteRequestDecode(t *testing.T) {
	goodMessage := "0211460a00ab0202000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0211))
	assert.Equal(t, omciMsg.MessageType, DeleteRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeDeleteRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DeleteRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDeleteRequestSerialize(t *testing.T) {
	goodMessage := "0211460a00ab0202000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0211,
		MessageType:   DeleteRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &DeleteRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x202),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDeleteResponseDecode(t *testing.T) {
	goodMessage := "0211260a00ab0202000000000000000000000000000000000000000000000000000000000000000000000028013437fb"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0211))
	assert.Equal(t, omciMsg.MessageType, DeleteResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeDeleteResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*DeleteResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDeleteResponseSerialize(t *testing.T) {
	goodMessage := "0211260a00ab0202000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0211,
		MessageType:   DeleteResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &DeleteResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x202),
		},
		Result: me.Success,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestSetRequestDecode(t *testing.T) {
	goodMessage := "0107480a01000000020000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0107))
	assert.Equal(t, omciMsg.MessageType, SetRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetRequestSerialize(t *testing.T) {
	goodMessage := "0107480a01000000020000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0107,
		MessageType:   SetRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x200),
		Attributes:    me.AttributeValueMap{"AdministrativeState": byte(0)},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestSetResponseDecode(t *testing.T) {
	goodMessage := "0107280a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0107))
	assert.Equal(t, omciMsg.MessageType, SetResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetResponseSerialize(t *testing.T) {
	goodMessage := "0107280a01000000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0107,
		MessageType:   SetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result: me.Success,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)

}

func TestSetResponseTableFailedAttributesDecode(t *testing.T) {
	// This is a SET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestSetResponseTableFailedAttributesSerialize(t *testing.T) {
	// This is a SET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestGetRequestDecode(t *testing.T) {
	goodMessage := "035e490a01070000004400000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetRequestSerialize(t *testing.T) {
	goodMessage := "035e490a01070000004400000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x0044),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetResponseDecode(t *testing.T) {
	goodMessage := "035e290a01070000000044dbcb05f10000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x035e))
	assert.Equal(t, omciMsg.MessageType, GetResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.Result, me.Success)
	assert.Equal(t, response.AttributeMask, uint16(0x0044))
	assert.Equal(t, response.Attributes["TransmitOpticalLevel"], uint16(0x05f1))
	assert.Equal(t, response.Attributes["OpticalSignalLevel"], uint16(0xdbcb))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetResponseSerialize(t *testing.T) {
	goodMessage := "035e290a01070000000044dbcb05f10000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0x0044),
		Attributes: me.AttributeValueMap{
			"TransmitOpticalLevel": uint16(0x05f1),
			"OpticalSignalLevel":   uint16(0xdbcb)},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

///////////////////////////////////////////////////////////////////////
// Packet definitions for attributes of various types/sizes
func toOctets(str string) []byte {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("Invalid Base-64 string: '%v'", str))
	}
	return data
}

func TestGetResponseSerializeTruncationFailure(t *testing.T) {
	// Too much data and 'fix-length' is not specified.  This response has 26
	// octets in the requested data, but only 25 octets available

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0xE000),
		Attributes: me.AttributeValueMap{
			"VendorId":     toOctets("ICAgIA=="),
			"Version":      toOctets("MAAAAAAAAAAAAAAAAAA="),
			"SerialNumber": toOctets("AAAAAAAAAAA="),
		},
	}
	// Test serialization and verify truncation failure
	var options gopacket.SerializeOptions
	options.FixLengths = false

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
	assert.IsType(t, &me.MessageTruncatedError{}, err)
}

func TestGetResponseSerializeTruncationButOkay(t *testing.T) {
	// Too much data and 'fix-length' is specified so it packs as much as
	// possible and adjusts the failure masks

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	response := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0xE000),
		Attributes: me.AttributeValueMap{
			"VendorId":     toOctets("ICAgIA=="),
			"Version":      toOctets("MAAAAAAAAAAAAAAAAAA="),
			"SerialNumber": toOctets("AAAAAAAAAAA="),
		},
	}
	// Test serialization and verify truncation failure
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, response)
	assert.NoError(t, err)

	// Now deserialize it and see if we have the proper result (Attribute Failure)
	// and a non-zero failed mask
	responsePacket := buffer.Bytes()
	packet := gopacket.NewPacket(responsePacket, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer2 := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer2)

	omciMsg2, ok := omciLayer2.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciLayer.TransactionID, omciMsg2.TransactionID)
	assert.Equal(t, omciLayer.MessageType, GetResponseType)
	assert.Equal(t, omciLayer.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciLayer.Length, uint16(40))

	msgLayer2 := packet.Layer(LayerTypeGetResponse)
	assert.NotNil(t, msgLayer2)

	response2, ok2 := msgLayer2.(*GetResponse)
	assert.True(t, ok2)
	assert.Equal(t, me.AttributeFailure, response2.Result)
	assert.NotZero(t, response2.AttributeMask)
	assert.NotZero(t, response2.FailedAttributeMask)
	assert.Zero(t, response2.UnsupportedAttributeMask)
}

func TestGetResponseTableFailedAttributesDecode(t *testing.T) {
	// This is a GET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestGetResponseTableFailedAttributesSerialize(t *testing.T) {
	// This is a GET Response with failed and unsupported attributes
	// TODO:Implement
}

func TestGetResponseTableAttributeDecode(t *testing.T) {
	// This is a GET Response for a table attribute. It should return the attribute
	// size as a uint16.
	// TODO:Implement
}

func TestGetResponseTableAttributeSerialize(t *testing.T) {
	// This is a GET Response for a table attribute. It should return the attribute
	// size as a uint16.
	// TODO:Implement
}

func TestGetAllAlarmsRequestDecode(t *testing.T) {
	goodMessage := "04454b0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0445))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.AlarmRetrievalMode, byte(0))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsRequestSerialize(t *testing.T) {
	goodMessage := "04454b0a00020000010000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0445,
		MessageType:   GetAllAlarmsRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AlarmRetrievalMode: byte(1),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetAllAlarmsResponseDecode(t *testing.T) {
	goodMessage := "04452b0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0445))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.NumberOfCommands, uint16(3))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsResponseSerialize(t *testing.T) {
	goodMessage := "04452b0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0445,
		MessageType:   GetAllAlarmsResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		NumberOfCommands: uint16(3),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetAllAlarmsNextRequestDecode(t *testing.T) {
	goodMessage := "02344c0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0234))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsNextRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextRequestSerialize(t *testing.T) {
	goodMessage := "02344c0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0234,
		MessageType:   GetAllAlarmsNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetAllAlarmsNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		CommandSequenceNumber: uint16(0),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetAllAlarmsNextResponseDecode(t *testing.T) {
	goodMessage := "02342c0a00020000000b01028000000000000000000000000000000000000000000000000000000000000028f040fc87"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0234))
	assert.Equal(t, omciMsg.MessageType, GetAllAlarmsNextResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	var alarms [224 / 8]byte
	alarms[0] = 0x80
	assert.Equal(t, response.AlarmEntityClass, me.PhysicalPathTerminationPointEthernetUniClassID)
	assert.Equal(t, response.AlarmEntityInstance, uint16(0x102))
	assert.Equal(t, response.AlarmBitMap, alarms)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextResponseSerialize(t *testing.T) {
	goodMessage := "02342c0a00020000000b01028000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0234,
		MessageType:   GetAllAlarmsNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	request := &GetAllAlarmsNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AlarmEntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
		AlarmEntityInstance: uint16(0x102),
		AlarmBitMap:         alarms,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetAllAlarmsNextResponseBadCommandNumberDecode(t *testing.T) {
	// Test of a GetNext Response that results when an invalid command number
	// is requested. In the case where the ONU receives a get all alarms next
	// request message in which the command sequence number is out of range,
	// the ONU should respond with a message in which bytes 9 to 40 are all
	// set to 0. This corresponds to a response with entity class 0, entity
	// instance 0, and bit map all 0s.
	//TODO: Implement
}

func TestGetAllAlarmsNextResponseBadCommandNumberSerialize(t *testing.T) {
	// Test of a GetNext Response that results when an invalid command number
	// is requested.
	//TODO: Implement
}

func TestMibUploadRequestDecode(t *testing.T) {
	goodMessage := "03604d0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0360))
	assert.Equal(t, omciMsg.MessageType, MibUploadRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))
	msgLayer := packet.Layer(LayerTypeMibUploadRequest)

	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadRequestSerialize(t *testing.T) {
	goodMessage := "03604d0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0360,
		MessageType:   MibUploadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	request := &MibUploadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadResponse(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0360))
	assert.Equal(t, omciMsg.MessageType, MibUploadResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.NumberOfCommands, uint16(0x112))
}

func TestMibUploadResponseSerialize(t *testing.T) {
	goodMessage := "03602d0a00020000011200000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0360,
		MessageType:   MibUploadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	request := &MibUploadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		NumberOfCommands: uint16(0x112),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextRequestDecode(t *testing.T) {
	goodMessage := "02864e0a00020000003a00000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0286))
	assert.Equal(t, omciMsg.MessageType, MibUploadNextRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*MibUploadNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.CommandSequenceNumber, uint16(0x3a))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextRequestSerialize(t *testing.T) {
	goodMessage := "02864e0a00020000003a00000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0286,
		MessageType:   MibUploadNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibUploadNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		CommandSequenceNumber: uint16(0x3a),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseDecode(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0286))
	assert.Equal(t, omciMsg.MessageType, MibUploadNextResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.ReportedME.GetClassID(), me.PriorityQueueClassID)
	assert.Equal(t, response.ReportedME.GetEntityID(), uint16(0))

	attributes := me.AttributeValueMap{
		"QueueConfigurationOption":                            byte(0),
		"MaximumQueueSize":                                    uint16(0),
		"AllocatedQueueSize":                                  uint16(0),
		"DiscardBlockCounterResetInterval":                    uint16(0),
		"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0),
		"RelatedPort":                                         uint32(16842752),
		"TrafficSchedulerPointer":                             uint16(0),
		"Weight":                                              byte(1),
		"BackPressureOperation":                               uint16(0),
		"BackPressureTime":                                    uint32(0),
		"BackPressureOccurQueueThreshold":                     uint16(0),
		"BackPressureClearQueueThreshold":                     uint16(0),
	}
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, pktValue, value)
	}
	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibUploadNextResponseSerialize(t *testing.T) {
	goodMessage := "02862e0a0002000001150000fff0000000000000000000010100000000010000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0286,
		MessageType:   MibUploadNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	paramData := me.ParamData{
		EntityID: uint16(0),
		Attributes: me.AttributeValueMap{
			"QueueConfigurationOption":                            byte(0),
			"MaximumQueueSize":                                    uint16(0),
			"AllocatedQueueSize":                                  uint16(0),
			"DiscardBlockCounterResetInterval":                    uint16(0),
			"ThresholdValueForDiscardedBlocksDueToBufferOverflow": uint16(0),
			"RelatedPort":                                         uint32(16842752),
			"TrafficSchedulerPointer":                             uint16(0),
			"Weight":                                              byte(1),
			"BackPressureOperation":                               uint16(0),
			"BackPressureTime":                                    uint32(0),
			"BackPressureOccurQueueThreshold":                     uint16(0),
			"BackPressureClearQueueThreshold":                     uint16(0),
		},
	}
	reportedME, err := me.NewPriorityQueue(paramData)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	request := &MibUploadNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		ReportedME: *reportedME,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	omciErr := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, omciErr)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibUploadNextResponseBadCommandNumberDecode(t *testing.T) {
	// Test of a MIB Upload next Response that results when an invalid command number.
	// Note that if all attributes of a managed entity do not fit within one MIB
	// upload next response message, the attributes will be split over several
	// messages. The OLT can use the information in the attribute mask to determine
	// which attribute values are reported in which MIB upload next response message.
	//TODO: Implement
}

func TestMibUploadNextResponseBadCommandNumberSerialize(t *testing.T) {
	// Test of a MIB Upload next Response that results when an invalid command number
	// is requested.
	//TODO: Implement
}

// TODO: Create request/response tests for all of the following types
//Test,

func TestStartSoftwareDownloadRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000530a0007000113000f424001000100000000000000000000000000000000000000000000000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, StartSoftwareDownloadRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*StartSoftwareDownloadRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadRequestSerialize(t *testing.T) {
	//// TODO: Need to complete implementation & debug this
	//goodMessage := "0000530a0007000113000f424001000100000000000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   StartSoftwareDownloadRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &StartSoftwareDownloadRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestStartSoftwareDownloadResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, StartSoftwareDownloadResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*StartSoftwareDownloadResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   StartSoftwareDownloadResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &StartSoftwareDownloadResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000140a00070001083534363836393733323036393733323036313230373436353733373400000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, DownloadSectionRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*DownloadSectionRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestDownloadSectionRequestSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000140a00070001083534363836393733323036393733323036313230373436353733373400000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   DownloadSectionRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &DownloadSectionRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestDownloadSectionResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, DownloadSectionResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*DownloadSectionResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   DownloadSectionResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &DownloadSectionResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestEndSoftwareDownloadRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, EndSoftwareDownloadRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*EndSoftwareDownloadRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadRequestSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   EndSoftwareDownloadRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &EndSoftwareDownloadRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestEndSoftwareDownloadResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, EndSoftwareDownloadResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*EndSoftwareDownloadResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   EndSoftwareDownloadResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &EndSoftwareDownloadResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestActivateSoftwareRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000560a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, ActivateSoftwareRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeActivateSoftwareRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*ActivateSoftwareRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareRequestSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000560a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   ActivateSoftwareRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &ActivateSoftwareRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestActivateSoftwareResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, ActivateSoftwareResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeActivateSoftwareResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*ActivateSoftwareResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   ActivateSoftwareResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &ActivateSoftwareResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCommitSoftwareRequestDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, CommitSoftwareRequestType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeCommitSoftwareRequest)
	//assert.NotNil(t, msgLayer)
	//
	//request, ok2 := msgLayer.(*CommitSoftwareRequest)
	//assert.True(t, ok2)
	//assert.NotNil(t, request)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareRequestSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := "0000570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   CommitSoftwareRequestType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &CommitSoftwareRequest{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestCommitSoftwareResponseDecode(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//data, err := stringToPacket(goodMessage)
	//assert.NoError(t, err)
	//
	//packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	//assert.NotNil(t, packet)
	//
	//omciLayer := packet.Layer(LayerTypeOMCI)
	//assert.NotNil(t, packet)
	//
	//omciMsg, ok := omciLayer.(*OMCI)
	//assert.True(t, ok)
	//assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	//assert.Equal(t, omciMsg.MessageType, CommitSoftwareResponseType)
	//assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	//assert.Equal(t, omciMsg.Length, uint16(40))
	//
	//msgLayer := packet.Layer(LayerTypeCommitSoftwareResponse)
	//
	//assert.NotNil(t, msgLayer)
	//
	//response, ok2 := msgLayer.(*CommitSoftwareResponse)
	//assert.True(t, ok2)
	//assert.NotNil(t, response)
	//
	//// Verify string output for message
	//packetString := packet.String()
	//assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareResponseSerialize(t *testing.T) {
	// TODO: Need to complete implementation & debug this
	//goodMessage := ""
	//
	//omciLayer := &OMCI{
	//	TransactionID: 0x01,
	//	MessageType:   CommitSoftwareResponseType,
	//	// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
	//	// Length:           0x28,						// Optional, defaults to 40 octets
	//}
	//request := &CommitSoftwareResponse{
	//	MeBasePacket: MeBasePacket{
	//		EntityClass: OnuDataClassID,
	//		// Default Instance ID is 0
	//	},
	//}
	//// Test serialization back to former string
	//var options gopacket.SerializeOptions
	//options.FixLengths = true
	//
	//buffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	//assert.NoError(t, err)
	//
	//outgoingPacket := buffer.Bytes()
	//reconstituted := packetToString(outgoingPacket)
	//assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestMibResetResponseDecode(t *testing.T) {
	goodMessage := "00012F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, MibResetResponseType)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeMibResetResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibResetResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestMibResetResponseSerialize(t *testing.T) {
	goodMessage := "00012F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x01,
		MessageType:   MibResetResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &MibResetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuDataClassID,
			// Default Instance ID is 0
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestSynchronizeTimeRequestDecode(t *testing.T) {
	goodMessage := "0109580a0100000007e20c0101301b0000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, SynchronizeTimeRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SynchronizeTimeRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.Year, uint16(2018))
	assert.Equal(t, request.Month, uint8(12))
	assert.Equal(t, request.Day, uint8(1))
	assert.Equal(t, request.Hour, uint8(01))
	assert.Equal(t, request.Minute, uint8(48))
	assert.Equal(t, request.Second, uint8(27))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSynchronizeTimeRequestSerialize(t *testing.T) {
	goodMessage := "0109580a0100000007e20c0101301b0000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0109,
		MessageType:   SynchronizeTimeRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SynchronizeTimeRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			// Default Instance ID is 0
		},
		Year:   uint16(2018),
		Month:  uint8(12),
		Day:    uint8(1),
		Hour:   uint8(01),
		Minute: uint8(48),
		Second: uint8(27),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestSynchronizeTimeResponseDecode(t *testing.T) {
	goodMessage := "0109380a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.MessageType, SynchronizeTimeResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SynchronizeTimeResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSynchronizeTimeResponseSerialize(t *testing.T) {
	goodMessage := "0109380a01000000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0109,
		MessageType:   SynchronizeTimeResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &SynchronizeTimeResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result:         me.Success,
		SuccessResults: uint8(0),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestRebootRequestDecode(t *testing.T) {
	goodMessage := "0001590a01000000010000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0001))
	assert.Equal(t, omciMsg.MessageType, RebootRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeRebootRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*RebootRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.OnuGClassID)
	assert.Equal(t, request.EntityInstance, uint16(0))
	assert.Equal(t, request.RebootCondition, uint8(1))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestRebootRequestSerialize(t *testing.T) {
	goodMessage := "0001590a01000000020000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0001,
		MessageType:   RebootRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &RebootRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			// Default Instance ID is 0
		},
		RebootCondition: uint8(2),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestRebootResponseDecode(t *testing.T) {
	goodMessage := "023c390a01000000000000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x023c))
	assert.Equal(t, omciMsg.MessageType, RebootResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeRebootResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*RebootResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, response.EntityClass, me.OnuGClassID)
	assert.Equal(t, response.EntityInstance, uint16(0))
	assert.Equal(t, response.Result, me.Success)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestRebootResponseSerialize(t *testing.T) {
	goodMessage := "023c390a01000000060000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x023c,
		MessageType:   RebootResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &RebootResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Result: me.DeviceBusy,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetNextRequestDecode(t *testing.T) {
	goodMessage := "285e5a0a00ab0202040000010000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x285e))
	assert.Equal(t, omciMsg.MessageType, GetNextRequestType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.ExtendedVlanTaggingOperationConfigurationDataClassID)
	assert.Equal(t, request.EntityInstance, uint16(0x0202))
	assert.Equal(t, request.AttributeMask, uint16(0x0400))
	assert.Equal(t, request.SequenceNumber, uint16(1))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetNextRequestSerialize(t *testing.T) {
	goodMessage := "285e5a0a00ab0202040000010000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x285e,
		MessageType:   GetNextRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x0202),
		},
		AttributeMask:  uint16(0x0400),
		SequenceNumber: uint16(1),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestGetNextResponseDecode(t *testing.T) {
	goodMessage := "285e3a0a00ab0202000400080334000000000000000000000000000000000000000000000000000000000028"

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x285e))
	assert.Equal(t, omciMsg.MessageType, GetNextResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeGetNextResponse)
	assert.NotNil(t, msgLayer)

	vlanOpTable := []byte{0x08, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	response, ok2 := msgLayer.(*GetNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, response.EntityClass)
	assert.Equal(t, uint16(0x0202), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint16(0x0400), response.AttributeMask)

	// For GetNextResponse frames, caller is responsible for trimming last packet to remaining
	// size
	expectedOctets := 16
	value := response.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.Equal(t, vlanOpTable, value.([]byte)[:expectedOctets])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetNextResponseSerialize(t *testing.T) {
	goodMessage := "285e3a0a00ab0202000400080334000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x285e,
		MessageType:   GetNextResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	vlanOpTable := []byte{0x08, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	request := &GetNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x0202),
		},
		Result:        me.Success,
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": vlanOpTable},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

// TODO: Create request/response tests for all of the following types//GetCurrentData,
//SetTable}

func TestAlarmNotificationDecode(t *testing.T) {
	goodMessage := "0000100a000b0104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AlarmNotificationType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.EntityClass, me.PhysicalPathTerminationPointEthernetUniClassID)
	assert.Equal(t, request.EntityInstance, uint16(0x104))
	assert.Equal(t, request.AlarmBitmap, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	assert.Equal(t, request.AlarmSequenceNumber, byte(5))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestAlarmNotificationSerialize(t *testing.T) {
	goodMessage := "0000100a000b0104800000000000000000000000000000000000000000000000000000000000000500000028"

	omciLayer := &OMCI{
		TransactionID: 0,
		MessageType:   AlarmNotificationType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &AlarmNotificationMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
			EntityInstance: uint16(0x104),
		},
		AlarmBitmap: [28]byte{
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AlarmSequenceNumber: byte(5),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

func TestAttributeValueChangeDecode(t *testing.T) {
	goodMessage := "0000110a0007000080004d4c2d33363236000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0))
	assert.Equal(t, omciMsg.MessageType, AttributeValueChangeType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeAttributeValueChange)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AttributeValueChangeMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, request.AttributeMask, uint16(0x8000))
	assert.Equal(t, request.EntityClass, me.SoftwareImageClassID)
	assert.Equal(t, request.EntityInstance, uint16(0))
	assert.Equal(t, request.Attributes["Version"], []byte{
		0x4d, 0x4c, 0x2d, 0x33, 0x36, 0x32, 0x36,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestAttributeValueChangeSerialize(t *testing.T) {
	goodMessage := "0000110a0007000080004d4c2d33363236000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0,
		MessageType:   AttributeValueChangeType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &AttributeValueChangeMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x8000),
		Attributes: me.AttributeValueMap{
			"Version": []byte{
				0x4d, 0x4c, 0x2d, 0x33, 0x36, 0x32, 0x36,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.NoError(t, err)

	outgoingPacket := buffer.Bytes()
	reconstituted := packetToString(outgoingPacket)
	assert.Equal(t, strings.ToLower(goodMessage), reconstituted)
}

// TODO: Create notification tests for all of the following types
//TestResult,
