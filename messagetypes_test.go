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
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go"
	me "github.com/opencord/omci-lib-go/generated"
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

func TestGetSoftwareImageResponseDecode(t *testing.T) {
	goodMessage := "035e290a00070000000400000102030405060708090a0b0c0d0e0f0000000000000000000000000000000028"
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
	assert.Equal(t, response.AttributeMask, uint16(0x0400))
	assert.Equal(t, response.Attributes["ImageHash"], toOctets("AAECAwQFBgcICQoLDA0ODw==")) // 0->f octets)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetSoftwareImageResponseSerialize(t *testing.T) {
	goodMessage := "035e290a00070000000400000102030405060708090a0b0c0d0e0f0000000000000000000000000000000028"
	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetResponseType,
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0x0400),
		Attributes: me.AttributeValueMap{
			"ImageHash": toOctets("AAECAwQFBgcICQoLDA0ODw==")}, // 0->f octets
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
