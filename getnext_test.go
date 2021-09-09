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

func TestGetNextRequestDecode(t *testing.T) {
	goodMessage := "285e5a0a00ab0202040000010000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x285e), omciMsg.TransactionID)
	assert.Equal(t, GetNextRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0x0202), request.EntityInstance)
	assert.Equal(t, uint16(0x0400), request.AttributeMask)
	assert.Equal(t, uint16(1), request.SequenceNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetNextRequestDecodeExtended(t *testing.T) {
	goodMessage := "285e5a0b00ab0202000404000001"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x285e), omciMsg.TransactionID)
	assert.Equal(t, GetNextRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(4), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0x0202), request.EntityInstance)
	assert.Equal(t, uint16(0x0400), request.AttributeMask)
	assert.Equal(t, uint16(1), request.SequenceNumber)

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

func TestGetNextRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
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
	assert.Error(t, err)
}

func TestGetNextRequestSerializeExtended(t *testing.T) {
	goodMessage := "285e5a0b00ab0202000404000001"

	omciLayer := &OMCI{
		TransactionID:    0x285e,
		MessageType:      GetNextRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x0202),
			Extended:       true,
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
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x285e), omciMsg.TransactionID)
	assert.Equal(t, GetNextResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetNextResponse)
	assert.NotNil(t, msgLayer)

	vlanOpTable := []byte{0x08, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	response, ok2 := msgLayer.(*GetNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, response.EntityClass)
	assert.Equal(t, uint16(0x0202), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint16(0x0400), response.AttributeMask)

	// For GetNextResponse frames, caller is responsible for trimming last packet to remaining
	// size
	expectedOctets := 16
	value := response.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.Equal(t, value.([]byte)[:expectedOctets], vlanOpTable)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetNextResponseDecodeExtended(t *testing.T) {
	goodMessage := "285e3a0b00ab0202001300040008033400000000000000000000000000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x285e), omciMsg.TransactionID)
	assert.Equal(t, GetNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(19), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetNextResponse)
	assert.NotNil(t, msgLayer)

	vlanOpTable := []byte{0x08, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	response, ok2 := msgLayer.(*GetNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, response.EntityClass)
	assert.Equal(t, uint16(0x0202), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint16(0x0400), response.AttributeMask)

	// For GetNextResponse frames, caller is responsible for trimming last packet to remaining
	// size
	expectedOctets := 16
	value := response.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.Equal(t, value.([]byte)[:expectedOctets], vlanOpTable)

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

func TestGetNextResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
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
	assert.Error(t, err)
}

func TestGetNextResponseSerializeExtended(t *testing.T) {
	goodMessage := "285e3a0b00ab0202001300040008033400000000000000000000000000"

	omciLayer := &OMCI{
		TransactionID:    0x285e,
		MessageType:      GetNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	vlanOpTable := []byte{0x08, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	request := &GetNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x0202),
			Extended:       true,
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
