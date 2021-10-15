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
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestGetCurrentDataRequestDecode(t *testing.T) {
	goodMessage := "035e5c0a01a90000004400000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeGetCurrentDataRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x035e), omciMsg.TransactionID)
	assert.Equal(t, GetCurrentDataRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetCurrentDataRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetCurrentDataRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetCurrentDataRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetCurrentDataRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.EthernetFrameExtendedPm64BitClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)
	assert.Equal(t, uint16(0x0044), request.AttributeMask)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetCurrentDataRequestSerialize(t *testing.T) {
	goodMessage := "035e5c0a01a90000004400000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetCurrentDataRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetCurrentDataRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.EthernetFrameExtendedPm64BitClassID,
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

func TestGetCurrentDataRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   GetCurrentDataRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetCurrentDataRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.EthernetFrameExtendedPm64BitClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: uint16(0x0044),
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestGetCurrentDataResponseDecode(t *testing.T) {
	goodMessage := "035e3c0a01a90000000044123456781234dbcb432187654321dac1000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeGetCurrentDataResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x035e), omciMsg.TransactionID)
	assert.Equal(t, GetCurrentDataResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetCurrentDataResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetCurrentDataResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetCurrentDataResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetCurrentDataResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.EthernetFrameExtendedPm64BitClassID, response.EntityClass)
	assert.Equal(t, uint16(0), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint16(0x0044), response.AttributeMask)
	assert.Equal(t, uint64(0x123456781234dbcb), response.Attributes["OversizeFrames"])
	assert.Equal(t, uint64(0x432187654321dac1), response.Attributes["Frames256To511Octets"])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetCurrentDataResponseSerialize(t *testing.T) {
	goodMessage := "035e3c0a01a90000000044123456781234dbcb432187654321dac10000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x035e,
		MessageType:   GetCurrentDataResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetCurrentDataResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.EthernetFrameExtendedPm64BitClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0x0044),
		Attributes: me.AttributeValueMap{
			"OversizeFrames":       uint64(0x123456781234dbcb),
			"Frames256To511Octets": uint64(0x432187654321dac1),
			// BroadcastFrames can be supplied but will not be encoded since not in attribute mask.
			"BroadcastFrames": uint64(0x0123456789abcdef)},
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

func TestGetCurrentDataResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   GetCurrentDataResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &GetCurrentDataResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.EthernetFrameExtendedPm64BitClassID,
			EntityInstance: uint16(0),
		},
		Result:        0,
		AttributeMask: uint16(0x0044),
		Attributes: me.AttributeValueMap{
			"OversizeFrames":       uint64(0x123456781234dbcb),
			"Frames256To511Octets": uint64(0x432187654321dac1),
			// BroadcastFrames can be supplied but will not be encoded since not in attribute mask.
			"BroadcastFrames": uint64(0x0123456789abcdef)},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestExtendedGetCurrentDataRequestDecode(t *testing.T) {
	goodMessage := "035e5c0b0034000100028000"
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
	assert.Equal(t, LayerTypeGetCurrentDataRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x035e), omciMsg.TransactionID)
	assert.Equal(t, GetCurrentDataRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetCurrentDataRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetCurrentDataRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetCurrentDataRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetCurrentDataRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.MacBridgePortPerformanceMonitoringHistoryDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0x8000), request.AttributeMask)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedGetCurrentDataRequestSerialize(t *testing.T) {
	goodMessage := "035e5c0b0034000100028000"

	omciLayer := &OMCI{
		TransactionID:    0x035e,
		MessageType:      GetCurrentDataRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.MacBridgePortPerformanceMonitoringHistoryDataClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		AttributeMask: uint16(0x8000),
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

func TestExtendedGetCurrentDataResponseDecode(t *testing.T) {
	goodMessage := "035e3c0b0034000100080080000000000010"
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
	assert.Equal(t, LayerTypeGetCurrentDataResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x035e), omciMsg.TransactionID)
	assert.Equal(t, GetCurrentDataResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(8), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetCurrentDataResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetCurrentDataResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetCurrentDataResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetCurrentDataResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.MacBridgePortPerformanceMonitoringHistoryDataClassID, response.EntityClass)
	assert.Equal(t, uint16(1), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint16(0x8000), response.AttributeMask)
	assert.Equal(t, uint8(0x10), response.Attributes["IntervalEndTime"])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedGetCurrentDataResponseSerialize(t *testing.T) {
	goodMessage := "035e3c0b0034000100080080000000000010"

	omciLayer := &OMCI{
		TransactionID:    0x035e,
		MessageType:      GetCurrentDataResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.MacBridgePortPerformanceMonitoringHistoryDataClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		Result:        me.Success,
		AttributeMask: uint16(0x8000),
		Attributes: me.AttributeValueMap{
			"IntervalEndTime": uint8(0x10),
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
