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

func TestGetAllAlarmsRequestDecode(t *testing.T) {
	goodMessage := "04454b0a00020000000000000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0445), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, byte(0), request.AlarmRetrievalMode)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsRequestDecodeExtended(t *testing.T) {
	goodMessage := "04454b0b00020000000101"
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
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0445), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, byte(1), request.AlarmRetrievalMode)

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

func TestGetAllAlarmsRequestSerializeExtended(t *testing.T) {
	goodMessage := "04454b0b00020000000101"

	omciLayer := &OMCI{
		TransactionID:    0x0445,
		MessageType:      GetAllAlarmsRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetAllAlarmsRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0445), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, uint16(3), response.NumberOfCommands)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsResponseDecodeExtended(t *testing.T) {
	goodMessage := "04452b0b0002000000020003"
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
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0445), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, uint16(3), response.NumberOfCommands)

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

func TestGetAllAlarmsResponseSerializeExtended(t *testing.T) {
	goodMessage := "04452b0b0002000000020003"

	omciLayer := &OMCI{
		TransactionID:    0x0445,
		MessageType:      GetAllAlarmsResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetAllAlarmsResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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
	goodMessage := "02344c0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"

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
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0234), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsNextRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(3), request.CommandSequenceNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextRequestDecodeExtended(t *testing.T) {
	goodMessage := "02344c0b0002000000020003"

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
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0234), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsNextRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*GetAllAlarmsNextRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, request.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsNextRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(3), request.CommandSequenceNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextRequestSerialize(t *testing.T) {
	goodMessage := "02344c0a00020000000300000000000000000000000000000000000000000000000000000000000000000028"

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
		CommandSequenceNumber: uint16(3),
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

func TestGetAllAlarmsNextRequestSerializeExtended(t *testing.T) {
	goodMessage := "02344c0b0002000000020004"

	omciLayer := &OMCI{
		TransactionID:    0x0234,
		MessageType:      GetAllAlarmsNextRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &GetAllAlarmsNextRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		CommandSequenceNumber: uint16(4),
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
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0234), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsNextResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())

	var alarms [224 / 8]byte
	alarms[0] = 0x80
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, response.AlarmEntityClass)
	assert.Equal(t, uint16(0x102), response.AlarmEntityInstance)
	assert.Equal(t, alarms, response.AlarmBitMap)
	assert.Nil(t, response.AdditionalAlarms)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextResponseDecodeExtended(t *testing.T) {
	goodMessage := "02342c0b000200000020000b010280000000000000000000000000000000000000000000000000000000"
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
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0234), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(32), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())

	var alarms [224 / 8]byte
	alarms[0] = 0x80
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, response.AlarmEntityClass)
	assert.Equal(t, uint16(0x102), response.AlarmEntityInstance)
	assert.Equal(t, alarms, response.AlarmBitMap)
	assert.Nil(t, response.AdditionalAlarms)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGetAllAlarmsNextResponseDecodeExtendedTwoBitmaps(t *testing.T) {
	alarm1 := "000b010280000000000000000000000000000000000000000000000000000000"
	alarm2 := "000b010380000000000000000000000000000000000000000000000000000000"
	goodMessage := "02342c0b000200000040" + alarm1 + alarm2
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
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0234), omciMsg.TransactionID)
	assert.Equal(t, GetAllAlarmsNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(64), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeGetAllAlarmsNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*GetAllAlarmsNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeGetAllAlarmsNextResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())

	var alarms [224 / 8]byte
	alarms[0] = 0x80
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, response.AlarmEntityClass)
	assert.Equal(t, uint16(0x102), response.AlarmEntityInstance)
	assert.Equal(t, alarms, response.AlarmBitMap)

	assert.NotNil(t, response.AdditionalAlarms)
	assert.Equal(t, 1, len(response.AdditionalAlarms))
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, response.AdditionalAlarms[0].AlarmEntityClass)
	assert.Equal(t, uint16(0x103), response.AdditionalAlarms[0].AlarmEntityInstance)
	assert.Equal(t, alarms, response.AdditionalAlarms[0].AlarmBitMap)

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

func TestGetAllAlarmsNextResponseSerializeExtended(t *testing.T) {
	goodMessage := "02342c0b000200000020000b010280000000000000000000000000000000000000000000000000000000"

	omciLayer := &OMCI{
		TransactionID:    0x0234,
		MessageType:      GetAllAlarmsNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	request := &GetAllAlarmsNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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

func TestGetAllAlarmsNextResponseSerializeExtendedTwoBitmaps(t *testing.T) {
	alarm1 := "000b010280000000000000000000000000000000000000000000000000000000"
	alarm2 := "000b010380000000000000000000000000000000000000000000000000000000"
	goodMessage := "02342c0b000200000040" + alarm1 + alarm2

	omciLayer := &OMCI{
		TransactionID:    0x0234,
		MessageType:      GetAllAlarmsNextResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	var alarms [224 / 8]byte
	alarms[0] = 0x80

	secondAlarm := AdditionalAlarmsData{
		AlarmEntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
		AlarmEntityInstance: uint16(0x103),
		AlarmBitMap:         alarms,
	}
	request := &GetAllAlarmsNextResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuDataClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		AlarmEntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
		AlarmEntityInstance: uint16(0x102),
		AlarmBitMap:         alarms,
		AdditionalAlarms:    []AdditionalAlarmsData{secondAlarm},
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

func TestAlarmNotificationDecode(t *testing.T) {
	goodMessage := "0000100a000b0104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAlarmNotification, request.LayerType())
	assert.Equal(t, LayerTypeAlarmNotification, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, request.EntityClass)
	assert.Equal(t, uint16(0x104), request.EntityInstance)
	assert.Equal(t, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, request.AlarmBitmap)
	assert.Equal(t, byte(5), request.AlarmSequenceNumber)

	// Active/Clear tests
	active, err2 := request.IsAlarmActive(0)
	clear, err3 := request.IsAlarmClear(0)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.True(t, active)
	assert.False(t, clear)

	// Active/Clear for undefined alarm bits
	active, err2 = request.IsAlarmActive(1)
	clear, err3 = request.IsAlarmClear(1)
	assert.NotNil(t, err2)
	assert.NotNil(t, err3)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestInvalidClassAlarmNotificationDecode(t *testing.T) {
	// Choosing GalEthernetProfile (272) since it does not support alarms, show we should
	// file the decode
	badMessage := "0000100a01100104800000000000000000000000000000000000000000000000000000000000000500000028"
	data, err := stringToPacket(badMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeAlarmNotification, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.Nil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.False(t, ok2)
	assert.Nil(t, request)
	assert.Equal(t, LayerTypeAlarmNotification, request.LayerType())
	assert.Equal(t, LayerTypeAlarmNotification, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
}

func TestUnknownsMeAlarmNotificationDecode(t *testing.T) {
	// Choosing class ID 22 since it is in the G.988 class ID space and is reserved
	goodMessage := "0000100a00160104800000000000000000000000000000000000000000000000000000000000000500000028"
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
	assert.Equal(t, LayerTypeAlarmNotification, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAlarmNotification, request.LayerType())
	assert.Equal(t, LayerTypeAlarmNotification, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.ClassID(22), request.EntityClass)
	assert.Equal(t, uint16(0x104), request.EntityInstance)
	assert.Equal(t, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, request.AlarmBitmap)
	assert.Equal(t, byte(5), request.AlarmSequenceNumber)
}

func TestVendorSpecificAlarmNotificationDecode(t *testing.T) {
	// Choosing class ID 255 since it is in the first vendor specific class ID space
	goodMessage := "0000100a00FF0104800000000000000000000000000000000000000000000000000000000000000500000028"
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
	assert.Equal(t, LayerTypeAlarmNotification, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAlarmNotification, request.LayerType())
	assert.Equal(t, LayerTypeAlarmNotification, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.ClassID(255), request.EntityClass)
	assert.Equal(t, uint16(0x104), request.EntityInstance)
	assert.Equal(t, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, request.AlarmBitmap)
	assert.Equal(t, byte(5), request.AlarmSequenceNumber)
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

func TestAlarmNotificationSerializeNonZeroTIC(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 1,
		MessageType:   AlarmNotificationType,
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
	assert.Error(t, err)
}

func TestExtendedAlarmNotificationDecode(t *testing.T) {
	//                                   1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
	goodMessage := "0000100b000b0104001d8000000000000000000000000000000000000000000000000000000005"
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
	assert.Equal(t, LayerTypeAlarmNotification, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AlarmNotificationType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(29), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAlarmNotification)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AlarmNotificationMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAlarmNotification, request.LayerType())
	assert.Equal(t, LayerTypeAlarmNotification, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, me.PhysicalPathTerminationPointEthernetUniClassID, request.EntityClass)
	assert.Equal(t, uint16(0x104), request.EntityInstance)
	assert.Equal(t, [28]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, request.AlarmBitmap)
	assert.Equal(t, byte(5), request.AlarmSequenceNumber)

	// Active/Clear tests
	active, err2 := request.IsAlarmActive(0)
	clear, err3 := request.IsAlarmClear(0)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.True(t, active)
	assert.False(t, clear)

	// Active/Clear for undefined alarm bits
	active, err2 = request.IsAlarmActive(1)
	clear, err3 = request.IsAlarmClear(1)
	assert.NotNil(t, err2)
	assert.NotNil(t, err3)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedAlarmNotificationSerialize(t *testing.T) {
	//                                   1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
	goodMessage := "0000100b000b0104001d8000000000000000000000000000000000000000000000000000000005"

	omciLayer := &OMCI{
		TransactionID:    0,
		MessageType:      AlarmNotificationType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &AlarmNotificationMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.PhysicalPathTerminationPointEthernetUniClassID,
			EntityInstance: uint16(0x104),
			Extended:       true,
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

func TestAlarmDecodesOmciLayerHeaderTooSmall(t *testing.T) {
	// Baseline is always checked for < 40 octets and that test is in mebase_test.go. And
	// that test also handles Extended message set where the length field is short. This
	// test for a valid length field but no message content past that.
	getAllAlarmsRequestExt := "04454b0b000200000000"
	getAllAlarmsResponseExt := "04452b0b000200000000"
	getAllAlarmsNextRequestExt := "02344c0b000200000000"
	alarmNotificationExt := "0000100b000b01040000"

	frames := []string{
		getAllAlarmsRequestExt,
		getAllAlarmsResponseExt,
		getAllAlarmsNextRequestExt,
		alarmNotificationExt,
	}
	for _, frame := range frames {
		data, err := stringToPacket(frame)
		assert.NoError(t, err)

		// Should get packet but with error layer
		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		// OMCI layer should be present (but not message type specific layer)
		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		// And there is an error layer. Since OMCI, we only have two OMCI and
		// the message type layer (which should be the failed one)
		assert.Equal(t, 2, len(packet.Layers()))
		errLayer := packet.ErrorLayer()
		assert.NotNil(t, errLayer)
		metaData := packet.Metadata()
		assert.NotNil(t, metaData)
		assert.True(t, metaData.Truncated)
	}
}
