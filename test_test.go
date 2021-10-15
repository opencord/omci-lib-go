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
	"fmt"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestGenericTestResultDecode(t *testing.T) {
	// ONU-G ME for this test with just made up data
	payload := "1234567890123456789012345678901234567890123456789012345678901234"
	goodMessage := "00001b0a01000000" + payload + "00000028"
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
	assert.Equal(t, LayerTypeTestResult, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0000), omciMsg.TransactionID)
	assert.Equal(t, TestResultType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestResult)
	assert.NotNil(t, msgLayer)

	// This is a generic struct since we do not do detailed decode
	generic, ok2 := msgLayer.(*TestResultNotification)
	assert.True(t, ok2)
	assert.NotNil(t, generic)
	assert.Equal(t, LayerTypeTestResult, generic.LayerType())
	assert.Equal(t, LayerTypeTestResult, generic.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, generic.NextLayerType())
	assert.NotNil(t, generic.MeBasePacket.Payload) // Next three all same data
	assert.NotNil(t, generic.Payload)
	assert.NotNil(t, generic.TestResults())

	base := generic.MeBasePacket
	assert.Equal(t, me.OnuGClassID, base.EntityClass)
	assert.Equal(t, uint16(0), base.EntityInstance)

	// For the generic Test Result, get the payload data which is all the data in
	// the test notification past the Entity Instance value.
	payloadData, payloadErr := stringToPacket(payload)
	assert.NotNil(t, payloadData)
	assert.NoError(t, payloadErr)
	assert.Equal(t, payloadData, base.Payload)
	assert.Equal(t, payloadData, generic.Payload)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestOpticalLineSupervisionTestResultDecode(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "010034" + "030067" + "050091" + "090034" + "0c0067" + "8901" + "000000000000000000000000000000"
	goodMessage := "00001b0a01078001" + payload + "00000028"
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
	assert.Equal(t, LayerTypeTestResult, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0000), omciMsg.TransactionID)
	assert.Equal(t, TestResultType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestResult)
	assert.NotNil(t, msgLayer)

	// This is a optical line test results
	optical, ok2 := msgLayer.(*OpticalLineSupervisionTestResult)
	assert.True(t, ok2)
	assert.NotNil(t, optical)
	assert.Equal(t, LayerTypeTestResult, optical.LayerType())
	assert.Equal(t, LayerTypeTestResult, optical.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, optical.NextLayerType())

	// Get the Managed Entity class ID and instance ID from the base packet
	base := optical.MeBasePacket
	assert.Equal(t, me.AniGClassID, base.EntityClass)
	assert.Equal(t, uint16(0x8001), base.EntityInstance)

	assert.Equal(t, uint8(1), optical.PowerFeedVoltageType)
	assert.Equal(t, uint16(0x34), optical.PowerFeedVoltage)

	assert.Equal(t, uint8(3), optical.ReceivedOpticalPowerType)
	assert.Equal(t, uint16(0x67), optical.ReceivedOpticalPower)

	assert.Equal(t, uint8(5), optical.MeanOpticalLaunchType)
	assert.Equal(t, uint16(0x91), optical.MeanOpticalLaunch)

	assert.Equal(t, uint8(9), optical.LaserBiasCurrentType)
	assert.Equal(t, uint16(0x34), optical.LaserBiasCurrent)

	assert.Equal(t, uint8(12), optical.TemperatureType)
	assert.Equal(t, uint16(0x67), optical.Temperature)

	assert.Equal(t, uint16(0x8901), optical.GeneralPurposeBuffer)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGenericTestResultSerialize(t *testing.T) {
	payload := "1234567891234567890123456789012345678901234567890123456789012345"
	goodMessage := "00001b0a01000000" + payload + "00000028"

	omciLayer := &OMCI{
		TransactionID: 0x0000, // Optional for notifications since TID always 0x0000
		MessageType:   TestResultType,
		// DeviceIdentifier: omci.BaselineIdent,    // Optional, defaults to Baseline
		// Length:           0x28,					// Optional, defaults to 40 octets
	}
	data, derr := stringToPacket(payload)
	assert.NoError(t, derr)

	request := &TestResultNotification{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Payload: data,
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

func TestGenericTestResultNonZeroTICSerialize(t *testing.T) {
	payload := "1234567891234567890123456789012345678901234567890123456789012345"
	goodMessage := "12341b0a01000000" + payload + "00000028"

	omciLayer := &OMCI{
		TransactionID: 0x1234,
		MessageType:   TestResultType,
		// DeviceIdentifier: omci.BaselineIdent,    // Optional, defaults to Baseline
		// Length:           0x28,					// Optional, defaults to 40 octets
	}
	data, derr := stringToPacket(payload)
	assert.NoError(t, derr)

	request := &TestResultNotification{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Payload: data,
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

func TestOpticalLineSupervisionTestResultSerialize(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "010034" + "030067" + "050091" + "090034" + "0c0067" + "8901" + "000000000000000000000000000000"
	goodMessage := "00001b0a01078001" + payload + "00000028"

	omciLayer := &OMCI{
		// TransactionID: 0x0c,						// Optional for notifications since TID always 0x0000
		MessageType: TestResultType,
		// DeviceIdentifier: omci.BaselineIdent,    // Optional, defaults to Baseline
		// Length:           0x28,					// Optional, defaults to 40 octets
	}
	request := &OpticalLineSupervisionTestResult{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0x8001),
		},
		PowerFeedVoltageType:     uint8(1),
		PowerFeedVoltage:         uint16(0x34),
		ReceivedOpticalPowerType: uint8(3),
		ReceivedOpticalPower:     uint16(0x67),
		MeanOpticalLaunchType:    uint8(5),
		MeanOpticalLaunch:        uint16(0x91),
		LaserBiasCurrentType:     uint8(9),
		LaserBiasCurrent:         uint16(0x34),
		TemperatureType:          uint8(12),
		Temperature:              uint16(0x67),
		GeneralPurposeBuffer:     uint16(0x8901),
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

func TestGenericTestRequestDecode(t *testing.T) {
	// ONU-G ME for this test with just made up data
	payload := "1234567890523456789012345678901234567890123456789012345678901234"
	goodMessage := "0123520a01000000" + payload + "00000028"
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
	assert.Equal(t, LayerTypeTestRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0123), omciMsg.TransactionID)
	assert.Equal(t, TestRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestRequest)
	assert.NotNil(t, msgLayer)

	// This is a generic struct since we do not do detailed decode
	generic, ok2 := msgLayer.(*TestRequest)
	assert.True(t, ok2)
	assert.NotNil(t, generic)
	assert.Equal(t, LayerTypeTestRequest, generic.LayerType())
	assert.Equal(t, LayerTypeTestRequest, generic.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, generic.NextLayerType())
	assert.NotNil(t, generic.MeBasePacket.Payload) // Next three all same data
	assert.NotNil(t, generic.Payload)
	assert.NotNil(t, generic.TestRequest())

	base := generic.MeBasePacket
	assert.Equal(t, me.OnuGClassID, base.EntityClass)
	assert.Equal(t, uint16(0), base.EntityInstance)

	// For the generic Test Result, get the payload data which is all the data in
	// the test notification past the Entity Instance value.
	payloadData, payloadErr := stringToPacket(payload)
	assert.NotNil(t, payloadData)
	assert.NoError(t, payloadErr)
	assert.Equal(t, payloadData, base.Payload)
	assert.Equal(t, payloadData, generic.Payload)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestOpticalLineSupervisionTestRequestDecode(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "01" + "1234" + "5678" + "000000000000000000000000000000000000000000000000000000"
	goodMessage := "0ddd520a01078001" + payload + "00000028"
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
	assert.Equal(t, LayerTypeTestRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0ddd), omciMsg.TransactionID)
	assert.Equal(t, TestRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestRequest)
	assert.NotNil(t, msgLayer)

	// This is a optical line test results
	optical, ok2 := msgLayer.(*OpticalLineSupervisionTestRequest)
	assert.True(t, ok2)
	assert.NotNil(t, optical)
	assert.Equal(t, LayerTypeTestRequest, optical.LayerType())
	assert.Equal(t, LayerTypeTestRequest, optical.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, optical.NextLayerType())

	// Get the Managed Entity class ID and instance ID from the base packet
	base := optical.MeBasePacket
	assert.Equal(t, me.AniGClassID, base.EntityClass)
	assert.Equal(t, uint16(0x8001), base.EntityInstance)

	assert.Equal(t, uint8(1), optical.SelectTest)
	assert.Equal(t, uint16(0x1234), optical.GeneralPurposeBuffer)
	assert.Equal(t, uint16(0x5678), optical.VendorSpecificParameters)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestGenericTestRequestSerialize(t *testing.T) {
	payload := "1234567891234567890123456789012345678901234567890123456789012345"
	goodMessage := "eeee520a01000000" + payload + "00000028"

	omciLayer := &OMCI{
		TransactionID: 0xeeee,
		MessageType:   TestRequestType,
		// DeviceIdentifier: omci.BaselineIdent,    // Optional, defaults to Baseline
		// Length:           0x28,					// Optional, defaults to 40 octets
	}
	data, derr := stringToPacket(payload)
	assert.NoError(t, derr)

	request := &TestRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
		},
		Payload: data,
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

func TestOpticalLineSupervisionTestRequestSerialize(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "01" + "1234" + "5678" + "000000000000000000000000000000000000000000000000000000"
	goodMessage := "bbbb520a01078001" + payload + "00000028"

	omciLayer := &OMCI{
		TransactionID: 0xbbbb,
		MessageType:   TestRequestType,
		// DeviceIdentifier: omci.BaselineIdent,    // Optional, defaults to Baseline
		// Length:           0x28,					// Optional, defaults to 40 octets
	}
	request := &OpticalLineSupervisionTestRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0x8001),
		},
		SelectTest:               uint8(1),
		GeneralPurposeBuffer:     uint16(0x1234),
		VendorSpecificParameters: uint16(0x5678),
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

func TestTestResponseDecode(t *testing.T) {
	goodMessage := "0001320A01000000000000000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeTestResponse, omciMsg.NextLayerType())
	assert.Equal(t, TestResponseType, omciMsg.MessageType)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*TestResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeTestResponse, response.LayerType())
	assert.Equal(t, LayerTypeTestResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.OnuGClassID, response.EntityClass)
	assert.Equal(t, uint16(0), response.EntityInstance)
	assert.Equal(t, me.Success, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestTestResponseSerialize(t *testing.T) {
	goodMessage := "0001320A01000000000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x01,
		MessageType:   TestResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &TestResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.OnuGClassID,
			// Default Instance ID is 0
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

func TestExtendedGenericTestResultDecode(t *testing.T) {
	// ONU-G ME for this test with just made up data
	payload := "1234567890123456789012345678901234567890"
	resultLen := len(payload) / 2
	goodMessage := "00001b0b01000000" + fmt.Sprintf("%04x", resultLen) + payload
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
	assert.Equal(t, LayerTypeTestResult, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0000), omciMsg.TransactionID)
	assert.Equal(t, TestResultType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, omciMsg.Length, uint16(resultLen))

	msgLayer := packet.Layer(LayerTypeTestResult)
	assert.NotNil(t, msgLayer)

	// This is a generic struct since we do not do detailed decode
	generic, ok2 := msgLayer.(*TestResultNotification)
	assert.True(t, ok2)
	assert.NotNil(t, generic)
	assert.Equal(t, LayerTypeTestResult, generic.LayerType())
	assert.Equal(t, LayerTypeTestResult, generic.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, generic.NextLayerType())
	assert.NotNil(t, generic.MeBasePacket.Payload) // Next three all same data
	assert.NotNil(t, generic.Payload)
	assert.NotNil(t, generic.TestResults())

	base := generic.MeBasePacket
	assert.Equal(t, me.OnuGClassID, base.EntityClass)
	assert.Equal(t, uint16(0), base.EntityInstance)

	// For the generic Test Result, get the payload data which is all the data in
	// the test notification past the Entity Instance value.
	payloadData, payloadErr := stringToPacket(payload)
	assert.NotNil(t, payloadData)
	assert.NoError(t, payloadErr)
	assert.Equal(t, payloadData, base.Payload)
	assert.Equal(t, payloadData, generic.Payload)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedOpticalLineSupervisionTestResultDecode(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "010034" + "030067" + "050091" + "090034" + "0c0067" + "8901"
	resultLen := len(payload) / 2
	goodMessage := "00001b0b01078001" + fmt.Sprintf("%04x", resultLen) + payload
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
	assert.Equal(t, LayerTypeTestResult, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0000), omciMsg.TransactionID)
	assert.Equal(t, TestResultType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(resultLen), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeTestResult)
	assert.NotNil(t, msgLayer)

	// This is a optical line test results
	optical, ok2 := msgLayer.(*OpticalLineSupervisionTestResult)
	assert.True(t, ok2)
	assert.NotNil(t, optical)
	assert.Equal(t, LayerTypeTestResult, optical.LayerType())
	assert.Equal(t, LayerTypeTestResult, optical.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, optical.NextLayerType())

	// Get the Managed Entity class ID and instance ID from the base packet
	base := optical.MeBasePacket
	assert.Equal(t, me.AniGClassID, base.EntityClass)
	assert.Equal(t, uint16(0x8001), base.EntityInstance)

	assert.Equal(t, uint8(1), optical.PowerFeedVoltageType)
	assert.Equal(t, uint16(0x34), optical.PowerFeedVoltage)

	assert.Equal(t, uint8(3), optical.ReceivedOpticalPowerType)
	assert.Equal(t, uint16(0x67), optical.ReceivedOpticalPower)

	assert.Equal(t, uint8(5), optical.MeanOpticalLaunchType)
	assert.Equal(t, uint16(0x91), optical.MeanOpticalLaunch)

	assert.Equal(t, uint8(9), optical.LaserBiasCurrentType)
	assert.Equal(t, uint16(0x34), optical.LaserBiasCurrent)

	assert.Equal(t, uint8(12), optical.TemperatureType)
	assert.Equal(t, uint16(0x67), optical.Temperature)

	assert.Equal(t, uint16(0x8901), optical.GeneralPurposeBuffer)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedGenericTestResultSerialize(t *testing.T) {
	payload := "12345678901234567890"
	resultLen := len(payload) / 2
	goodMessage := "00001b0b01000000" + fmt.Sprintf("%04x", resultLen) + payload

	omciLayer := &OMCI{
		// TransactionID: 0x0c,						// Optional for notifications since TID always 0x0000
		MessageType:      TestResultType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	data, derr := stringToPacket(payload)
	assert.NoError(t, derr)

	request := &TestResultNotification{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0),
			Extended:       true,
		},
		Payload: data,
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

func TestExtendedOpticalLineSupervisionTestResultSerialize(t *testing.T) {
	// ANI-G ME for this test with just made up data
	payload := "010034" + "030067" + "050091" + "090034" + "0c0067" + "8901"
	resultLen := len(payload) / 2
	goodMessage := "00001b0b01078001" + fmt.Sprintf("%04x", resultLen) + payload

	omciLayer := &OMCI{
		// TransactionID: 0x0c,						// Optional for notifications since TID always 0x0000
		MessageType:      TestResultType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &OpticalLineSupervisionTestResult{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.AniGClassID,
			EntityInstance: uint16(0x8001),
			Extended:       true,
		},
		PowerFeedVoltageType:     uint8(1),
		PowerFeedVoltage:         uint16(0x34),
		ReceivedOpticalPowerType: uint8(3),
		ReceivedOpticalPower:     uint16(0x67),
		MeanOpticalLaunchType:    uint8(5),
		MeanOpticalLaunch:        uint16(0x91),
		LaserBiasCurrentType:     uint8(9),
		LaserBiasCurrent:         uint16(0x34),
		TemperatureType:          uint8(12),
		Temperature:              uint16(0x67),
		GeneralPurposeBuffer:     uint16(0x8901),
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
