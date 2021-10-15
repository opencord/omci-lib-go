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

func TestStartSoftwareDownloadRequestDecode(t *testing.T) {
	goodMessage := "0004530a00070001ff000f424001000100000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0004), omciMsg.TransactionID)
	assert.Equal(t, StartSoftwareDownloadRequestType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*StartSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, request.LayerType())
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint8(0xff), request.WindowSize)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)
	assert.Equal(t, uint8(1), request.NumberOfCircuitPacks)
	assert.NotNil(t, request.CircuitPacks)
	assert.Equal(t, 1, len(request.CircuitPacks))
	assert.Equal(t, uint16(1), request.CircuitPacks[0])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadRequestDecodeExtended(t *testing.T) {
	goodMessage := "0004530b000700010008ff000f4240010001"
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
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0004), omciMsg.TransactionID)
	assert.Equal(t, StartSoftwareDownloadRequestType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(8), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*StartSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, request.LayerType())
	assert.Equal(t, LayerTypeStartSoftwareDownloadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint8(0xff), request.WindowSize)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)
	assert.Equal(t, uint8(1), request.NumberOfCircuitPacks)
	assert.NotNil(t, request.CircuitPacks)
	assert.Equal(t, 1, len(request.CircuitPacks))
	assert.Equal(t, uint16(1), request.CircuitPacks[0])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadRequestSerialize(t *testing.T) {
	goodMessage := "0004530a00070001ff000f424001000100000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x04,
		MessageType:   StartSoftwareDownloadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &StartSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		WindowSize:           255,
		ImageSize:            0x000f4240,
		NumberOfCircuitPacks: 1,
		CircuitPacks:         []uint16{0x0001},
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

func TestStartSoftwareDownloadRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   StartSoftwareDownloadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &StartSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		WindowSize:           255,
		ImageSize:            0x000f4240,
		NumberOfCircuitPacks: 1,
		CircuitPacks:         []uint16{0x0001},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestStartSoftwareDownloadRequestSerializeExtended(t *testing.T) {
	goodMessage := "0004530b000700010008ff000f4240010001"

	omciLayer := &OMCI{
		TransactionID:    0x04,
		MessageType:      StartSoftwareDownloadRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &StartSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		WindowSize:           255,
		ImageSize:            0x000f4240,
		NumberOfCircuitPacks: 1,
		CircuitPacks:         []uint16{0x0001},
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

func TestStartSoftwareDownloadResponseDecode(t *testing.T) {
	goodMessage := "0004330a0007000100ff00000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(0x0004))
	assert.Equal(t, omciMsg.MessageType, StartSoftwareDownloadResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*StartSoftwareDownloadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint8(0xff), response.WindowSize)
	assert.Equal(t, uint8(0), response.NumberOfInstances)
	assert.Nil(t, response.MeResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadResponseDecodeExtended(t *testing.T) {
	goodMessage := "0004330b00070001000300ff00"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0004), omciMsg.TransactionID)
	assert.Equal(t, StartSoftwareDownloadResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*StartSoftwareDownloadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.Success, response.Result)
	assert.Equal(t, uint8(0xff), response.WindowSize)
	assert.Equal(t, uint8(0), response.NumberOfInstances)
	assert.Nil(t, response.MeResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestStartSoftwareDownloadResponseSerialize(t *testing.T) {
	goodMessage := "0001330a0007000100ff00000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x01,
		MessageType:   StartSoftwareDownloadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &StartSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result:            me.Success,
		WindowSize:        0xff,
		NumberOfInstances: 0,   // Note: Optional since default is zero
		MeResults:         nil, // Note: Optional since default is nil
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

func TestStartSoftwareDownloadResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   StartSoftwareDownloadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &StartSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result:            me.Success,
		WindowSize:        0xff,
		NumberOfInstances: 0,   // Note: Optional since default is zero
		MeResults:         nil, // Note: Optional since default is nil
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestStartSoftwareDownloadResponseSerializeExtended(t *testing.T) {
	goodMessage := "0001330b00070001000300ff00"

	omciLayer := &OMCI{
		TransactionID:    0x01,
		MessageType:      StartSoftwareDownloadResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &StartSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		Result:            me.Success,
		WindowSize:        0xff,
		NumberOfInstances: 0,   // Note: Optional since default is zero
		MeResults:         nil, // Note: Optional since default is nil
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

func TestDownloadSectionRequestDecodeNoResponseExpected(t *testing.T) {
	goodMessage := "0008140a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"
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
	assert.Equal(t, LayerTypeDownloadSectionRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestType, omciMsg.MessageType)
	assert.False(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.LayerType())
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint8(0xcc), request.SectionNumber)
	assert.Equal(t, MaxDownloadSectionLength, len(request.SectionData))

	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))
	assert.Equal(t, sectionData, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionRequestDecodeResponseExpected(t *testing.T) {
	goodMessage := "0008540a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"
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
	assert.Equal(t, LayerTypeDownloadSectionLastRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestWithResponseType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.LayerType())
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint8(0xcc), request.SectionNumber)
	assert.Equal(t, 31, len(request.SectionData))

	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))
	assert.Equal(t, sectionData, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionRequestSerializeNoResponseExpected(t *testing.T) {
	goodMessage := "0123140a00070000cc0102030405060708091011121314151617181920212223242526272829303100000028"

	omciLayer := &OMCI{
		TransactionID: 0x0123,
		MessageType:   DownloadSectionRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
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

func TestDownloadSectionRequestSerializeNoResponsePartialDataExpected(t *testing.T) {
	// If a small buffer is provided, serialize will now zero extend the baseline format
	goodMessage := "0123140a00070000cc0102030405060708091011121314151617181920212223242526272829000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0123,
		MessageType:   DownloadSectionRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("0102030405060708091011121314151617181920212223242526272829")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength-2, len(sectionData)) // Partial data buffer

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
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

func TestDownloadSectionRequestSerializeResponseExpectedMethod1(t *testing.T) {
	goodMessage := "2468540a00070000cc0102030405060708091011121314151617181920212223242526272829303100000028"

	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestType, // or DownloadSectionRequestWithResponseType
		ResponseExpected: true,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
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

func TestDownloadSectionRequestSerializeResponseExpectedMethod2(t *testing.T) {
	goodMessage := "2468540a00070001cc0102030405060708091011121314151617181920212223242526272829303100000028"

	// In this case, just use the request type with AR response requested already encoded
	omciLayer := &OMCI{
		TransactionID: 0x2468,
		MessageType:   DownloadSectionRequestWithResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
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

func TestDownloadSectionRequestSerializeResponseExpectedZeroTICMethod1(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0,
		MessageType:      DownloadSectionRequestType, // or DownloadSectionRequestWithResponseType
		ResponseExpected: true,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	sectionData, genErr := stringToPacket("01020304050607080910111213141516171819202122232425262728293031")
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, MaxDownloadSectionLength, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default Instance ID is 0
		},
		SectionNumber: 0xcc,
		SectionData:   sectionData,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestExtendedDownloadSectionRequestDecodeNoResponseExpected(t *testing.T) {
	goodMessage := "0008140b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x88
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.Nil(t, packet.ErrorLayer())

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeDownloadSectionRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestType, omciMsg.MessageType)
	assert.False(t, omciMsg.ResponseExpected)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(length), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.LayerType())
	assert.Equal(t, LayerTypeDownloadSectionRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint8(sectionNumber), request.SectionNumber)
	assert.Equal(t, length-1, len(request.SectionData))

	data, err = stringToPacket(payloadTotal)
	assert.NoError(t, err)
	assert.Equal(t, data, request.SectionData[:])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionRequestDecodeResponseExpected(t *testing.T) {
	goodMessage := "0008540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x88
	length := 1 + (20 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	assert.Nil(t, packet.ErrorLayer())

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x0008), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionRequestWithResponseType, omciMsg.MessageType)
	assert.True(t, omciMsg.ResponseExpected)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(length), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*DownloadSectionRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(sectionNumber), request.SectionNumber)
	assert.Equal(t, length-1, len(request.SectionData))

	data, err = stringToPacket(payloadTotal)
	assert.NoError(t, err)
	assert.Equal(t, data, request.SectionData)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedDownloadSectionRequestSerializeNoResponseExpected(t *testing.T) {
	goodMessage := "0123140b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	omciLayer := &OMCI{
		TransactionID:    0x0123,
		MessageType:      DownloadSectionRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
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

func TestExtendedDownloadSectionRequestSerializeResponseExpectedMethod1(t *testing.T) {
	goodMessage := "2468540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestType, // or DownloadSectionRequestWithResponseType
		ResponseExpected: true,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(1),
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
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

func TestExtendedDownloadSectionRequestSerializeResponseExpectedMethod2(t *testing.T) {
	goodMessage := "2468540b00070001"
	payloadFragment := "01020304050607080910111213141516171819202122232425"
	payloadTotal := payloadFragment + payloadFragment + payloadFragment + payloadFragment +
		payloadFragment + payloadFragment + payloadFragment + payloadFragment
	sectionNumber := 0x84
	length := 1 + (8 * 25)
	hdr := fmt.Sprintf("%04x%02x", length, sectionNumber)
	goodMessage += hdr + payloadTotal

	// In this case, just use the request type with AR response requested already encoded
	omciLayer := &OMCI{
		TransactionID:    0x2468,
		MessageType:      DownloadSectionRequestWithResponseType,
		ResponseExpected: true,
		DeviceIdentifier: ExtendedIdent,
	}
	sectionData, genErr := stringToPacket(payloadTotal)
	assert.Nil(t, genErr)
	assert.NotNil(t, sectionData)
	assert.Equal(t, len(payloadTotal)/2, len(sectionData))

	request := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
			Extended:       true,
		},
		SectionNumber: byte(sectionNumber),
		SectionData:   sectionData,
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

func TestExtendedDownloadSectionRequestDecodeTruncated(t *testing.T) {
	goodMessage := "0008540b000700010000"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	failure := packet.ErrorLayer()
	assert.NotNil(t, failure)

	decodeFailure, ok := failure.(*gopacket.DecodeFailure)
	assert.True(t, ok)
	assert.NotNil(t, decodeFailure)
	assert.NotNil(t, decodeFailure.String())
	assert.True(t, len(decodeFailure.String()) > 0)
	assert.Equal(t, gopacket.LayerTypeDecodeFailure, decodeFailure.LayerType())

	metadata := packet.Metadata()
	assert.NotNil(t, metadata)
	assert.True(t, metadata.Truncated)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseDecode(t *testing.T) {
	goodMessage := "0022340a00070001061f00000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeDownloadSectionResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0022), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*DownloadSectionResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeDownloadSectionResponse, response.LayerType())
	assert.Equal(t, LayerTypeDownloadSectionResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0x1f), response.SectionNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseDecodeExtended(t *testing.T) {
	goodMessage := "0022340b000700010002061f"
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
	assert.Equal(t, LayerTypeDownloadSectionResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0022), omciMsg.TransactionID)
	assert.Equal(t, DownloadSectionResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*DownloadSectionResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeDownloadSectionResponse, response.LayerType())
	assert.Equal(t, LayerTypeDownloadSectionResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0x1f), response.SectionNumber)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseDecodeTruncatedExtended(t *testing.T) {
	goodMessage := "0022340b00070001000106"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	failure := packet.ErrorLayer()
	assert.NotNil(t, failure)

	decodeFailure, ok := failure.(*gopacket.DecodeFailure)
	assert.True(t, ok)
	assert.NotNil(t, decodeFailure)
	assert.NotNil(t, decodeFailure.String())
	assert.True(t, len(decodeFailure.String()) > 0)
	assert.Equal(t, gopacket.LayerTypeDecodeFailure, decodeFailure.LayerType())

	metadata := packet.Metadata()
	assert.NotNil(t, metadata)
	assert.True(t, metadata.Truncated)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestDownloadSectionResponseSerialize(t *testing.T) {
	goodMessage := "0022340a00070001061f00000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x0022,
		MessageType:   DownloadSectionResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result:        me.DeviceBusy,
		SectionNumber: 0x1f,
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

func TestDownloadSectionResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   DownloadSectionResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result:        me.DeviceBusy,
		SectionNumber: 0x1f,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestDownloadSectionResponseSerializeExtended(t *testing.T) {
	goodMessage := "0022340b000700010002061f"

	omciLayer := &OMCI{
		TransactionID:    0x0022,
		MessageType:      DownloadSectionResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		Result:        me.DeviceBusy,
		SectionNumber: 0x1f,
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

func TestEndSoftwareDownloadRequestDecode(t *testing.T) {
	//
	// 8100 55 0a 0007 0001 ff92a226 000f4240 01 0001 00000000000000000000000000000000000000000000000028
	//
	goodMessage := "8100550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x8100), omciMsg.TransactionID)
	assert.Equal(t, EndSoftwareDownloadRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*EndSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, request.LayerType())
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint32(0xff92a226), request.CRC32)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)
	assert.Equal(t, byte(1), request.NumberOfInstances)
	assert.Equal(t, 1, len(request.ImageInstances))
	assert.Equal(t, uint16(1), request.ImageInstances[0])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadRequestDecodeExtended(t *testing.T) {
	//
	// 8100 55 0a 0007 0001 000b ff92a226 000f4240 01 0001
	//
	goodMessage := "8100550b00070001000bff92a226000f4240010001"
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
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x8100), omciMsg.TransactionID)
	assert.Equal(t, EndSoftwareDownloadRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(11), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*EndSoftwareDownloadRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, request.LayerType())
	assert.Equal(t, LayerTypeEndSoftwareDownloadRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint32(0xff92a226), request.CRC32)
	assert.Equal(t, uint32(0x000f4240), request.ImageSize)
	assert.Equal(t, byte(1), request.NumberOfInstances)
	assert.Equal(t, 1, len(request.ImageInstances))
	assert.Equal(t, uint16(1), request.ImageInstances[0])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadRequestSerialize(t *testing.T) {
	// 8100 55 0a 0007 0001 ff92a226 000f4240 01 0001 00000000000000000000000000000000000000000000000028
	goodMessage := "8100550a00070001ff92a226000f424001000100000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8100,
		MessageType:   EndSoftwareDownloadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
		},
		CRC32:             0xff92a226,
		ImageSize:         1000000,
		NumberOfInstances: 1,
		ImageInstances:    []uint16{1},
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

func TestEndSoftwareDownloadRequestZeroTICSerialize(t *testing.T) {
	// 8100 55 0a 0007 0001 ff92a226 000f4240 01 0001 00000000000000000000000000000000000000000000000028
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   EndSoftwareDownloadRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
		},
		CRC32:             0xff92a226,
		ImageSize:         1000000,
		NumberOfInstances: 1,
		ImageInstances:    []uint16{1},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestEndSoftwareDownloadRequestSerializeExtended(t *testing.T) {
	goodMessage := "8100550b00070001000bff92a226000f4240010001"

	omciLayer := &OMCI{
		TransactionID:    0x8100,
		MessageType:      EndSoftwareDownloadRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 0x0001, // Default is zero, here we want image 1
			Extended:       true,
		},
		CRC32:             0xff92a226,
		ImageSize:         1000000,
		NumberOfInstances: 1,
		ImageInstances:    []uint16{1},
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

func TestEndSoftwareDownloadResponseDecode(t *testing.T) {
	// 8123 35 0a 0007 0001 06 0000000000000000000000000000000000000000000000000000000000000000000028
	goodMessage := "8123350a00070001060000000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x8123), omciMsg.TransactionID)
	assert.Equal(t, EndSoftwareDownloadResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*EndSoftwareDownloadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, response.LayerType())
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0), response.NumberOfInstances)
	assert.Nil(t, response.MeResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadResponseDecodeExtended(t *testing.T) {
	goodMessage := "8123350b0007000100020600"
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
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x8123), omciMsg.TransactionID)
	assert.Equal(t, EndSoftwareDownloadResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeEndSoftwareDownloadResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*EndSoftwareDownloadResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, response.LayerType())
	assert.Equal(t, LayerTypeEndSoftwareDownloadResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.DeviceBusy, response.Result)
	assert.Equal(t, byte(0), response.NumberOfInstances)
	assert.Nil(t, response.MeResults)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestEndSoftwareDownloadResponseSerialize(t *testing.T) {
	goodMessage := "8456350a00070000010000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8456,
		MessageType:   EndSoftwareDownloadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default is zero
		},
		Result:            me.ProcessingError,
		NumberOfInstances: 0,
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

func TestEndSoftwareDownloadResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   EndSoftwareDownloadResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass: me.SoftwareImageClassID,
			// Default is zero
		},
		Result:            me.ProcessingError,
		NumberOfInstances: 0,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestEndSoftwareDownloadResponseSerializeExtended(t *testing.T) {
	goodMessage := "8456350b0007000100020100"

	omciLayer := &OMCI{
		TransactionID:    0x8456,
		MessageType:      EndSoftwareDownloadResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			// Default is zero
			Extended: true,
		},
		Result:            me.ProcessingError,
		NumberOfInstances: 0,
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

func TestActivateSoftwareRequestDecode(t *testing.T) {
	goodMessage := "0009560a00070001020000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(9), omciMsg.TransactionID)
	assert.Equal(t, ActivateSoftwareRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeActivateSoftwareRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*ActivateSoftwareRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(2), request.ActivateFlags)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareRequestDecodeExtended(t *testing.T) {
	goodMessage := "0009560b00070001000102"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(9), omciMsg.TransactionID)
	assert.Equal(t, ActivateSoftwareRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeActivateSoftwareRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*ActivateSoftwareRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, uint8(2), request.ActivateFlags)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareRequestSerialize(t *testing.T) {
	goodMessage := "0009560b00070001000102"

	omciLayer := &OMCI{
		TransactionID:    0x09,
		MessageType:      ActivateSoftwareRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &ActivateSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		ActivateFlags: 2,
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

func TestActivateSoftwareRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0,
		MessageType:      ActivateSoftwareRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &ActivateSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		ActivateFlags: 2,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestActivateSoftwareRequestSerializeExtended(t *testing.T) {
	goodMessage := "0009560b00070001000102"

	omciLayer := &OMCI{
		TransactionID:    0x09,
		MessageType:      ActivateSoftwareRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &ActivateSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
		},
		ActivateFlags: 2,
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

func TestActivateSoftwareResponseDecode(t *testing.T) {
	goodMessage := "0009360a00070001060000000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, omciMsg.TransactionID, uint16(9))
	assert.Equal(t, omciMsg.MessageType, ActivateSoftwareResponseType)
	assert.Equal(t, omciMsg.DeviceIdentifier, BaselineIdent)
	assert.Equal(t, omciMsg.Length, uint16(40))

	msgLayer := packet.Layer(LayerTypeActivateSoftwareResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*ActivateSoftwareResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareResponseDecodeExtended(t *testing.T) {
	goodMessage := "0009360b00070001000106"
	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, uint16(9), omciMsg.TransactionID)
	assert.Equal(t, ActivateSoftwareResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeActivateSoftwareResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*ActivateSoftwareResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestActivateSoftwareResponseSerialize(t *testing.T) {
	goodMessage := "0009360a00070001060000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x09,
		MessageType:   ActivateSoftwareResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &ActivateSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
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

func TestActivateSoftwareResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   ActivateSoftwareResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &ActivateSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
		},
		Result: me.DeviceBusy,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestActivateSoftwareResponseSerializeExtended(t *testing.T) {
	goodMessage := "0009360b00070001000106"

	omciLayer := &OMCI{
		TransactionID:    0x09,
		MessageType:      ActivateSoftwareResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &ActivateSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1,
			Extended:       true,
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

func TestCommitSoftwareRequestDecode(t *testing.T) {
	goodMessage := "0011570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeCommitSoftwareRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x11), omciMsg.TransactionID)
	assert.Equal(t, CommitSoftwareRequestType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCommitSoftwareRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CommitSoftwareRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeCommitSoftwareRequest, request.LayerType())
	assert.Equal(t, LayerTypeCommitSoftwareRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(1), request.MeBasePacket.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareRequestDecodeExtended(t *testing.T) {
	goodMessage := "0011570b000700010000"
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
	assert.Equal(t, LayerTypeCommitSoftwareRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x11), omciMsg.TransactionID)
	assert.Equal(t, CommitSoftwareRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(0), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCommitSoftwareRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*CommitSoftwareRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeCommitSoftwareRequest, request.LayerType())
	assert.Equal(t, LayerTypeCommitSoftwareRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(1), request.MeBasePacket.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareRequestSerialize(t *testing.T) {
	goodMessage := "0044570a00070001000000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x44,
		MessageType:   CommitSoftwareRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
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

func TestCommitSoftwareRequestZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   CommitSoftwareRequestType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestCommitSoftwareRequestSerializeExtended(t *testing.T) {
	goodMessage := "0011570b000700010000"

	omciLayer := &OMCI{
		TransactionID:    0x11,
		MessageType:      CommitSoftwareRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
			Extended:       true,
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

func TestCommitSoftwareResponseDecode(t *testing.T) {
	goodMessage := "00aa370a00070001060000000000000000000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeCommitSoftwareResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0xaa), omciMsg.TransactionID)
	assert.Equal(t, CommitSoftwareResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCommitSoftwareResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CommitSoftwareResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeCommitSoftwareResponse, response.LayerType())
	assert.Equal(t, LayerTypeCommitSoftwareResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, uint16(1), response.MeBasePacket.EntityInstance)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareResponseDecodeExtended(t *testing.T) {
	goodMessage := "00aa370b00070001000106"
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
	assert.Equal(t, LayerTypeCommitSoftwareResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0xaa), omciMsg.TransactionID)
	assert.Equal(t, CommitSoftwareResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeCommitSoftwareResponse)

	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*CommitSoftwareResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeCommitSoftwareResponse, response.LayerType())
	assert.Equal(t, LayerTypeCommitSoftwareResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, uint16(1), response.MeBasePacket.EntityInstance)
	assert.Equal(t, me.DeviceBusy, response.Result)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestCommitSoftwareResponseSerialize(t *testing.T) {
	goodMessage := "8001370a00070001060000000000000000000000000000000000000000000000000000000000000000000028"

	omciLayer := &OMCI{
		TransactionID: 0x8001,
		MessageType:   CommitSoftwareResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
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

func TestCommitSoftwareResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 0x0,
		MessageType:   CommitSoftwareResponseType,
		// DeviceIdentifier: omci.BaselineIdent,		// Optional, defaults to Baseline
		// Length:           0x28,						// Optional, defaults to 40 octets
	}
	request := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
		},
		Result: me.DeviceBusy,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestCommitSoftwareResponseSerializeExtended(t *testing.T) {
	goodMessage := "8001370b00070001000106"

	omciLayer := &OMCI{
		TransactionID:    0x8001,
		MessageType:      CommitSoftwareResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: 1, // Default Instance ID is 0
			Extended:       true,
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
