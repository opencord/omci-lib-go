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

func TestAttributeValueChangeDecode(t *testing.T) {
	goodMessage := "0000110a0007000080004d4c2d33363236000000000000000000000000000000000000000000000000000028"
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
	assert.Equal(t, LayerTypeAttributeValueChange, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AttributeValueChangeType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAttributeValueChange)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AttributeValueChangeMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAttributeValueChange, request.LayerType())
	assert.Equal(t, LayerTypeAttributeValueChange, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(0x8000), request.AttributeMask)
	assert.Equal(t, me.SoftwareImageClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)
	assert.Equal(t, []byte{
		0x4d, 0x4c, 0x2d, 0x33, 0x36, 0x32, 0x36,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		request.Attributes["Version"])

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

func TestAttributeValueChangeNonZeroTicSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID: 1,
		MessageType:   AttributeValueChangeType,
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
	assert.Error(t, err)
}

func TestExtendedAttributeValueChangeDecode(t *testing.T) {
	// Software Image Version (14 bytes) AVC
	goodMessage := "0000110b00070000001080004d4c2d3336323600000000000000"
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
	assert.Equal(t, LayerTypeAttributeValueChange, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0), omciMsg.TransactionID)
	assert.Equal(t, AttributeValueChangeType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2+14), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeAttributeValueChange)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*AttributeValueChangeMsg)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeAttributeValueChange, request.LayerType())
	assert.Equal(t, LayerTypeAttributeValueChange, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())
	assert.Equal(t, uint16(0x8000), request.AttributeMask)
	assert.Equal(t, me.SoftwareImageClassID, request.EntityClass)
	assert.Equal(t, uint16(0), request.EntityInstance)
	assert.Equal(t, []byte{
		0x4d, 0x4c, 0x2d, 0x33, 0x36, 0x32, 0x36,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, request.Attributes["Version"])

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestExtendedAttributeValueChangeSerialize(t *testing.T) {
	goodMessage := "0000110b00070000001080004d4c2d3336323600000000000000"

	omciLayer := &OMCI{
		TransactionID:    0,
		MessageType:      AttributeValueChangeType,
		DeviceIdentifier: ExtendedIdent,
		// Length parameter is optional for Extended message format serialization
		// and if present it will be overwritten during the serialization with the
		// actual value.
	}
	request := &AttributeValueChangeMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.SoftwareImageClassID,
			EntityInstance: uint16(0),
			Extended:       true,
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
