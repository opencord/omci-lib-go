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
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	. "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var allBaselineTypes = []MessageType{
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
	DownloadSectionRequestWithResponseType,
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
	AlarmNotificationType,
	AttributeValueChangeType,
	TestResultType,
}

func stringToPacket(input string) ([]byte, error) {
	var p []byte

	p, err := hex.DecodeString(input)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return p, nil
}

func packetToString(input []byte) string {
	return strings.ToLower(hex.EncodeToString(input))
}

func getSbcMask(meDefinition IManagedEntityDefinition) uint16 {
	var sbcMask uint16

	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if SupportsAttributeAccess(attr, SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	return sbcMask
}

func TestDeviceIdents(t *testing.T) {

	baselineString := BaselineIdent.String()
	assert.NotZero(t, len(baselineString))

	extendedString := ExtendedIdent.String()
	assert.NotZero(t, len(extendedString))

	assert.NotEqual(t, baselineString, extendedString)

	unknownString := DeviceIdent(0xff).String()
	assert.NotZero(t, len(unknownString))
	assert.NotEqual(t, unknownString, baselineString)
	assert.NotEqual(t, unknownString, extendedString)
}

func TestOmciCanDecodeAndNextLayer(t *testing.T) {

	baselineString := BaselineIdent.String()
	assert.NotZero(t, len(baselineString))

	createGalEthernetProfile := "0002440A011000010030000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"

	data, err := stringToPacket(createGalEthernetProfile)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, packet)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeCreateRequest, omciMsg.NextLayerType())

	msgLayer := packet.Layer(LayerTypeCreateRequest)
	assert.NotNil(t, msgLayer)

	omciMsg2, ok2 := msgLayer.(*CreateRequest)
	assert.True(t, ok2)
	assert.Equal(t, LayerTypeCreateRequest, omciMsg2.LayerType())
	assert.Equal(t, LayerTypeCreateRequest, omciMsg2.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, omciMsg2.NextLayerType())
}

func TestOmciHeaderVeryShort(t *testing.T) {
	// Need at least 6 octets in OMCI header to decode Message Type
	message := "000159"
	data, err := stringToPacket(message)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.Nil(t, omciLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.True(t, packet.Metadata().Truncated)
}

func TestOmciHeaderBaselineShort(t *testing.T) {
	for _, msgType := range allBaselineTypes {
		// Smallest message baseline is 40 bytes (length and MIC optional)
		tid := 1
		if msgType == AlarmNotificationType || msgType == AttributeValueChangeType {
			tid = 0
		}
		msg39 := fmt.Sprintf("%04x%02x0a0002000000000000000000000000000000000000000000000000000000000000000000",
			uint16(tid), uint8(msgType))

		data, err := stringToPacket(msg39)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.Nil(t, omciLayer)

		badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
		assert.NotNil(t, badLayer)
		truncated := packet.Metadata().Truncated
		assert.True(t, truncated)

		// Let length be optional size baseline size is fixed and we can recover from that
		msg40 := fmt.Sprintf("%04x%02x0a000200000000000000000000000000000000000000000000000000000000000000000000",
			uint16(tid), uint8(msgType))
		data, err = stringToPacket(msg40)
		assert.NoError(t, err)

		packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer = packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)

		omciMsg, ok := omciLayer.(*OMCI)
		assert.True(t, ok)
		assert.Equal(t, uint16(40), omciMsg.Length)
	}
}

func TestOmciHeaderExtendedShort(t *testing.T) {
	// Smallest message possible is an Extended Set Delete request which
	// is 10 octets.

	//mibResetRequest := "0001 4F 0A 0002 0000 0000000000000000" +
	//	"00000000000000000000000000000000" +
	//	"000000000000000000000028"

}

func TestBad2017_G_988(t *testing.T) {
	// ITU-G.988 11/2017 has a bad set of class IDs that map the Ethernet 64-bit PM counter
	// to class ID 426 when it should be 425.   Make sure that code-generation of the OMCI
	// ME's does not let that bad value find it's way back into our library.

	assert.Equal(t, ClassID(425), EthernetFrameExtendedPm64BitClassID)

	instance, omciErr := NewEthernetFrameExtendedPm64Bit()
	assert.NotNil(t, instance)
	assert.NotNil(t, omciErr)
	assert.Equal(t, omciErr.StatusCode(), Success)
	assert.Equal(t, EthernetFrameExtendedPm64BitClassID, instance.GetClassID())
}

func TestBaselineBadLenSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0211,
		MessageType:      DeleteResponseType,
		DeviceIdentifier: BaselineIdent,
		Length:           39, // Must be 0 or 40
	}
	request := &DeleteResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x202),
		},
		Result: Success,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestBadIdentSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0211,
		MessageType:      DeleteResponseType,
		DeviceIdentifier: DeviceIdent(1), // Default is Baseline (0xa), other is Extended (0xb)
	}
	request := &DeleteResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x202),
		},
		Result: Success,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}
