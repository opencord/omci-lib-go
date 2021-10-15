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

func TestSetTableRequestDecode(t *testing.T) {
	// Single row
	row := "F0000000" + "F0000000" + "00000000" + "00000000"
	goodMessage := "01075d0b00AB123400120400"
	data, err := stringToPacket(goodMessage + row)
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
	assert.Equal(t, LayerTypeSetTableRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(2+16), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetTableRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, LayerTypeSetTableRequest, request.LayerType())
	assert.Equal(t, LayerTypeSetTableRequest, request.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, request.NextLayerType())

	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0x1234), request.EntityInstance)
	assert.Equal(t, uint16(0x0400), request.AttributeMask)

	vlanTable, tblOk := request.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.True(t, tblOk)
	assert.NotNil(t, vlanTable)

	rows, rowOk := vlanTable.(me.TableRows)
	assert.True(t, rowOk)
	assert.NotNil(t, rows)
	assert.Equal(t, 1, rows.NumRows)
	assert.Equal(t, 16*rows.NumRows, len(rows.Rows))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetTableRequestDecodeZeroRows(t *testing.T) {
	// No rows are okay
	row := ""
	goodMessage := "01075d0b00AB123400020400"
	data, err := stringToPacket(goodMessage + row)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, uint16(2), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetTableRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, request.EntityClass)
	assert.Equal(t, uint16(0x1234), request.EntityInstance)
	assert.Equal(t, uint16(0x0400), request.AttributeMask)

	vlanTable, tblOk := request.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.True(t, tblOk)
	assert.NotNil(t, vlanTable)

	rows, rowOk := vlanTable.(me.TableRows)
	assert.True(t, rowOk)
	assert.NotNil(t, rows)
	assert.Equal(t, 0, rows.NumRows)
	assert.Nil(t, rows.Rows)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetTableRequestDecodeMultipleRows(t *testing.T) {
	// More than one row
	row1 := "F0000000" + "F0000000" + "00000000" + "00000000"
	row2 := "70000000" + "F0000000" + "00000000" + "00000000"
	row3 := "70000000" + "70000000" + "00000000" + "00000000"
	goodMessage := "01075d0b00AB123400320400"
	data, err := stringToPacket(goodMessage + row1 + row2 + row3)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, uint16(2+(3*16)), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.NotNil(t, msgLayer)

	request, ok2 := msgLayer.(*SetTableRequest)
	assert.True(t, ok2)
	assert.NotNil(t, request)
	vlanTable, tblOk := request.Attributes["ReceivedFrameVlanTaggingOperationTable"]
	assert.True(t, tblOk)
	assert.NotNil(t, vlanTable)

	rows, rowOk := vlanTable.(me.TableRows)
	assert.True(t, rowOk)
	assert.NotNil(t, rows)
	assert.Equal(t, 3, rows.NumRows)
	assert.Equal(t, 16*rows.NumRows, len(rows.Rows))

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetTableRequestDecodeTruncatedRow(t *testing.T) {
	// More than one row, but one is short
	row1 := "F0000000" + "F0000000" + "00000000" + "00000000"
	row2 := "70000000" + "F0000000" + "00000000" + "00000000"
	row3 := "70000000" + "70000000" + "00000000" + "0000"
	goodMessage := "01075d0b00ab123400300400"
	data, err := stringToPacket(goodMessage + row1 + row2 + row3)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, uint16(48), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	shortLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, shortLayer)
	assert.True(t, packet.Metadata().Truncated)
}

func TestSetTableRequestDecodeOneAttributeOnly(t *testing.T) {
	// Single row but also extra non-table row
	row := "F0000000" + "F0000000" + "00000000" + "00000000"
	goodMessage := "01075d0b00ab123400138400" + "00"
	data, err := stringToPacket(goodMessage + row)
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
	assert.Equal(t, LayerTypeSetTableRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3+16), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.False(t, packet.Metadata().Truncated) // It was correct length, but not right

	failure, ok3 := badLayer.(*gopacket.DecodeFailure)
	assert.True(t, ok3)
	assert.NotNil(t, failure)
}

func TestSetTableRequestDecodeTableAttributesOnly(t *testing.T) {

	// Single row but also extra non-table row
	goodMessage := "01075d0b00ab123400038000" + "00"
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
	assert.Equal(t, LayerTypeSetTableRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.False(t, packet.Metadata().Truncated) // It was correct length, but not right

	failure, ok3 := badLayer.(*gopacket.DecodeFailure)
	assert.True(t, ok3)
	assert.NotNil(t, failure)
}

func TestSetTableRequestDecodeMeNotSupported(t *testing.T) {

	// Single row but also extra non-table row
	goodMessage := "01075d0b0100000000031000" + "01"
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
	assert.Equal(t, LayerTypeSetTableRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(3), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.False(t, packet.Metadata().Truncated) // It was correct length, but not right

	failure, ok3 := badLayer.(*gopacket.DecodeFailure)
	assert.True(t, ok3)
	assert.NotNil(t, failure)
}

func TestSetTableRequestDecodeTableWritableOnly(t *testing.T) {

	// Single row but also extra non-table row
	goodMessage := "01075d0b00ab123400044000" + "0000"
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
	assert.Equal(t, LayerTypeSetTableRequest, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(4), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.False(t, packet.Metadata().Truncated) // It was correct length, but not right

	failure, ok3 := badLayer.(*gopacket.DecodeFailure)
	assert.True(t, ok3)
	assert.NotNil(t, failure)
}

func TestSetTableRequestDecodeBaselineNotSupported(t *testing.T) {
	// Single row
	message := "01075d0a00AB1234001204000000000000000000000000000000000000000000000000000000000000000028"
	data, err := stringToPacket(message)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableRequestType, omciMsg.MessageType)

	msgLayer := packet.Layer(LayerTypeSetTableRequest)
	assert.Nil(t, msgLayer)

	badLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, badLayer)
	assert.False(t, packet.Metadata().Truncated)
}

func TestSetTableRequestSerialize(t *testing.T) {
	// Single row
	row := "F0000001" + "F0000002" + "00000003" + "00000004"
	goodMessage := "01075d0b00AB123400120400" + row

	rowData, rErr := stringToPacket(row)
	assert.NoError(t, rErr)

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{
		NumRows: 1,
		Rows:    rowData,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
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

func TestSetTableRequestZeroTICSerialize(t *testing.T) {
	// Single row
	row := "F0000001" + "F0000002" + "00000003" + "00000004"
	rowData, rErr := stringToPacket(row)
	assert.NoError(t, rErr)

	omciLayer := &OMCI{
		TransactionID:    0x0,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{
		NumRows: 1,
		Rows:    rowData,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeZeroRows(t *testing.T) {
	// No rows is sort of dumb on a set but technically it is allowed
	goodMessage := "01075d0b00AB123400020400"

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
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

func TestSetTableRequestSerializeMultipleRows(t *testing.T) {
	// More than one row
	row1 := "F0000000" + "F0000000" + "00004000" + "0000000c"
	row2 := "70000000" + "F0000000" + "00300000" + "0000000a"
	row3 := "70000000" + "70000000" + "0005000b" + "0000000b"
	goodMessage := "01075d0b00AB123400320400" + row1 + row2 + row3

	rowData, rErr := stringToPacket(row1 + row2 + row3)
	assert.NoError(t, rErr)

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{
		NumRows: 3,
		Rows:    rowData,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
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

func TestSetTableRequestSerializeTruncatedRow(t *testing.T) {
	// More than one row, but one is short
	row1 := "F0000000" + "F0000000" + "00000000" + "00000000"
	row2 := "70000000" + "F0000000" + "00000000" + "00000000"
	row3 := "70000000" + "70000000" + "00000000" + "0000"

	rowData, rErr := stringToPacket(row1 + row2 + row3)
	assert.NoError(t, rErr)

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{
		NumRows: 3,
		Rows:    rowData,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeOneAttributeOnly(t *testing.T) {
	rowData, rErr := stringToPacket("F0000000" + "F0000000" + "00000000" + "00000000")
	assert.NoError(t, rErr)

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	tableRow := me.TableRows{
		NumRows: 1,
		Rows:    rowData,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x8400),
		Attributes: me.AttributeValueMap{
			"ReceivedFrameVlanTaggingOperationTable": tableRow,
			"AssociationType":                        byte(1),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeTableAttributesOnly(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x8000),
		Attributes: me.AttributeValueMap{
			"AssociationType": byte(1),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeTableWritableOnly(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		AttributeMask: uint16(0x4000),
		Attributes: me.AttributeValueMap{
			"ReceivedFrameVlanTaggingOperationTableMaxSize": byte(1),
		},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeBaselineNotSupported(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: BaselineIdent,
	}
	tableRow := me.TableRows{}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       false,
		},
		AttributeMask: uint16(0x0400),
		Attributes:    me.AttributeValueMap{"ReceivedFrameVlanTaggingOperationTable": tableRow},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableRequestSerializeBaselineManageEntityNotSupported(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableRequestType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetTableRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.OnuGClassID,
			EntityInstance: uint16(0x0),
			Extended:       true,
		},
		AttributeMask: uint16(0x1000),
		Attributes:    me.AttributeValueMap{"TrafficManagementOption": byte(1)},
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}

func TestSetTableResponseDecode(t *testing.T) {
	goodMessage := "01073d0b00ab1234000101"
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
	assert.Equal(t, LayerTypeSetTableResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0107), omciMsg.TransactionID)
	assert.Equal(t, SetTableResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(1), omciMsg.Length)

	msgLayer := packet.Layer(LayerTypeSetTableResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*SetTableResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeSetTableResponse, response.LayerType())
	assert.Equal(t, LayerTypeSetTableResponse, response.CanDecode())
	assert.Equal(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, me.ProcessingError, response.Result)
	assert.Equal(t, me.ExtendedVlanTaggingOperationConfigurationDataClassID, response.EntityClass)
	assert.Equal(t, uint16(0x1234), response.EntityInstance)

	// Verify string output for message
	packetString := packet.String()
	assert.NotZero(t, len(packetString))
}

func TestSetTableResponseSerialize(t *testing.T) {
	goodMessage := "01073d0b00ab1234000103"

	omciLayer := &OMCI{
		TransactionID:    0x0107,
		MessageType:      SetTableResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetTableResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		Result: me.ParameterError,
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

func TestSetTableResponseZeroTICSerialize(t *testing.T) {
	omciLayer := &OMCI{
		TransactionID:    0x0,
		MessageType:      SetTableResponseType,
		DeviceIdentifier: ExtendedIdent,
	}
	request := &SetTableResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: uint16(0x1234),
			Extended:       true,
		},
		Result: me.ParameterError,
	}
	// Test serialization back to former string
	var options gopacket.SerializeOptions
	options.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciLayer, request)
	assert.Error(t, err)
}
