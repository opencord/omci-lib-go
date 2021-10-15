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
	"github.com/google/gopacket/layers"
	. "github.com/opencord/omci-lib-go/v2"
	"github.com/stretchr/testify/assert"
	"testing"
)

var buffer []byte

func simpleMock(t *testing.T) *MeBasePacket {
	mibResetRequest := "00014F0A000200000000000000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000028"
	data, err := stringToPacket(mibResetRequest)
	assert.Nil(t, err)
	assert.NotNil(t, data)

	return &MeBasePacket{
		EntityClass:    0x02,
		EntityInstance: 0x00,
		Layer:          nil,
		BaseLayer:      layers.BaseLayer{},
		MsgLayerType:   LayerTypeMibResetRequest,
	}
}

func TestNextIsNil(t *testing.T) {
	mock := simpleMock(t)
	assert.Equal(t, mock.NextLayerType(), gopacket.LayerTypeZero)
}

func TestPayloadAlwaysNil(t *testing.T) {
	mock := simpleMock(t)
	assert.Nil(t, mock.LayerPayload())
}

func TestMsgCanBeDecoded(t *testing.T) {
	mock := simpleMock(t)
	assert.Equal(t, mock.CanDecode(), mock.MsgLayerType)
}

func TestDecodesFrameNoTrailer(t *testing.T) {
	// No baseline trailer.  Which is okay. Earlier library release depended on at
	// least the length field being present but we know baseline is always 40 bytes of payload

	getAllAlarmsRequest := "04454b0a000200000000000000000000000000000000000000000000000000000000000000000000"
	getAllAlarmsResponse := "04452b0a000200000003000000000000000000000000000000000000000000000000000000000000"

	getAllAlarmsNextRequest := "02344c0a000200000003000000000000000000000000000000000000000000000000000000000000"
	getAllAlarmsNextResponse := "02342c0a00020000000b010280000000000000000000000000000000000000000000000000000000"

	alarmNotification := "0000100a000b01048000000000000000000000000000000000000000000000000000000000000005"

	frames := []string{
		getAllAlarmsRequest,
		getAllAlarmsResponse,
		getAllAlarmsNextRequest,
		getAllAlarmsNextResponse,
		alarmNotification,
	}
	for _, frame := range frames {
		data, err := stringToPacket(frame)
		assert.NoError(t, err)

		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.NotNil(t, omciLayer)
	}
}

func TestDecodesFrameTooSmall(t *testing.T) {
	// Less than 4 (so cannot determine message set)
	veryShort := "04454b"

	// Baseline message set checks (only 39 bytes)
	// Extended message set checks (only 1 octet of 2 byte length field)
	getAllAlarmsRequest := "04454b0a0002000000000000000000000000000000000000000000000000000000000000000000"
	getAllAlarmsRequestExt := "04454b0b0002000000"
	getAllAlarmsResponse := "04452b0a0002000000030000000000000000000000000000000000000000000000000000000000"
	getAllAlarmsResponseExt := "04452b0b0002000000"

	getAllAlarmsNextRequest := "02344c0a0002000000030000000000000000000000000000000000000000000000000000000000"
	getAllAlarmsNextRequestExt := "02342c0b0002000000"
	getAllAlarmsNextResponse := "02342c0a00020000000b0102800000000000000000000000000000000000000000000000000000"
	getAllAlarmsNextResponseExt := "02342c0b0002000000"

	alarmNotification := "0000100a000b010480000000000000000000000000000000000000000000000000000000000000"
	alarmNotificationExt := "0000100b000b010400"

	frames := []string{
		veryShort,
		getAllAlarmsRequest,
		getAllAlarmsResponse,
		getAllAlarmsNextRequest,
		getAllAlarmsNextResponse,
		alarmNotification,
		getAllAlarmsRequestExt,
		getAllAlarmsResponseExt,
		getAllAlarmsNextRequestExt,
		getAllAlarmsNextResponseExt,
		alarmNotificationExt,
	}
	for _, frame := range frames {
		data, err := stringToPacket(frame)
		assert.NoError(t, err)

		// Should get packet but with error layer
		packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
		assert.NotNil(t, packet)
		errLayer := packet.ErrorLayer()
		assert.NotNil(t, errLayer)
		metaData := packet.Metadata()
		assert.NotNil(t, metaData)
		assert.True(t, metaData.Truncated)

		omciLayer := packet.Layer(LayerTypeOMCI)
		assert.Nil(t, omciLayer)
	}
}

func TestFrameWithUnknownMessageType(t *testing.T) {
	frame := "00010b0a000200000000000000000000000000000000000000000000000000000000000000000000"

	data, err := stringToPacket(frame)
	assert.NoError(t, err)

	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)
	errLayer := packet.ErrorLayer()
	assert.NotNil(t, errLayer)
	metaData := packet.Metadata()
	assert.NotNil(t, metaData)
	assert.False(t, metaData.Truncated)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)
}
