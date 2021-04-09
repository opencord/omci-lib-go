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
	. "github.com/opencord/omci-lib-go"
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
