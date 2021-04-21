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
	"github.com/opencord/omci-lib-go"
	me "github.com/opencord/omci-lib-go/generated"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Note: The majority of this file is tested by other unit tests
func TestKnownMessageType(t *testing.T) {
	for _, msg := range allMessageTypes {
		layer, err := omci.MsgTypeToNextLayer(msg, false)
		assert.NotEqual(t, layer, gopacket.LayerTypeZero)
		assert.Nil(t, err)
	}
	unknown := me.MsgType(0xFF)
	strMsg := unknown.String()
	assert.NotEqual(t, len(strMsg), 0)
}

func TestUnknownMessageType(t *testing.T) {
	unknown := omci.MessageType(0xFF)
	layer, err := omci.MsgTypeToNextLayer(unknown, false)
	assert.Equal(t, layer, gopacket.LayerTypeZero)
	assert.NotNil(t, err)
}
