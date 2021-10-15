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
package meframe_test

import (
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/opencord/omci-lib-go/v2/meframe"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func testDeleteRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// Generate the frame. Use a default Entity ID of zero, but for the
	// OMCI library, we need to specify all supported Set-By-Create
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, DeleteRequestType, meframe.TransactionID(tid), meframe.FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testDeleteResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested

	frame, omciErr := meframe.GenFrame(meInstance, DeleteResponseType, meframe.TransactionID(tid), meframe.Result(result),
		meframe.FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, DeleteResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDeleteResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DeleteResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
}
