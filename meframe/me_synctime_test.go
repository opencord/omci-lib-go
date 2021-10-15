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
	"time"
)

func testSynchronizeTimeRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	tm := time.Now().UTC()
	tmUnix := tm.Unix()

	frame, omciErr := meframe.GenFrame(meInstance, SynchronizeTimeRequestType, meframe.TransactionID(tid),
		meframe.Payload(tmUnix), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, SynchronizeTimeRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SynchronizeTimeRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)

	assert.Equal(t, uint16(tm.Year()), msgObj.Year)
	assert.Equal(t, uint8(tm.Month()), msgObj.Month)
	assert.Equal(t, uint8(tm.Day()), msgObj.Day)
	assert.Equal(t, uint8(tm.Hour()), msgObj.Hour)
	assert.Equal(t, uint8(tm.Minute()), msgObj.Minute)
	assert.Equal(t, uint8(tm.Second()), msgObj.Second)
}

func testSynchronizeTimeResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested
	successResult := uint8(rand.Int31n(2)) // [0, 1]

	var frame []byte
	frame, omciErr := meframe.GenFrame(meInstance, SynchronizeTimeResponseType, meframe.TransactionID(tid),
		meframe.Result(result), meframe.SuccessResult(successResult), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, SynchronizeTimeResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSynchronizeTimeResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SynchronizeTimeResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
	if result == me.Success {
		assert.Equal(t, successResult, msgObj.SuccessResults)
	} else {
		assert.Zero(t, msgObj.SuccessResults)
	}
}
