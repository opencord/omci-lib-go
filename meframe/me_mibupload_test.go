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

func testMibUploadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, MibUploadRequestType, meframe.TransactionID(tid), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, MibUploadRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1)  // [1, 0xFFFF]
	numOfCommands := uint16(rand.Int31n(5)) // [0, 5)

	frame, omciErr := meframe.GenFrame(meInstance, MibUploadResponseType, meframe.TransactionID(tid),
		meframe.SequenceNumberCountOrSize(numOfCommands), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, MibUploadResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, numOfCommands, msgObj.NumberOfCommands)
}

func testMibUploadNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	seqNumber := uint16(rand.Int31n(0xFFFF)) // [0, 0xFFFE]
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]

	var frame []byte
	frame, omciErr := meframe.GenFrame(meInstance, MibUploadNextRequestType, meframe.TransactionID(tid),
		meframe.SequenceNumberCountOrSize(seqNumber), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, MibUploadNextRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, seqNumber, msgObj.CommandSequenceNumber)
	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
}

func testMibUploadNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	// TODO: Since only baseline messages supported, send only one ME
	uploadMe := meInstance

	frame, omciErr := meframe.GenFrame(meInstance, MibUploadNextResponseType, meframe.TransactionID(tid),
		meframe.Payload(uploadMe), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, MibUploadNextResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*MibUploadNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, uploadMe.GetClassID(), msgObj.ReportedME.GetClassID())
	assert.Equal(t, uploadMe.GetEntityID(), msgObj.ReportedME.GetEntityID())
}
