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

func testStartSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	instance := uint16(0) // ONU-G
	image := uint16(1)
	params := me.ParamData{
		EntityID: uint16((instance << 8) + image),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	options := meframe.SoftwareOptions{
		WindowSize:   uint8(rand.Int31n(255)),                  // [0, 255]
		ImageSize:    uint32(rand.Int31n(0x100000) + 0x100000), // [1 Meg, 2M-1]
		CircuitPacks: []uint16{0},                              // [1 Meg, 2M-1]
	}
	frame, omciErr := meframe.GenFrame(meInstance, StartSoftwareDownloadRequestType,
		meframe.TransactionID(tid), meframe.Software(options), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, StartSoftwareDownloadRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeStartSoftwareDownloadRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*StartSoftwareDownloadRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, options.ImageSize, msgObj.ImageSize)
	assert.Equal(t, len(options.CircuitPacks), int(msgObj.NumberOfCircuitPacks))

	for index, circuitPack := range options.CircuitPacks {
		assert.Equal(t, circuitPack, msgObj.CircuitPacks[index])
	}
}

func testStartSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testDownloadSectionRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: In future, also support slot/multiple download formats
	instance := uint16(0)
	image := uint16(rand.Intn(1)) // Image 0 or 1 for this test
	params := me.ParamData{
		EntityID: (instance << 8) + image,
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	var data []byte

	if messageSet == ExtendedIdent {
		data = make([]byte, MaxDownloadSectionExtendedLength)
	} else {
		data = make([]byte, MaxDownloadSectionLength)
	}
	for index := range data {
		data[index] = byte(index & 0xFF)
	}
	options := meframe.SoftwareOptions{
		SectionNumber: uint8(rand.Int31n(255)), // [0, 255]
		Data:          data,
	}
	frame, omciErr := meframe.GenFrame(meInstance, DownloadSectionRequestType,
		meframe.TransactionID(tid), meframe.Software(options), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, DownloadSectionRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDownloadSectionRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DownloadSectionRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, options.SectionNumber, msgObj.SectionNumber)
	assert.NotNil(t, msgObj.SectionData)
	assert.Equal(t, options.Data, msgObj.SectionData)
}

func testDownloadSectionResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	instance := uint16(0)
	image := uint16(rand.Intn(1)) // Image 0 or 1 for this test
	params := me.ParamData{
		EntityID: (instance << 8) + image,
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(7))   // [0, 6] Not all types will be tested
	swOptions := meframe.SoftwareOptions{
		SectionNumber: uint8(rand.Int31n(255)), // [0, 255]
	}
	var frame []byte
	frame, omciErr := meframe.GenFrame(meInstance, DownloadSectionResponseType, meframe.TransactionID(tid),
		meframe.Result(result), meframe.FrameFormat(messageSet), meframe.Software(swOptions))

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
	assert.Equal(t, DownloadSectionResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeDownloadSectionResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*DownloadSectionResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)
	assert.Equal(t, swOptions.SectionNumber, msgObj.SectionNumber)
}

func testEndSoftwareDownloadRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testEndSoftwareDownloadResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testActivateSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testActivateSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testCommitSoftwareRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}

func testCommitSoftwareResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	// TODO: Implement
}
