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

func testSetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	attrDefs := managedEntity.GetAttributeDefinitions()
	tableAttrFound := false
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.IsTableAttribute() {
			tableAttrFound = true
			continue // TODO: Skip table attributes for now
		} else if attrDef.GetAccess().Contains(me.Write) {
			params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
		}
	}
	if tableAttrFound && len(params.Attributes) == 0 {
		// The only set attribute may have been a table and we do not have
		// a test for that right now.
		return
	}
	assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)
	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, SetRequestType, meframe.TransactionID(tid),
		meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet))
	// some frames cannot fit all the attributes
	if omciErr != nil {
		if _, ok := omciErr.(*me.MessageTruncatedError); ok {
			return
		}
	}
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))

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
	assert.Equal(t, SetRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeValueMap(), msgObj.Attributes)
}

func testSetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID: uint16(0),
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]
	result := me.Results(rand.Int31n(10))  // [0, 9] Not all types will be tested

	// Always pass a failure mask, but should only get encoded if result == ParameterError
	var unsupportedMask uint16
	var failedMask uint16
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified

		} else if attrDef.GetAccess().Contains(me.Write) {
			// Random 10% chance this parameter unsupported and
			// 10% it failed
			switch rand.Int31n(5) {
			case 0:
				unsupportedMask |= attrDef.Mask
			case 1:
				failedMask |= attrDef.Mask
			}
		}
	}
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	frame, omciErr := meframe.GenFrame(meInstance, SetResponseType,
		meframe.TransactionID(tid), meframe.Result(result),
		meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet),
		meframe.AttributeExecutionMask(failedMask),
		meframe.UnsupportedAttributeMask(unsupportedMask))
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
	assert.Equal(t, SetResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeSetResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*SetResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, result, msgObj.Result)

	if result == me.AttributeFailure {
		assert.Equal(t, failedMask, msgObj.FailedAttributeMask)
		assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)
	} else {
		assert.Zero(t, msgObj.FailedAttributeMask)
		assert.Zero(t, msgObj.UnsupportedAttributeMask)
	}
}
