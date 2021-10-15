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

func testGetNextRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	// TODO: Loop over all table attributes for this class ID
	// Find first attribute that is a table definition
	// TODO: Test request of more than 1 attribute. G.988 specifies that a status
	//       code of (3) should be returned.  Raise error during encode instead of
	//       waiting for compliant ONU.  May want to have an 'ignore' to allow it.
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.IsTableAttribute() {
			// TODO: Tables without a size are not supported. At least needs to be one octet
			if attrDef.Size == 0 {
				continue
			}
			// Allow 'nil' as parameter value for GetNextRequests since we only need names
			params.Attributes[attrDef.GetName()] = nil
			break
		}
	}
	if len(params.Attributes) == 0 {
		return
	}
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	seqNumber := uint16(rand.Int31n(0xFFFF)) // [0, 0xFFFE]
	tid := uint16(rand.Int31n(0xFFFE) + 1)   // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, GetNextRequestType, meframe.TransactionID(tid),
		meframe.SequenceNumberCountOrSize(seqNumber), meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, GetNextRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetNextRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetNextRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)
	assert.Equal(t, seqNumber, msgObj.SequenceNumber)
}

func testGetNextResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	// TODO: Loop over result types (here and other responses with results)
	result := me.Success // me.Results(rand.Int31n(7))  // [0, 6]
	bitmask := uint16(0)
	attrDefs := managedEntity.GetAttributeDefinitions()

	// TODO: Loop over all table attributes for this class ID
	if result == me.Success {
		// Find first attribute that is a table definition
		// TODO: Test request of more than 1 attribute. G.988 specifies that a status
		//       code of (3) should be returned.  Raise error during encode instead of
		//       waiting for compliant ONU.  May want to have an 'ignore' to allow it.
		for _, attrDef := range attrDefs {
			if attrDef.Index == 0 {
				continue // Skip entity ID, already specified
			} else if attrDef.IsTableAttribute() {
				if len(params.Attributes) == 0 {
					// Need a parameter that is a table attribute
					return
				}
				params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
				break
			}
		}
		if len(params.Attributes) == 0 {
			return
		}
		assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
		var attrErr error
		bitmask, attrErr = me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
		assert.Nil(t, attrErr)
	}
	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, GetNextResponseType, meframe.TransactionID(tid), meframe.Result(result),
		meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet))
	assert.NotNil(t, frame)
	assert.NotZero(t, len(frame))
	assert.Nil(t, omciErr)

	///////////////////////////////////////////////////////////////////
	// Now decode and compare
	cid := meInstance.GetClassID()
	assert.NotEqual(t, cid, 0)
	packet := gopacket.NewPacket(frame, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciObj, omciOk := omciLayer.(*OMCI)
	assert.NotNil(t, omciObj)
	assert.True(t, omciOk)
	assert.Equal(t, tid, omciObj.TransactionID)
	assert.Equal(t, GetNextResponseType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetNextResponse)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetNextResponse)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)

	switch msgObj.Result {
	default:
		assert.Equal(t, result, msgObj.Result)

	case me.Success:
		assert.Equal(t, result, msgObj.Result)
		// The attributes should be equal but for variable length table attribute (size = 0 in structure)
		// we will have the frame padding returned as well.
		for attrName, value := range meInstance.GetAttributeValueMap() {
			attr, err := me.GetAttributeDefinitionByName(attrDefs, attrName)
			assert.Nil(t, err)
			assert.NotNil(t, attr)
			assert.Equal(t, attrName, attr.GetName())
			if attr.IsTableAttribute() {
				instValue := value.([]byte)
				msgValue := msgObj.Attributes[attrName].([]byte)
				assert.True(t, len(instValue) <= len(msgValue))
				assert.Equal(t, msgValue[:len(instValue)], instValue)
			} else {
				assert.Equal(t, value, msgObj.Attributes[attrName])
			}
		}
	}
}
