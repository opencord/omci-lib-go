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
	. "github.com/opencord/omci-lib-go"
	me "github.com/opencord/omci-lib-go/generated"
	"github.com/opencord/omci-lib-go/meframe"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func testGetRequestTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap, 0),
	}
	attrDefs := managedEntity.GetAttributeDefinitions()
	for _, attrDef := range attrDefs {
		if attrDef.Index == 0 {
			continue // Skip entity ID, already specified
		} else if attrDef.GetAccess().Contains(me.Read) {
			// Allow 'nil' as parameter value for GetRequests since we only need names
			params.Attributes[attrDef.GetName()] = nil
		}
	}
	assert.NotEmpty(t, params.Attributes) // Need a parameter that is a table attribute
	bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
	assert.Nil(t, attrErr)

	// Create the managed instance
	meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)
	assert.NotNil(t, err)
	assert.Equal(t, err.StatusCode(), me.Success)

	tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

	frame, omciErr := meframe.GenFrame(meInstance, GetRequestType, meframe.TransactionID(tid),
		meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet))
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
	assert.Equal(t, GetRequestType, omciObj.MessageType)
	assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

	msgLayer := packet.Layer(LayerTypeGetRequest)
	assert.NotNil(t, msgLayer)

	msgObj, msgOk := msgLayer.(*GetRequest)
	assert.NotNil(t, msgObj)
	assert.True(t, msgOk)

	assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
	assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)
	assert.Equal(t, meInstance.GetAttributeMask(), msgObj.AttributeMask)
}

func testGetResponseTypeMeFrame(t *testing.T, managedEntity *me.ManagedEntity, messageSet DeviceIdent) {
	params := me.ParamData{
		EntityID:   uint16(0),
		Attributes: make(me.AttributeValueMap),
	}
	// Add loop to test all valid result codes for this message type
	validResultCodes := []me.Results{
		me.Success,
		me.ProcessingError,
		me.NotSupported,
		me.ParameterError,
		me.UnknownEntity,
		me.UnknownInstance,
		me.DeviceBusy,
		me.AttributeFailure,
	}
	for _, result := range validResultCodes {
		tid := uint16(rand.Int31n(0xFFFE) + 1) // [1, 0xFFFF]

		// If success Results selected, set FailIfTruncated 50% of time to test
		// overflow detection and failures periodically.  This is primarily for
		// baseline message set for those MEs that may have lots of attribute space
		// needed.  If extended message set, always fail if truncated since we should
		// be able to stuff as much as we want (at least for now in these unit tests)
		failIfTruncated := false
		if result == me.Success && (rand.Int31n(2) == 1 || messageSet == ExtendedIdent) {
			failIfTruncated = true
		}
		// Always pass a failure mask, but should only get encoded if result == ParameterError
		var unsupportedMask uint16
		var failedMask uint16
		attrDefs := managedEntity.GetAttributeDefinitions()
		for _, attrDef := range attrDefs {
			if attrDef.Index == 0 {
				continue // Skip entity ID, already specified

			} else if attrDef.GetAccess().Contains(me.Read) {
				// Random 5% chance this parameter unsupported and
				// 5% it failed
				switch rand.Int31n(20) {
				default:
					// TODO: Table attributes not yet supported.  For Table Attributes, figure out a
					//       good way to unit test this and see if that can be extended to a more
					//       general operation that provides the 'get-next' frames to the caller who
					//		 wishes to serialize a table attribute.
					if !attrDef.IsTableAttribute() {
						params.Attributes[attrDef.GetName()] = pickAValue(attrDef)
					}
				case 0:
					unsupportedMask |= attrDef.Mask
				case 1:
					failedMask |= attrDef.Mask
				}
			}
		}
		bitmask, attrErr := me.GetAttributesBitmap(attrDefs, getAttributeNameSet(params.Attributes))
		assert.Nil(t, attrErr)

		// Create the managed instance
		meInstance, err := me.NewManagedEntity(managedEntity.GetManagedEntityDefinition(), params)

		frame, omciErr := meframe.GenFrame(meInstance, GetResponseType,
			meframe.TransactionID(tid), meframe.Result(result),
			meframe.AttributeMask(bitmask), meframe.FrameFormat(messageSet),
			meframe.AttributeExecutionMask(failedMask),
			meframe.UnsupportedAttributeMask(unsupportedMask),
			meframe.FailIfTruncated(failIfTruncated))

		// TODO: Need to test if err is MessageTruncatedError. Sometimes reported as
		//       a proessing error
		if omciErr != nil {
			if _, ok := omciErr.(*me.MessageTruncatedError); ok {
				return
			}
		}
		assert.NotNil(t, frame)
		assert.NotZero(t, len(frame))
		assert.NotNil(t, err)
		assert.Equal(t, err.StatusCode(), me.Success)

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
		assert.Equal(t, GetResponseType, omciObj.MessageType)
		assert.Equal(t, messageSet, omciObj.DeviceIdentifier)

		msgLayer := packet.Layer(LayerTypeGetResponse)
		// If requested Result was Success and FailIfTruncated is true, then we may
		// fail (get nil layer) if too many attributes to fit in a frame
		if result == me.Success && msgLayer == nil {
			return // was expected
		}
		assert.NotNil(t, msgLayer)

		msgObj, msgOk := msgLayer.(*GetResponse)
		assert.NotNil(t, msgObj)
		assert.True(t, msgOk)

		assert.Equal(t, meInstance.GetClassID(), msgObj.EntityClass)
		assert.Equal(t, meInstance.GetEntityID(), msgObj.EntityInstance)

		switch msgObj.Result {
		default:
			assert.Equal(t, result, msgObj.Result)
			assert.Zero(t, msgObj.FailedAttributeMask)
			assert.Zero(t, msgObj.UnsupportedAttributeMask)

		case me.Success:
			assert.Equal(t, result, msgObj.Result)
			assert.Zero(t, msgObj.FailedAttributeMask)
			assert.Zero(t, msgObj.UnsupportedAttributeMask)
			assert.Equal(t, meInstance.GetAttributeValueMap(), msgObj.Attributes)

		case me.AttributeFailure:
			// Should have been Success or AttributeFailure to start with
			assert.True(t, result == me.Success || result == me.AttributeFailure)
			if result == me.AttributeFailure {
				assert.Equal(t, unsupportedMask, msgObj.UnsupportedAttributeMask)
			}
			// Returned may have more bits set in failed mask and less attributes
			// since failIfTruncated is false and we may add more fail attributes
			// since they do not fit. May also set only lower value (lower bits)
			// if it turns out that the upper bits are already pre-assigned to the
			// failure bits.
			//
			// Make sure any successful attributes were requested
			meMap := meInstance.GetAttributeValueMap()
			for name := range msgObj.Attributes {
				getValue, ok := meMap[name]
				assert.True(t, ok)
				assert.NotNil(t, getValue)
			}
		}
	}
}
